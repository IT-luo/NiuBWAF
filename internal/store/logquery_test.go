package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func openLogStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedLog 同步写入一条攻击日志（LogAttack 走异步队列，测试需要立即可查）
func seedLog(t *testing.T, s *Store, ip, domain, action string) int64 {
	t.Helper()
	res, err := s.DB.Exec(`INSERT INTO attack_logs(site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id)
		VALUES(0,?,?,'-','GET','/t',?,941100,'测试','HIGH',403,'req-1')`, domain, ip, action)
	if err != nil {
		t.Fatalf("写入日志失败: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestLogWhereUsesIndexFriendlyPredicates(t *testing.T) {
	cases := []struct {
		name           string
		ip, domain     string
		wantContains   string
		wantNotContain string
		wantArgs       []any
	}{
		{name: "整 IP 等值", ip: "10.0.0.7", wantContains: "client_ip=?", wantNotContain: "LIKE", wantArgs: []any{"10.0.0.7"}},
		{name: "IPv6 等值", ip: "2001:db8::1", wantContains: "client_ip=?", wantNotContain: "LIKE", wantArgs: []any{"2001:db8::1"}},
		{name: "IP 前缀", ip: "10.0.", wantContains: "client_ip LIKE ?", wantArgs: []any{"10.0.%"}},
		{name: "十六进制片段按前缀", ip: "192.168", wantContains: "client_ip LIKE ?", wantArgs: []any{"192.168%"}},
		{name: "非 IP 字符回退包含匹配", ip: "内部扫描", wantContains: "client_ip LIKE ?", wantArgs: []any{"%内部扫描%"}},
		{name: "整域名等值", domain: "API.Example.COM", wantContains: "domain=?", wantNotContain: "domain LIKE", wantArgs: []any{"api.example.com"}},
		{name: "域名片段包含匹配", domain: "example", wantContains: "domain LIKE ?", wantArgs: []any{"%example%"}},
		{name: "含通配符不走等值", domain: "a%.com", wantContains: "domain LIKE ?", wantArgs: []any{"%a%.com%"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			where, args := logWhere(c.ip, c.domain, "")
			if !strings.Contains(where, c.wantContains) {
				t.Fatalf("where 应含 %q, got %q", c.wantContains, where)
			}
			if c.wantNotContain != "" && strings.Contains(where, c.wantNotContain) {
				t.Fatalf("where 不应含 %q, got %q", c.wantNotContain, where)
			}
			if fmt.Sprint(args) != fmt.Sprint(c.wantArgs) {
				t.Fatalf("args = %v, want %v", args, c.wantArgs)
			}
		})
	}
}

func TestLogWhereAction(t *testing.T) {
	where, args := logWhere("", "", "waf")
	if !strings.Contains(where, "action=?") || fmt.Sprint(args) != "[waf]" {
		t.Fatalf("动作过滤应走等值: %q %v", where, args)
	}
}

func TestQueryLogsFiltersAndPaging(t *testing.T) {
	s := openLogStore(t)
	seedLog(t, s, "10.0.0.7", "api.example.com", "waf")
	seedLog(t, s, "10.0.0.8", "api.example.com", "cc")
	seedLog(t, s, "10.9.1.1", "www.example.com", "waf")
	seedLog(t, s, "10.0.0.7", "shop.test", "semantic")

	if list, total, err := s.QueryLogs("10.0.0.7", "", "", 20, 0); err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("整 IP 过滤应命中 2 条: total=%d len=%d err=%v", total, len(list), err)
	}
	if _, total, _ := s.QueryLogs("10.0.", "", "", 20, 0); total != 3 {
		t.Fatalf("IP 前缀过滤应命中 3 条, got %d", total)
	}
	if _, total, _ := s.QueryLogs("", "api.example.com", "", 20, 0); total != 2 {
		t.Fatalf("整域名过滤应命中 2 条, got %d", total)
	}
	if _, total, _ := s.QueryLogs("", "example", "", 20, 0); total != 3 {
		t.Fatalf("域名片段过滤应命中 3 条, got %d", total)
	}
	if list, total, _ := s.QueryLogs("", "", "waf", 20, 0); total != 2 || list[0].Action != "waf" {
		t.Fatalf("动作过滤应命中 2 条, got %d", total)
	}
	list, total, _ := s.QueryLogs("10.0.0.7", "", "", 1, 1)
	if total != 2 || len(list) != 1 {
		t.Fatalf("分页应返回 1 条 / 共 2 条, got len=%d total=%d", len(list), total)
	}
	if first, _, _ := s.QueryLogs("", "", "", 1, 0); first[0].ClientIP != "10.0.0.7" || first[0].Domain != "shop.test" {
		t.Fatalf("应按 id 倒序返回最新记录, got %+v", first[0])
	}
}

func TestEachLogStreamsAndPropagatesError(t *testing.T) {
	s := openLogStore(t)
	for i := 0; i < 25; i++ {
		seedLog(t, s, fmt.Sprintf("10.0.0.%d", i%3+1), "api.example.com", "waf")
	}
	n, prev := 0, int64(1<<62)
	if err := s.EachLog("", "", "", func(l *AttackLog) error {
		n++
		if l.ID >= prev {
			t.Fatalf("EachLog 应按 id 倒序, got %d after %d", l.ID, prev)
		}
		prev = l.ID
		return nil
	}); err != nil {
		t.Fatalf("EachLog 失败: %v", err)
	}
	if n != 25 {
		t.Fatalf("EachLog 应遍历 25 条, got %d", n)
	}
	sentinel := errors.New("stop")
	seen := 0
	if err := s.EachLog("10.0.0.1", "", "", func(l *AttackLog) error {
		seen++
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("回调错误应向上传递, got %v", err)
	}
	if seen != 1 {
		t.Fatalf("回调返回错误后应停止遍历, got %d 次", seen)
	}
}

func TestClearLogsAndMaxLogID(t *testing.T) {
	s := openLogStore(t)
	if id := s.MaxLogID(); id != 0 {
		t.Fatalf("空库 MaxLogID 应为 0, got %d", id)
	}
	last := int64(0)
	for i := 0; i < 5; i++ {
		last = seedLog(t, s, "10.0.0.9", "api.example.com", "waf")
	}
	if id := s.MaxLogID(); id != last {
		t.Fatalf("MaxLogID 应等于最后写入 id %d, got %d", last, id)
	}
	s.Audit("admin", "测试审计", "不应被清空")
	n, err := s.ClearLogs()
	if err != nil || n != 5 {
		t.Fatalf("ClearLogs 应删除 5 条, got n=%d err=%v", n, err)
	}
	if id := s.MaxLogID(); id != 0 {
		t.Fatalf("清空后 MaxLogID 应为 0, got %d", id)
	}
	if _, total, _ := s.QueryLogs("", "", "", 20, 0); total != 0 {
		t.Fatalf("清空后应无攻击日志, got %d", total)
	}
	rows, err := s.DB.Query(`SELECT COUNT(*) FROM audit_logs`)
	if err != nil {
		t.Fatalf("查询审计日志失败: %v", err)
	}
	defer rows.Close()
	rows.Next()
	var audit int
	rows.Scan(&audit)
	if audit == 0 {
		t.Fatal("清空攻击日志不应影响审计日志")
	}
}
