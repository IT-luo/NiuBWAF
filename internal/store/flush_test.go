package store

import (
	"path/filepath"
	"testing"
)

func TestFlushReportsErrors(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "flush.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	// 不注册 t.Cleanup(s.Close)：本测试需要手动关闭 DB 制造错误路径，
	// 后台 flushLoop 在 DB 关闭后只会记录错误而不会 panic。
	pending := map[trafficKey]trafficVal{
		{minute: "2026-11-17 20:00", siteID: 1}: {reqs: 2, blocks: 0, bytes: 100},
	}
	logs := []*AttackLog{{SiteID: 1, Domain: "d.local", ClientIP: "1.2.3.4", Method: "GET", URL: "/", Action: "waf", RuleID: 942100, Msg: "m", Severity: "CRITICAL", Status: 403, ReqID: "r1"}}

	if err := s.flushTraffic(pending); err != nil {
		t.Fatalf("正常统计落盘不应报错: %v", err)
	}
	if err := s.flushLogs(logs); err != nil {
		t.Fatalf("正常日志落盘不应报错: %v", err)
	}
	// 落盘成功后应可查回
	if n := s.countRows(t, "traffic"); n == 0 {
		t.Fatal("统计应已写入")
	}
	if n := s.countRows(t, "attack_logs"); n == 0 {
		t.Fatal("日志应已写入")
	}

	// 关闭 DB：错误必须上报而非静默吞掉
	s.DB.Close()
	if err := s.flushTraffic(pending); err == nil {
		t.Fatal("DB 关闭后 flushTraffic 应返回错误")
	}
	if err := s.flushLogs(logs); err == nil {
		t.Fatal("DB 关闭后 flushLogs 应返回错误")
	}
	// flush() 在 DB 异常时不得 panic（仅记录日志）
	s.flush()
	s.Close()
}

func (s *Store) countRows(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("查询 %s 失败: %v", table, err)
	}
	return n
}
