package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestShadowColumnMigrationAndCRUD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-rules.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE custom_rules(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL DEFAULT 0,
		name TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		priority INTEGER DEFAULT 100,
		logic TEXT DEFAULT 'and',
		conditions TEXT DEFAULT '[]',
		action TEXT NOT NULL,
		action_param TEXT DEFAULT '',
		note TEXT DEFAULT '',
		created_at TEXT DEFAULT (datetime('now','localtime'))
	)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`INSERT INTO custom_rules(site_id,name,enabled,priority,logic,conditions,action,action_param,note)
		VALUES(0,'旧规则',1,100,'and','[{"field":"path","op":"eq","value":"/"}]','block','','')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("迁移老库失败: %v", err)
	}
	rows, err := s.DB.Query(`PRAGMA table_info(custom_rules)`)
	if err != nil {
		t.Fatal(err)
	}
	foundShadow := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if name == "shadow" {
			foundShadow = true
			if !defaultValue.Valid || defaultValue.String != "0" {
				t.Fatalf("shadow 默认值应为 0, got %+v", defaultValue)
			}
		}
	}
	rows.Close()
	if !foundShadow {
		t.Fatal("老库迁移后缺少 shadow 列")
	}
	rules, err := s.ListRules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("读取老规则失败: %+v %v", rules, err)
	}
	if rules[0].Shadow {
		t.Fatal("老规则必须默认真实执行，而不是影子运行")
	}
	r := rules[0]
	r.Shadow = true
	r.Name = "影子规则"
	if err := s.UpdateRule(&r); err != nil {
		t.Fatal(err)
	}
	created := &CustomRule{Name: "默认真实", Enabled: true, Priority: 100, Logic: "and",
		Conditions: `[{"field":"method","op":"eq","value":"GET"}]`, Action: "log"}
	if err := s.CreateRule(created); err != nil {
		t.Fatal(err)
	}
	rules, _ = s.ListRules()
	if len(rules) != 2 || !rules[0].Shadow || rules[1].Shadow {
		t.Fatalf("shadow CRUD 往返错误: %+v", rules)
	}
	if err := s.DeleteRule(created.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// 第二次 Open 重复执行 ALTER，必须幂等且保留 shadow 值。
	s, err = Open(path)
	if err != nil {
		t.Fatalf("重复迁移失败: %v", err)
	}
	defer s.Close()
	rules, err = s.ListRules()
	if err != nil || len(rules) != 1 || !rules[0].Shadow || rules[0].Name != "影子规则" {
		t.Fatalf("重复迁移后 shadow 未保留: %+v %v", rules, err)
	}
}

func TestReplayQueryContextFiltersLimitAndCancellation(t *testing.T) {
	s := openLogStore(t)
	now := time.Now().Truncate(time.Second)
	from := now.Add(-time.Hour).Format("2006-01-02 15:04:05")
	to := now.Add(time.Hour).Format("2006-01-02 15:04:05")
	seed := func(ts time.Time, ip, domain, action, rawURL string) {
		t.Helper()
		_, err := s.DB.Exec(`INSERT INTO attack_logs(ts,site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id)
			VALUES(?,1,?,?,'CN','GET',?, ?,941100,'replay','HIGH',403,'req')`, ts.Format("2006-01-02 15:04:05"), domain, ip, rawURL, action)
		if err != nil {
			t.Fatal(err)
		}
	}
	seed(now, "10.0.0.1", "api.test", "waf", "/one")
	seed(now.Add(-time.Second), "10.0.0.1", "api.test", "cc", "/two")
	seed(now.Add(-2*time.Second), "10.0.0.1", "other.test", "waf", "/domain")
	seed(now.Add(-3*time.Second), "10.0.0.2", "api.test", "waf", "/ip")
	seed(now.Add(-2*time.Hour), "10.0.0.1", "api.test", "waf", "/old")

	query := ReplayLogQuery{From: from, To: to, IP: "10.0.0.1", Domain: "api.test", Action: "waf", Limit: 10}
	var got []string
	truncated, err := s.QueryContext(context.Background(), query, func(l *AttackLog) error {
		got = append(got, l.URL)
		return nil
	})
	if err != nil || truncated || len(got) != 1 || got[0] != "/one" {
		t.Fatalf("时间/IP/域名/动作过滤错误: got=%v truncated=%v err=%v", got, truncated, err)
	}

	query = ReplayLogQuery{From: from, To: to, Limit: 2}
	seen := 0
	truncated, err = s.QueryContext(context.Background(), query, func(l *AttackLog) error {
		seen++
		return nil
	})
	if err != nil || seen != 2 || !truncated {
		t.Fatalf("LIMIT max+1 应只回调 2 行并标记截断: seen=%d truncated=%v err=%v", seen, truncated, err)
	}
	query.Limit = 4
	seen = 0
	truncated, err = s.QueryContext(context.Background(), query, func(l *AttackLog) error {
		seen++
		return nil
	})
	if err != nil || seen != 4 || truncated {
		t.Fatalf("恰好等于 limit 时不应截断: seen=%d truncated=%v err=%v", seen, truncated, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	seen = 0
	_, err = s.QueryContext(ctx, ReplayLogQuery{From: from, To: to, Limit: 10}, func(l *AttackLog) error {
		seen++
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || seen != 1 {
		t.Fatalf("取消应停止流式读取: seen=%d err=%v", seen, err)
	}
}
