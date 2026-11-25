package store

import (
	"testing"
	"time"
)

func TestCustomRuleCRUD(t *testing.T) {
	s := repTestStore(t)
	r := &CustomRule{Name: "拦截后台", SiteID: 0, Enabled: true, Priority: 50, Logic: "and",
		Conditions: `[{"field":"path","op":"prefix","value":"/admin"}]`, Action: "block", Note: "n"}
	if err := s.CreateRule(r); err != nil {
		t.Fatal(err)
	}
	if r.ID == 0 {
		t.Fatal("应回填自增 ID")
	}
	list, err := s.ListRules()
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	r.Name, r.Enabled, r.Priority = "改名", false, 10
	if err := s.UpdateRule(r); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListRules()
	if list[0].Name != "改名" || list[0].Enabled || list[0].Priority != 10 {
		t.Fatalf("更新未生效: %+v", list[0])
	}
	if err := s.DeleteRule(r.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ = s.ListRules(); len(list) != 0 {
		t.Fatal("删除后应为空")
	}
}

func TestTopStatsExcludeObservations(t *testing.T) {
	s := repTestStore(t)
	now := time.Now().Format("2006-01-02 15:04:05")
	s.DB.Exec(`INSERT INTO attack_logs(ts,client_ip,domain,country,action,msg,severity,status) VALUES(?,?,?,?,?,?,?,?)`, now, "1.1.1.1", "real.test", "CN", "waf", "真实拦截", "CRITICAL", 403)
	s.DB.Exec(`INSERT INTO attack_logs(ts,client_ip,domain,country,action,msg,severity,status) VALUES(?,?,?,?,?,?,?,?)`, now, "2.2.2.2", "observed.test", "US", "bot", "Bot 观察", "WARNING", 200)
	checks := []struct {
		name string
		fn   func(int) ([]KV, error)
	}{
		{"TopIPs", s.TopIPs}, {"TopRules", s.TopRules}, {"TopDomains", s.TopDomains}, {"TopCountries", s.TopCountries},
	}
	for _, check := range checks {
		got, err := check.fn(10)
		if err != nil {
			t.Fatalf("%s: %v", check.name, err)
		}
		if len(got) != 1 || got[0].Count != 1 {
			t.Errorf("%s 应仅保留真实处置, got %+v", check.name, got)
		}
	}
}

func TestAttackCountSince(t *testing.T) {
	s := repTestStore(t)
	now := time.Now().Format("2006-01-02 15:04:05")
	old := time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	insertLog(s, "1.1.1.1", "waf", "CRITICAL", now)
	insertLog(s, "1.1.1.1", "waf", "CRITICAL", now)
	insertLog(s, "1.1.1.1", "waf", "CRITICAL", old)
	insertLogStatus(s, "2.2.2.2", "bot", "WARNING", now, 200)
	since := time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05")
	if n := s.AttackCountSince(since); n != 2 {
		t.Fatalf("窗口内计数=%d 期望 2", n)
	}
}
