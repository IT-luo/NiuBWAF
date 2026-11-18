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

func TestAttackCountSince(t *testing.T) {
	s := repTestStore(t)
	now := time.Now().Format("2006-01-02 15:04:05")
	old := time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	insertLog(s, "1.1.1.1", "waf", "CRITICAL", now)
	insertLog(s, "1.1.1.1", "waf", "CRITICAL", now)
	insertLog(s, "1.1.1.1", "waf", "CRITICAL", old)
	since := time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05")
	if n := s.AttackCountSince(since); n != 2 {
		t.Fatalf("窗口内计数=%d 期望 2", n)
	}
}