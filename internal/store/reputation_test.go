package store

import (
	"path/filepath"
	"testing"
	"time"
)

func repTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func insertLog(s *Store, ip, action, severity, ts string) {
	insertLogStatus(s, ip, action, severity, ts, 403)
}

func insertLogStatus(s *Store, ip, action, severity, ts string, status int) {
	s.DB.Exec(`INSERT INTO attack_logs(ts,client_ip,action,severity,status) VALUES(?,?,?,?,?)`, ts, ip, action, severity, status)
}

func TestScoreIPsWeightingAndFilter(t *testing.T) {
	s := repTestStore(t)
	now := time.Now().Format("2006-01-02 15:04:05")
	old := time.Now().Add(-48 * time.Hour).Format("2006-01-02 15:04:05")
	// A: 10 CRITICAL → 30
	for i := 0; i < 10; i++ {
		insertLog(s, "10.0.0.1", "waf", "CRITICAL", now)
	}
	// B: 5 WARNING cc(=10) + 5 NOTICE blacklist(排除) → 10
	for i := 0; i < 5; i++ {
		insertLog(s, "10.0.0.2", "cc", "WARNING", now)
		insertLog(s, "10.0.0.2", "blacklist", "NOTICE", now)
	}
	// C: 处置动作 reputation 不计分
	for i := 0; i < 50; i++ {
		insertLog(s, "10.0.0.3", "reputation", "WARNING", now)
	}
	// D: 窗口外的旧攻击不计分
	for i := 0; i < 50; i++ {
		insertLog(s, "10.0.0.4", "waf", "CRITICAL", old)
	}
	// E: 状态 200 的语义观察不计分
	for i := 0; i < 50; i++ {
		insertLogStatus(s, "10.0.0.5", "semantic", "CRITICAL", now, 200)
	}
	windowStart := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	scores, err := s.ScoreIPs(windowStart, 10)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]IPScore{}
	for _, sc := range scores {
		got[sc.IP] = sc
	}
	if a := got["10.0.0.1"]; a.Score != 30 || a.Count != 10 {
		t.Errorf("A 期望 score=30 count=10, got %+v", a)
	}
	if b := got["10.0.0.2"]; b.Score != 10 || b.Count != 5 {
		t.Errorf("B 期望 score=10 count=5（blacklist 排除）, got %+v", b)
	}
	if _, ok := got["10.0.0.3"]; ok {
		t.Error("C reputation 处置动作不应计分")
	}
	if _, ok := got["10.0.0.4"]; ok {
		t.Error("D 窗口外攻击不应计分")
	}
	if _, ok := got["10.0.0.5"]; ok {
		t.Error("E 状态 200 的语义观察不应计分")
	}
	// 阈值过滤
	hi, _ := s.ScoreIPs(windowStart, 30)
	if len(hi) != 1 || hi[0].IP != "10.0.0.1" {
		t.Errorf("阈值 30 应仅命中 A, got %+v", hi)
	}
}

func TestReputationBanLifecycle(t *testing.T) {
	s := repTestStore(t)
	now := time.Now()
	nowStr := now.Format("2006-01-02 15:04:05")
	future := now.Add(time.Hour).Format("2006-01-02 15:04:05")
	past := now.Add(-time.Hour).Format("2006-01-02 15:04:05")

	if err := s.UpsertReputation("1.2.3.4", 30, 1, future, "测试封禁"); err != nil {
		t.Fatal(err)
	}
	r := s.GetReputation("1.2.3.4")
	if r == nil || r.Score != 30 || r.BanCount != 1 || r.BannedUntil != future {
		t.Fatalf("信誉记录写入错误: %+v", r)
	}
	bans, err := s.ActiveBans(nowStr)
	if err != nil {
		t.Fatal(err)
	}
	if bans["1.2.3.4"] == 0 {
		t.Error("生效封禁应包含 1.2.3.4")
	}
	// 过期封禁不在生效列表
	s.UpsertReputation("5.6.7.8", 30, 1, past, "已过期")
	bans, err = s.ActiveBans(nowStr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bans["5.6.7.8"]; ok {
		t.Error("过期封禁不应生效")
	}
	// 人工解封：清空封禁 + 重置计数 + 赦免
	pardon := now.Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	if err := s.Unban("1.2.3.4", pardon); err != nil {
		t.Fatal(err)
	}
	r = s.GetReputation("1.2.3.4")
	if r.BannedUntil != "" || r.BanCount != 0 || r.PardonedUntil != pardon {
		t.Errorf("解封后状态错误: %+v", r)
	}
	bans, err = s.ActiveBans(nowStr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bans["1.2.3.4"]; ok {
		t.Error("解封后不应再封禁")
	}
	// 列表与计数
	list, _ := s.ListReputation(10)
	if len(list) < 2 {
		t.Errorf("信誉列表应至少 2 条, got %d", len(list))
	}
	insertLog(s, "9.9.9.9", "waf", "CRITICAL", nowStr)
	insertLogStatus(s, "9.9.9.9", "semantic", "CRITICAL", nowStr, 200)
	if n := s.IPAttackCount("9.9.9.9"); n != 1 {
		t.Errorf("IPAttackCount 期望 1, got %d", n)
	}
}
