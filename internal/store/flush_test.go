package store

import (
	"database/sql"
	"path/filepath"
	"strings"
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

func TestAttackLogDropsCountedAndRateLimited(t *testing.T) {
	logs := captureStoreLogs(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE traffic(
		minute TEXT NOT NULL, site_id INTEGER NOT NULL,
		reqs INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
		PRIMARY KEY(minute, site_id)
	)`); err != nil {
		t.Fatal(err)
	}
	s := &Store{
		DB:      db,
		traffic: map[trafficKey]trafficVal{},
		logCh:   make(chan *AttackLog, 1),
	}
	s.logCh <- &AttackLog{ReqID: "queued"}
	for i := 0; i < 1001; i++ {
		if err := s.LogAttack(&AttackLog{ReqID: "dropped"}); err != nil {
			t.Fatalf("队列满时 LogAttack 仍应非阻塞返回: %v", err)
		}
	}
	if got := s.droppedAttackLogs.Load(); got != 1001 {
		t.Fatalf("丢弃计数 = %d, want 1001", got)
	}
	if got := s.Stats().DroppedAttackLogs; got != 1001 {
		t.Fatalf("Stats 丢弃计数 = %d, want 1001", got)
	}
	if got := strings.Count(logs.String(), "攻击日志队列已满"); got != 2 {
		t.Fatalf("第 1 次和第 1000 次丢弃应各告警一次，实际 %d 次: %q", got, logs.String())
	}
	if !strings.Contains(logs.String(), "累计丢弃 1 条") || !strings.Contains(logs.String(), "累计丢弃 1000 条") {
		t.Fatalf("告警应包含累计丢弃数: %q", logs.String())
	}
}

func TestAuditLogRetentionAndBatchPruning(t *testing.T) {
	s := openHardening(t)
	if _, err := s.DB.Exec(`WITH RECURSIVE seq(n) AS (
		SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < ?
	)
	INSERT INTO audit_logs(user,action,detail)
	SELECT 'admin','seed',printf('seed-%d',n) FROM seq`, auditLogLimit); err != nil {
		t.Fatalf("构造审计日志失败: %v", err)
	}

	// 普通插入不做全表清理；到每 100 次插入的边界才批量收缩。
	s.Audit("admin", "test", "not-pruned")
	if got := s.countRows(t, "audit_logs"); got != auditLogLimit+1 {
		t.Fatalf("非清理周期不应立即删除审计日志, got %d", got)
	}
	s.auditInserts.Store(auditPruneInterval - 1)
	s.Audit("admin", "test", "latest")
	if got := s.countRows(t, "audit_logs"); got != auditLogLimit {
		t.Fatalf("清理后审计日志应保留 %d 条, got %d", auditLogLimit, got)
	}
	var minID, maxID int64
	if err := s.DB.QueryRow(`SELECT MIN(id),MAX(id) FROM audit_logs`).Scan(&minID, &maxID); err != nil {
		t.Fatal(err)
	}
	if minID != 3 || maxID != int64(auditLogLimit+2) {
		t.Fatalf("应仅保留最新记录, minID=%d maxID=%d", minID, maxID)
	}
	latest, err := s.ListAudit(1)
	if err != nil || len(latest) != 1 || latest[0].Detail != "latest" {
		t.Fatalf("最新审计记录保留错误: %+v, err=%v", latest, err)
	}
}
