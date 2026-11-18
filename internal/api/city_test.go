package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

// 真实 xdb 在位时验证读时城市补全：/api/logs 与 /api/top/ips 都应带 city
func TestLogsAndTopIPsCarryCity(t *testing.T) {
	src := filepath.Join("..", "..", "data", "ip2region_v4.xdb")
	if _, err := os.Stat(src); err != nil {
		t.Skip("无真实 ip2region_v4.xdb，跳过")
	}
	dir := t.TempDir()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ip2region_v4.xdb"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "city.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng, err := engine.New()
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.New(st, eng, proxy.NewGeoIP(dir), proxy.NewIDCMatcher(dir), proxy.NewTorList(dir), "secret")
	a := New(st, p)

	if err := st.LogAttack(&store.AttackLog{
		SiteID: 1, Domain: "city.test", ClientIP: "112.97.81.30", Country: "CN",
		Method: "GET", URL: "/?id=1' OR '1'='1", Action: "waf", RuleID: 942100,
		Msg: "SQL Injection Attack Detected", Severity: "CRITICAL", Status: 403,
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // 攻击日志异步批量落盘（1s ticker）

	rec := httptest.NewRecorder()
	a.logs(rec, httptest.NewRequest("GET", "/api/logs?size=5", nil))
	if rows, tot, err := st.QueryLogs("", "", "", 5, 0); err != nil || len(rows) != 1 {
		t.Fatalf("直查库应有 1 条: rows=%d total=%d err=%v", len(rows), tot, err)
	}
	var logs struct {
		List []store.AttackLog `json:"list"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &logs); err != nil {
		t.Fatal(err)
	}
	if len(logs.List) != 1 || logs.List[0].City != "深圳市" {
		t.Fatalf("/api/logs 城市补全失败: %+v", logs.List)
	}

	rec = httptest.NewRecorder()
	a.top(rec, httptest.NewRequest("GET", "/api/top/ips", nil), "ips")
	var tops []struct {
		Key   string `json:"key"`
		City  string `json:"city"`
		Count int    `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tops); err != nil {
		t.Fatal(err)
	}
	if len(tops) != 1 || tops[0].Key != "112.97.81.30" || tops[0].City != "深圳市" {
		t.Fatalf("/api/top/ips 城市补全失败: %+v", tops)
	}
}
