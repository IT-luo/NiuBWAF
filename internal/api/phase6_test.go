package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"niubwaf/internal/engine"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

func seedAttackLog(t *testing.T, a *API, ip, domain, action string) {
	t.Helper()
	if _, err := a.Store.DB.Exec(`INSERT INTO attack_logs(site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id)
		VALUES(0,?,?,'CN','GET','/x',?,941100,'测试,含逗号','HIGH',403,'rid')`, domain, ip, action); err != nil {
		t.Fatalf("写入攻击日志失败: %v", err)
	}
}

func TestAttackLogFeedFiltersBeforePaging(t *testing.T) {
	a := fullTestAPI(t)
	seedAttackLog(t, a, "192.0.2.1", "site.test", "waf")
	seedAttackLog(t, a, "192.0.2.2", "site.test", "bot")
	if _, err := a.Store.DB.Exec(`UPDATE attack_logs SET status=200 WHERE action='bot'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query  string
		action string
		total  int
	}{
		{"?size=1", "bot", 2},
		{"?size=1&attack_only=1", "waf", 1},
	} {
		rec := httptest.NewRecorder()
		a.logs(rec, httptest.NewRequest(http.MethodGet, "/api/logs"+tc.query, nil))
		var response struct {
			List  []struct{ Action string }
			Total int
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != tc.total || len(response.List) != 1 || response.List[0].Action != tc.action {
			t.Fatalf("查询 %s: %s", tc.query, rec.Body)
		}
	}
}

func TestAttackLogFeedReturnsCoordinatesWhenRequested(t *testing.T) {
	a := fullTestAPI(t)
	seedAttackLog(t, a, "192.0.2.1", "site.test", "waf")
	seedAttackLog(t, a, "192.0.2.2", "site.test", "cc")
	if _, err := a.Store.DB.Exec("UPDATE attack_logs SET country='' WHERE action='cc'"); err != nil {
		t.Fatal(err)
	}
	type row struct {
		Action string
		Lat    *float64
		Lon    *float64
	}
	query := func(path string) map[string]row {
		t.Helper()
		rec := httptest.NewRecorder()
		a.logs(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var got struct{ List []row }
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || len(got.List) != 2 {
			t.Fatalf("load %s: status=%d, %v, body=%s", path, rec.Code, err, rec.Body)
		}
		return map[string]row{got.List[0].Action: got.List[0], got.List[1].Action: got.List[1]}
	}
	located := query("/api/logs?screen=1")
	if entry := located["waf"]; entry.Lat == nil || entry.Lon == nil || *entry.Lat != 35.9 || *entry.Lon != 104.2 {
		t.Fatalf("stored country should supply fallback coordinates: %+v", entry)
	}
	if entry := located["cc"]; entry.Lat != nil || entry.Lon != nil {
		t.Fatalf("unknown locations must not receive coordinates: %+v", entry)
	}
	if entry := query("/api/logs?attack_only=1")["waf"]; entry.Lat != nil || entry.Lon != nil {
		t.Fatalf("the standard log response should omit coordinates: %+v", entry)
	}
}

func TestScreenLogFeedReturnsBoundedAttacksWithoutTotal(t *testing.T) {
	a := fullTestAPI(t)
	for i := 0; i < 62; i++ {
		seedAttackLog(t, a, fmt.Sprintf("192.0.2.%d", i+1), "site.test", "waf")
	}
	seedAttackLog(t, a, "192.0.2.200", "site.test", "bot")
	if _, err := a.Store.DB.Exec("UPDATE attack_logs SET status=200 WHERE action='bot'"); err != nil {
		t.Fatal(err)
	}

	path := "/api/logs?screen=1&size=200"
	rec := httptest.NewRecorder()
	a.logs(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var result struct {
		List []struct {
			ClientIP string `json:"client_ip"`
		}
		Total *int
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("screen feed: status=%d, %v", rec.Code, err)
	}
	if result.Total != nil || len(result.List) != 60 || result.List[0].ClientIP != "192.0.2.62" ||
		result.List[59].ClientIP != "192.0.2.3" {
		t.Fatalf("expected the latest 60 attacks and no total, got %d rows, total=%v", len(result.List), result.Total)
	}
	unauthenticated := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, path, nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("screen feed requires authentication, got %d", unauthenticated.Code)
	}
}

func TestScreenHistoryKeepsLocationConsistentWithStoredCountry(t *testing.T) {
	entry := store.AttackLog{Country: "CN"}
	lookup := proxy.GeoCity{Country: "US", City: "Seattle", Latitude: 47.61, Longitude: -122.33}
	got := locateAttackLog(entry, lookup)
	if got.Country != "CN" || got.City != "" || got.Lat == nil || got.Lon == nil ||
		*got.Lat != 35.9 || *got.Lon != 104.2 {
		t.Fatalf("expected recorded country and its approximate location, got %+v", got)
	}
}

func TestAllowedContentTypesSetting(t *testing.T) {
	a := fullTestAPI(t)

	rec := httptest.NewRecorder()
	a.getSettings(rec)
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if _, ok := got["allowed_content_types"]; !ok {
		t.Fatalf("设置项应包含 allowed_content_types: %v", got)
	}

	plain := func(ct string) engine.Result {
		h := http.Header{}
		h.Set("Host", "t.local")
		h.Set("User-Agent", "Mozilla/5.0")
		h.Set("Content-Type", ct)
		h.Set("Content-Length", "11")
		return a.Proxy.Engine.Detect("balanced", nil, &engine.RequestInfo{
			ClientIP: "1.2.3.4", ServerIP: "127.0.0.1", Method: "POST", URL: "/ingest",
			Proto: "HTTP/1.1", Headers: h, Body: []byte("hello world"),
		})
	}
	// 默认（未配置追加类型）排除 920420：任意 CT 放行
	if res := plain("text/plain"); res.Blocked {
		t.Fatalf("默认应放行任意 CT, got rule=%d msg=%s", res.RuleID, res.Msg)
	}

	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		req := testJSONRequest("PUT", "/api/settings", body)
		a.putSettings(r, req)
		return r
	}
	if r := put(`{"allowed_content_types":"text/plain"}`); r.Code != 200 {
		t.Fatalf("保存应成功, got %d %s", r.Code, r.Body.String())
	}
	if v := a.Store.GetSetting("allowed_content_types"); v != "text/plain" {
		t.Fatalf("设置应落盘, got %q", v)
	}
	if res := plain("text/plain"); res.Blocked {
		t.Fatalf("追加后应放行 text/plain, got rule=%d msg=%s", res.RuleID, res.Msg)
	}
	// 配置后进入严格模式：白名单外 CT 被 920420 拦截
	if res := plain("application/x-custom"); !res.Blocked || res.RuleID != 920420 {
		t.Fatalf("严格模式下白名单外 CT 应被 920420 拦截, got blocked=%v rule=%d", res.Blocked, res.RuleID)
	}
	for _, bad := range []string{
		`{"allowed_content_types":"text/plain| |x"}`,
		`{"allowed_content_types":"no-slash"}`,
		`{"allowed_content_types":"text/ plain"}`,
		`{"allowed_content_types":"` + strings.Repeat("application/x, ", 33) + `"}`,
	} {
		if r := put(bad); r.Code != 400 {
			t.Fatalf("非法配置应返回 400: %s → %d %s", bad, r.Code, r.Body.String())
		}
	}
	if v := a.Store.GetSetting("allowed_content_types"); v != "text/plain" {
		t.Fatalf("非法配置不应落盘, got %q", v)
	}
	if r := put(`{"allowed_content_types":""}`); r.Code != 200 {
		t.Fatalf("清空应成功, got %d", r.Code)
	}
	if res := plain("application/x-custom"); res.Blocked {
		t.Fatalf("清空后应恢复默认放行语义, got rule=%d msg=%s", res.RuleID, res.Msg)
	}
}

func TestClearLogsAPI(t *testing.T) {
	a := fullTestAPI(t)
	for i := 0; i < 4; i++ {
		seedAttackLog(t, a, fmt.Sprintf("10.0.0.%d", i), "a.local", "waf")
	}
	a.Store.Audit("admin", "测试", "审计不应被清空")

	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/logs", nil))
	if rec.Code != 401 {
		t.Fatalf("未登录清空日志应 401, got %d", rec.Code)
	}

	rec2 := httptest.NewRecorder()
	a.clearLogs(rec2, httptest.NewRequest("DELETE", "/api/logs", nil))
	if rec2.Code != 200 {
		t.Fatalf("清空应成功, got %d %s", rec2.Code, rec2.Body.String())
	}
	var body map[string]any
	json.Unmarshal(rec2.Body.Bytes(), &body)
	if int(body["deleted"].(float64)) != 4 {
		t.Fatalf("应删除 4 条, got %v", body["deleted"])
	}
	if _, total, _ := a.Store.QueryLogs("", "", "", 20, 0); total != 0 {
		t.Fatalf("清空后应为 0 条, got %d", total)
	}
	rows, err := a.Store.DB.Query(`SELECT COUNT(*) FROM audit_logs`)
	if err != nil {
		t.Fatalf("查询审计日志失败: %v", err)
	}
	defer rows.Close()
	rows.Next()
	var n int
	rows.Scan(&n)
	if n == 0 {
		t.Fatal("清空攻击日志不应影响审计日志")
	}
}

func TestExportCSVStreamsRows(t *testing.T) {
	a := fullTestAPI(t)
	for i := 0; i < 30; i++ {
		seedAttackLog(t, a, "10.0.0.1", "a.local", "waf")
	}
	seedAttackLog(t, a, "10.0.0.2", "b.local", "cc")

	rec := httptest.NewRecorder()
	a.exportCSV(rec, httptest.NewRequest("GET", "/api/logs/export", nil))
	if rec.Code != 200 {
		t.Fatalf("导出应成功, got %d", rec.Code)
	}
	out := rec.Body.String()
	if !strings.HasPrefix(out, "\ufeff时间,站点域名,") {
		t.Fatalf("应输出 BOM + 表头, got %.40q", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 32 {
		t.Fatalf("应导出 31 条数据行 + 表头, got %d", len(lines))
	}
	if !strings.Contains(out, `"测试,含逗号"`) {
		t.Fatal("含逗号的字段应被引号转义")
	}

	rec2 := httptest.NewRecorder()
	a.exportCSV(rec2, httptest.NewRequest("GET", "/api/logs/export?ip=10.0.0.2", nil))
	if n := len(strings.Split(strings.TrimSpace(rec2.Body.String()), "\n")); n != 2 {
		t.Fatalf("按 IP 过滤应仅导出 1 条, got %d 行", n-1)
	}
	rec3 := httptest.NewRecorder()
	a.exportCSV(rec3, httptest.NewRequest("GET", "/api/logs/export?domain=a.local", nil))
	if n := len(strings.Split(strings.TrimSpace(rec3.Body.String()), "\n")); n != 31 {
		t.Fatalf("按域名过滤应导出 30 条, got %d 行", n-1)
	}
}

func TestExportCSVFormulaInjection(t *testing.T) {
	a := fullTestAPI(t)
	if _, err := a.Store.DB.Exec(`INSERT INTO attack_logs(site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id)
		VALUES(0,'=HYPERLINK("http://evil")','1.2.3.4','CN','GET','=@SUM(1+1)','waf',941100,'+cmd|''/c calc''!A0','HIGH',403,'rid')`); err != nil {
		t.Fatalf("写入攻击日志失败: %v", err)
	}

	rec := httptest.NewRecorder()
	a.exportCSV(rec, httptest.NewRequest("GET", "/api/logs/export", nil))
	if rec.Code != 200 {
		t.Fatalf("导出应成功, got %d", rec.Code)
	}
	out := rec.Body.String()
	for _, want := range []string{"'=HYPERLINK", "'=@SUM(1+1)", "'+cmd|"} {
		if !strings.Contains(out, want) {
			t.Fatalf("公式字符开头的单元格应加单引号前缀, 缺 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, ",=HYPERLINK") || strings.Contains(out, ",=@SUM") || strings.Contains(out, ",+cmd|") {
		t.Fatalf("导出中不应出现裸公式单元格:\n%s", out)
	}
}

func TestBodyScanLimitSetting(t *testing.T) {
	a := fullTestAPI(t)

	rec := httptest.NewRecorder()
	a.getSettings(rec)
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["body_scan_kb"] != "16" {
		t.Fatalf("默认送检上限应为 16KB, got %q", got["body_scan_kb"])
	}
	if a.Proxy.Engine.ScanLimit() != 16<<10 {
		t.Fatalf("引擎送检上限应为 16KB, got %d", a.Proxy.Engine.ScanLimit())
	}

	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		a.putSettings(r, testJSONRequest("PUT", "/api/settings", body))
		return r
	}
	for _, bad := range []string{`{"body_scan_kb":"10"}`, `{"body_scan_kb":"4096"}`, `{"body_scan_kb":"abc"}`} {
		if r := put(bad); r.Code != 400 {
			t.Fatalf("非法送检上限应返回 400: %s → %d %s", bad, r.Code, r.Body.String())
		}
	}
	if a.Proxy.Engine.ScanLimit() != 16<<10 {
		t.Fatal("非法配置不应改动引擎送检上限")
	}
	if r := put(`{"body_scan_kb":"64"}`); r.Code != 200 {
		t.Fatalf("保存应成功, got %d %s", r.Code, r.Body.String())
	}
	if v := a.Store.GetSetting("body_scan_kb"); v != "64" {
		t.Fatalf("设置应落盘, got %q", v)
	}
	if a.Proxy.Engine.ScanLimit() != 64<<10 {
		t.Fatalf("应同步生效 64KB, got %d", a.Proxy.Engine.ScanLimit())
	}
}
