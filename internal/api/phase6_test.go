package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"niubwaf/internal/engine"
)

func seedAttackLog(t *testing.T, a *API, ip, domain, action string) {
	t.Helper()
	if _, err := a.Store.DB.Exec(`INSERT INTO attack_logs(site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id)
		VALUES(0,?,?,'CN','GET','/x',?,941100,'测试,含逗号','HIGH',403,'rid')`, domain, ip, action); err != nil {
		t.Fatalf("写入攻击日志失败: %v", err)
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
		req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body))
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

func TestBodyScanLimitSetting(t *testing.T) {
	a := fullTestAPI(t)

	rec := httptest.NewRecorder()
	a.getSettings(rec)
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["body_scan_kb"] != "128" {
		t.Fatalf("默认送检上限应为 128KB, got %q", got["body_scan_kb"])
	}
	if a.Proxy.Engine.ScanLimit() != 128<<10 {
		t.Fatalf("引擎送检上限应为 128KB, got %d", a.Proxy.Engine.ScanLimit())
	}

	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		a.putSettings(r, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body)))
		return r
	}
	for _, bad := range []string{`{"body_scan_kb":"10"}`, `{"body_scan_kb":"4096"}`, `{"body_scan_kb":"abc"}`} {
		if r := put(bad); r.Code != 400 {
			t.Fatalf("非法送检上限应返回 400: %s → %d %s", bad, r.Code, r.Body.String())
		}
	}
	if a.Proxy.Engine.ScanLimit() != 128<<10 {
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
