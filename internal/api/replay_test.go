package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/store"
)

func newReplayTestAPI(t *testing.T) *API {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, nil)
}

func replayTestDraft() store.CustomRule {
	return store.CustomRule{
		Name: "回放草稿", Enabled: true, Priority: 100, Logic: "and",
		Conditions: `[{"field":"path","op":"prefix","value":"/match"}]`,
		Action:     "block", Shadow: true,
	}
}

func doReplayTestRequest(a *API, ctx context.Context, req replayRuleRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/api/rules/replay", strings.NewReader(string(body)))
	httpReq.Header.Set("Content-Type", "application/json")
	if ctx != nil {
		httpReq = httpReq.WithContext(ctx)
	}
	rec := httptest.NewRecorder()
	a.replayRule(rec, httpReq)
	return rec
}

func seedReplayAPILog(t *testing.T, a *API, ts time.Time, siteID int64, domain, ip, action, rawURL string) {
	t.Helper()
	_, err := a.Store.DB.Exec(`INSERT INTO attack_logs(ts,site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id)
		VALUES(?,?,?,?,'CN','GET',?, ?,941100,'seed','HIGH',403,'req')`,
		ts.Format("2006-01-02 15:04:05"), siteID, domain, ip, rawURL, action)
	if err != nil {
		t.Fatal(err)
	}
}

func decodeReplayTestResponse(t *testing.T, rec *httptest.ResponseRecorder) replayRuleResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("回放状态码 = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp replayRuleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func replayTableCount(t *testing.T, a *API, table string) int {
	t.Helper()
	var n int
	if err := a.Store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReplayRuleFiltersLimitSamplesAndThreeValues(t *testing.T) {
	a := newReplayTestAPI(t)
	now := time.Now().Truncate(time.Second)
	seedReplayAPILog(t, a, now, 1, "api.test", "10.0.0.1", "waf", "/match?id=7")
	seedReplayAPILog(t, a, now.Add(-time.Second), 1, "api.test", "10.0.0.1", "waf", "/other")
	seedReplayAPILog(t, a, now.Add(-2*time.Second), 1, "api.test", "10.0.0.1", "waf", "://bad")
	seedReplayAPILog(t, a, now.Add(-3*time.Second), 2, "other.test", "10.0.0.1", "waf", "/match-domain")
	seedReplayAPILog(t, a, now.Add(-4*time.Second), 1, "api.test", "10.0.0.2", "waf", "/match-ip")
	seedReplayAPILog(t, a, now.Add(-5*time.Second), 1, "api.test", "10.0.0.1", "cc", "/match-action")
	seedReplayAPILog(t, a, now.Add(-25*time.Hour), 1, "api.test", "10.0.0.1", "waf", "/match-old")
	base := replayRuleRequest{
		Rule: replayTestDraft(), From: now.Add(-2 * time.Hour).Format("2006-01-02 15:04:05"),
		To: now.Add(time.Hour).Format("2006-01-02 15:04:05"), Domain: "api.test", IP: "10.0.0.1", Action: "waf",
		Limit: 2, SampleLimit: 1,
	}
	logsBefore := replayTableCount(t, a, "attack_logs")

	resp := decodeReplayTestResponse(t, doReplayTestRequest(a, nil, base))
	if resp.Source != "attack_logs" || resp.Scope != "logged_security_events_only" ||
		!reflect.DeepEqual(resp.UnavailableFields, []string{"header", "body"}) {
		t.Fatalf("回放来源/范围声明错误: %+v", resp)
	}
	if resp.Scanned != 2 || resp.Matched != 0 || resp.NotMatched != 1 || resp.Indeterminate != 0 || resp.Invalid != 1 || !resp.Truncated {
		t.Fatalf("limit/max+1 或分类统计错误: %+v", resp)
	}
	if len(resp.Samples) != 1 || resp.Samples[0].Result != "invalid" || resp.Samples[0].Log.URL != "://bad" {
		t.Fatalf("sample_limit 或样本内容错误: %+v", resp.Samples)
	}

	base.Limit, base.SampleLimit = 3, 5
	resp = decodeReplayTestResponse(t, doReplayTestRequest(a, nil, base))
	if resp.Scanned != 3 || resp.Matched != 1 || resp.NotMatched != 1 || resp.Invalid != 1 || resp.Truncated {
		t.Fatalf("完整过滤结果错误: %+v", resp)
	}

	base.Rule.Conditions = `[{"field":"path","op":"prefix","value":"/match"},{"field":"header","op":"eq","name":"X-Test","value":"yes"}]`
	resp = decodeReplayTestResponse(t, doReplayTestRequest(a, nil, base))
	if resp.Scanned != 3 || resp.Matched != 0 || resp.NotMatched != 1 || resp.Indeterminate != 1 || resp.Invalid != 1 {
		t.Fatalf("header unknown 不得计入不命中: %+v", resp)
	}
	if got := replayTableCount(t, a, "attack_logs"); got != logsBefore {
		t.Fatalf("回放不得改变攻击日志: before=%d after=%d", logsBefore, got)
	}
	if got := replayTableCount(t, a, "custom_rules"); got != 0 {
		t.Fatalf("回放不得保存规则草稿: %d", got)
	}
	if got := replayTableCount(t, a, "audit_logs"); got != 0 {
		t.Fatalf("回放不得写审计或其他日志: %d", got)
	}
}

func TestReplayHandlesRedactedQuery(t *testing.T) {
	a := newReplayTestAPI(t)
	now := time.Now().Add(-time.Minute)
	seedReplayAPILog(t, a, now, 1, "api.test", "10.0.0.1", "waf", "/match?query=log-fixture")
	seedReplayAPILog(t, a, now, 1, "api.test", "10.0.0.1", "waf", "/redacted")
	if _, err := a.Store.DB.Exec("UPDATE attack_logs SET query_redacted=1 WHERE url='/redacted'"); err != nil {
		t.Fatal(err)
	}
	rule := replayTestDraft()
	rule.Conditions = `[{"field":"param","name":"query","op":"eq","value":"log-fixture"}]`
	rec := doReplayTestRequest(a, nil, replayRuleRequest{Rule: rule})
	resp := decodeReplayTestResponse(t, rec)
	if resp.Matched != 1 || resp.Indeterminate != 1 || strings.Contains(rec.Body.String(), "log-fixture") {
		t.Fatalf("旧记录应可评估且对外脱敏，新记录应标记为不可判定: %+v", resp)
	}
}

func TestReplayRuleForcesDraftSiteScope(t *testing.T) {
	a := newReplayTestAPI(t)
	siteA := &store.Site{Name: "A", Domain: "a.test", Upstream: "http://127.0.0.1:18081", Enabled: true}
	siteB := &store.Site{Name: "B", Domain: "b.test", Upstream: "http://127.0.0.1:18082", Enabled: true}
	if err := a.Store.CreateSite(siteA); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.CreateSite(siteB); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	seedReplayAPILog(t, a, now, siteA.ID, "a.test", "10.0.0.1", "waf", "/match-a")
	seedReplayAPILog(t, a, now, siteB.ID, "b.test", "10.0.0.1", "waf", "/match-b")
	seedReplayAPILog(t, a, now, siteB.ID, "a.test", "10.0.0.1", "waf", "/match-wrong-site")
	draft := replayTestDraft()
	draft.SiteID = siteA.ID
	req := replayRuleRequest{Rule: draft, Domain: "b.test", Limit: 10, SampleLimit: 10}
	resp := decodeReplayTestResponse(t, doReplayTestRequest(a, nil, req))
	if resp.Domain != "a.test" || resp.Scanned != 1 || resp.Matched != 1 || len(resp.Samples) != 1 || resp.Samples[0].Log.URL != "/match-a" {
		t.Fatalf("站点专属草稿必须强制本站范围: %+v", resp)
	}
}

func TestReplayRuleDefaultsValidationCancellationAndConcurrency(t *testing.T) {
	if replayTimeout != 10*time.Second || cap(replaySlots) != 1 {
		t.Fatalf("回放超时/并发容量错误: timeout=%v cap=%d", replayTimeout, cap(replaySlots))
	}
	a := newReplayTestAPI(t)
	now := time.Now()
	seedReplayAPILog(t, a, now, 1, "api.test", "10.0.0.1", "waf", "/match-new")
	seedReplayAPILog(t, a, now.Add(-25*time.Hour), 1, "api.test", "10.0.0.1", "waf", "/match-old")
	resp := decodeReplayTestResponse(t, doReplayTestRequest(a, nil, replayRuleRequest{Rule: replayTestDraft()}))
	if resp.Scanned != 1 || resp.Matched != 1 {
		t.Fatalf("默认回放窗口应为 24h: %+v", resp)
	}

	tooWide := replayRuleRequest{Rule: replayTestDraft(), From: now.Add(-169 * time.Hour).Format(time.RFC3339), To: now.Format(time.RFC3339)}
	if rec := doReplayTestRequest(a, nil, tooWide); rec.Code != http.StatusBadRequest {
		t.Fatalf("超过 168h 应拒绝, got %d", rec.Code)
	}
	tooMany := replayRuleRequest{Rule: replayTestDraft(), Limit: replayMaxLimit + 1}
	if rec := doReplayTestRequest(a, nil, tooMany); rec.Code != http.StatusBadRequest {
		t.Fatalf("超过最大行数应拒绝, got %d", rec.Code)
	}
	invalidDraft := replayRuleRequest{Rule: replayTestDraft()}
	invalidDraft.Rule.Conditions = `[]`
	if rec := doReplayTestRequest(a, nil, invalidDraft); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法规则草稿应拒绝, got %d", rec.Code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rec := doReplayTestRequest(a, ctx, replayRuleRequest{Rule: replayTestDraft()}); rec.Code != http.StatusRequestTimeout {
		t.Fatalf("取消上下文应停止回放, got %d body=%s", rec.Code, rec.Body.String())
	}

	replaySlots <- struct{}{}
	rec := doReplayTestRequest(a, nil, replayRuleRequest{Rule: replayTestDraft()})
	<-replaySlots
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("容量 1 被占用时应非阻塞返回 429, got %d", rec.Code)
	}

	shadowRec := httptest.NewRecorder()
	a.listShadowRules(shadowRec, httptest.NewRequest(http.MethodGet, "/api/rules/shadow", nil))
	if shadowRec.Code != http.StatusServiceUnavailable {
		t.Fatal("代理未初始化时影子快照 API 应明确返回 503")
	}
}
