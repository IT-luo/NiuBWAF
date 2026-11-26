package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"niubwaf/internal/store"
)

func TestRequestDiagnosticsDistinguishObservationsAndResponseSources(t *testing.T) {
	var idAtOrigin atomic.Value
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idAtOrigin.Store(r.Header.Get(requestDiagnosticHeader))
		w.Header().Set(requestDiagnosticHeader, "origin-supplied-id")
		if r.URL.Path == "/origin-denied" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	const domain = "diagnostics.test"
	const browser = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
	p := newSecurityTestProxy(t, store.Site{Domain: domain, Name: "diagnostics", Upstream: origin.URL, Enabled: true, BotMode: "log"}, nil)
	perform := func(path, ua string) (*httptest.ResponseRecorder, RequestDiagnostic) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://"+domain+path, nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set(requestDiagnosticHeader, "client-supplied-id")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec, requireDiagnostic(t, p, rec)
	}
	allowed, d := perform("/?token=fixture-private-token", browser)
	if allowed.Code != 200 || len(allowed.Header().Values(requestDiagnosticHeader)) != 1 || idAtOrigin.Load() != d.ReqID || d.Source != "origin" || d.Outcome != "allowed" || d.UpstreamStatus != 200 || d.Domain != domain {
		t.Fatalf("可信请求 ID 或正常响应诊断有误: %+v", d)
	}
	_, d = perform("/", "curl/8.0.0")
	if d.Status != 200 || d.Outcome != "observed" || len(d.Observations) != 1 || d.Observations[0].Module != "bot" {
		t.Fatalf("观察事件诊断有误: %+v", d)
	}
	_, d = perform("/origin-denied", browser)
	if d.Status != 403 || d.UpstreamStatus != 403 || d.Source != "origin" || d.Outcome != "origin_error" {
		t.Fatalf("上游 403 诊断有误: %+v", d)
	}
	p.sites[domain].BotMode = "block"
	_, d = perform("/", "curl/8.0.0")
	if d.Status != 403 || d.UpstreamAttempted || d.Source != "waf" || d.Outcome != "blocked" || d.Module != "bot" {
		t.Fatalf("WAF 403 诊断有误: %+v", d)
	}
}

func TestRequestDiagnosticsExplainUploadLimitsAndCapacity(t *testing.T) {
	origin := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(origin.Close)
	p := uploadTestProxy(t, origin.URL)
	const limit = 2 << 20
	request := func(declared int64, body string) RequestDiagnostic {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://uploads.test/api/upload", strings.NewReader(body))
		req.ContentLength = declared
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return requireDiagnostic(t, p, rec)
	}
	d := request(limit+2, "x")
	if d.Status != 413 || d.BodyLimitBytes != limit || d.BodyLimitKind != "upload_policy" || d.BodyBytes != limit+2 || d.BodyBytesKind != "declared" {
		t.Fatalf("上传策略声明长度诊断有误: %+v", d)
	}
	d = request(-1, strings.Repeat("x", limit+2))
	if d.Status != 413 || d.BodyLimitBytes != limit || d.BodyBytes != limit+1 || d.BodyBytesKind != "at_least" {
		t.Fatalf("未知长度超限诊断有误: %+v", d)
	}
	site := p.sites["uploads.test"]
	route := uploadRoute{method: http.MethodPost, path: "/api/upload"}
	if !p.uploadBudget.acquire(uploadRouteKey{siteID: site.ID, route: route}, site.uploadPolicies[route], limit) {
		t.Fatal("测试未能占用上传容量")
	}
	d = request(-1, "x")
	if d.Status != 503 || d.Module != "upload_capacity" || d.Source != "waf" || d.Outcome != "rejected" || d.UpstreamAttempted {
		t.Fatalf("上传容量拒绝诊断有误: %+v", d)
	}
}

func requireDiagnostic(t *testing.T, p *Proxy, rec *httptest.ResponseRecorder) RequestDiagnostic {
	t.Helper()
	id := rec.Header().Get(requestDiagnosticHeader)
	d, ok := p.FindRequestDiagnostic(id)
	if !ok || len(id) != 12 || d.ReqID != id || d.Status != rec.Code {
		t.Fatalf("未找到 HTTP %d 请求诊断 %q: %+v", rec.Code, id, d)
	}
	return d
}

func TestRequestDiagnosticsKeepErrorsOutsideSuccessRingAndExpire(t *testing.T) {
	p := &Proxy{}
	now := time.Now()
	p.diagnostics.record(RequestDiagnostic{ReqID: "000000000000", TS: now, Status: 413})
	p.diagnostics.record(RequestDiagnostic{ReqID: "000000000001", TS: now, Status: 200})
	for i := 2; i <= 1+diagnosticShardSize; i++ {
		p.diagnostics.record(RequestDiagnostic{ReqID: fmt.Sprintf("%012x", i), TS: now, Status: 200})
	}
	if _, ok := p.FindRequestDiagnostic("000000000001"); ok {
		t.Fatal("近期请求缓存超出上限")
	}
	if _, ok := p.FindRequestDiagnostic("000000000000"); !ok {
		t.Fatal("正常请求挤掉了错误事件")
	}
	p.diagnostics.record(RequestDiagnostic{ReqID: "000000000000", TS: now.Add(-diagnosticRetention - time.Second), Status: 413})
	if _, ok := p.FindRequestDiagnostic("000000000000"); ok {
		t.Fatal("过期诊断仍可查询")
	}
}
