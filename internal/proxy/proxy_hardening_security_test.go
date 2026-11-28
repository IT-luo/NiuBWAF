package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/metrics"
	"niubwaf/internal/store"
)

func newSecurityTestProxy(t *testing.T, site store.Site, settings map[string]string) *Proxy {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "security.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	for key, value := range settings {
		if err := st.SetSetting(key, value); err != nil {
			t.Fatalf("写入设置 %s 失败: %v", key, err)
		}
	}
	eng, err := engine.New()
	if err != nil {
		t.Fatalf("构建 WAF 引擎失败: %v", err)
	}
	if site.WAFMode == "" {
		site.WAFMode = "balanced"
	}
	if err := st.CreateSite(&site); err != nil {
		t.Fatalf("创建测试站点失败: %v", err)
	}
	p := &Proxy{
		Store: st, Engine: eng, Geo: &GeoIP{}, Limiter: NewLimiter(),
		Cap: NewCaptcha("security-test-secret"), Hub: NewHub(),
		dynSecret: []byte("security-test-secret"),
	}
	p.Reload()
	return p
}

func TestReloadKeepsSnapshotWhenIPListCannotBeRead(t *testing.T) {
	p := newSecurityTestProxy(t, store.Site{Domain: "example.test", Upstream: "http://127.0.0.1:8080"}, nil)
	site := p.sites["example.test"]
	if _, err := p.Store.DB.Exec(`DELETE FROM sites`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Store.DB.Exec(`ALTER TABLE ip_lists RENAME TO unavailable_ip_lists`); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	if got := p.sites["example.test"]; got != site || site == nil {
		t.Fatal("failed reload replaced the previous site snapshot")
	}
	if _, err := p.Store.DB.Exec(`ALTER TABLE unavailable_ip_lists RENAME TO ip_lists`); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	if p.sites["example.test"] != nil {
		t.Fatal("reload did not apply the deletion after the database recovered")
	}
}

func TestSecuritySiteAuthOnAllForwardingPaths(t *testing.T) {
	requests := make(chan *http.Request, 6)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		w.Header().Add("Set-Cookie", "niub_admin=origin")
		w.Header().Add("Set-Cookie", "app=response")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	pass := store.HashPass("test-only-password")
	for _, path := range []string{"normal", "disabled", "whitelist", "custom-allow"} {
		t.Run(path, func(t *testing.T) {
			p := newSecurityTestProxy(t, store.Site{
				Name: "protected", Domain: "site.test", Upstream: upstream.URL, Enabled: path != "disabled",
				AuthUser: "site-user", AuthPass: pass,
			}, nil)
			switch path {
			case "whitelist":
				if err := p.Store.AddIP("white", "192.0.2.1", "", ""); err != nil {
					t.Fatal(err)
				}
			case "custom-allow":
				site := p.sites["site.test"]
				rule := store.CustomRule{
					Name: "allow path", SiteID: site.ID, Enabled: true, Logic: "and", Action: "allow",
					Conditions: `[{"field":"path","op":"eq","value":"/private"}]`,
				}
				if err := p.Store.CreateRule(&rule); err != nil {
					t.Fatal(err)
				}
			}
			p.Reload()

			unauthorized := httptest.NewRecorder()
			p.ServeHTTP(unauthorized, httptest.NewRequest("GET", "http://site.test/private", nil))
			if unauthorized.Code != http.StatusUnauthorized || len(requests) != 0 {
				t.Fatalf("缺少认证时上游不可达, status=%d", unauthorized.Code)
			}

			req := httptest.NewRequest("GET", "http://site.test/private", nil)
			req.SetBasicAuth("site-user", "test-only-password")
			req.Header.Set("Cookie", "niub_admin=private; app=request; niub_pass_bot=private")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent || len(requests) != 1 {
				t.Fatalf("合法认证请求未到达上游, status=%d", rec.Code)
			}
			got := <-requests
			if got.Header.Get("Authorization") != "" || got.Header.Get("Cookie") != "app=request" {
				t.Fatal("代理应保护 WAF 凭据并保留业务 Cookie")
			}
			if cookies := rec.Header().Values("Set-Cookie"); len(cookies) != 1 || cookies[0] != "app=response" {
				t.Fatalf("上游响应应仅设置业务 Cookie, got %v", cookies)
			}
		})
	}
}

func TestSecurityBodyLimitsBeforeForwarding(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	p := newSecurityTestProxy(t, store.Site{
		Name: "body", Domain: "site.test", Upstream: upstream.URL, Enabled: true,
	}, map[string]string{"semantic_mode": "off"})
	limit := p.Engine.ScanLimit()
	for _, tt := range []struct {
		name, method, encoding string
		size                   int
		chunked                bool
		want                   int
	}{
		{"known length", "POST", "", limit + 1, false, http.StatusRequestEntityTooLarge},
		{"unknown length", "POST", "", limit + 1, true, http.StatusRequestEntityTooLarge},
		{"encoded", "POST", "gzip", 8, false, http.StatusUnsupportedMediaType},
		{"CONNECT", "CONNECT", "", 0, false, http.StatusMethodNotAllowed},
		{"exact limit", "POST", "identity", limit, false, http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://site.test/form", strings.NewReader("v="+strings.Repeat("a", max(0, tt.size-2))))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.encoding != "" {
				req.Header.Set("Content-Encoding", tt.encoding)
			}
			if tt.chunked {
				req.ContentLength = -1
				req.TransferEncoding = []string{"chunked"}
			}
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("响应状态 = %d, want %d", rec.Code, tt.want)
			}
		})
	}
	if hits.Load() != 1 {
		t.Fatalf("预期只有合法请求到达上游, got %d", hits.Load())
	}
}

func TestSecurityUnknownHostsShareUnknownMetric(t *testing.T) {
	oldRegistry := metrics.Default
	registry := metrics.New()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = oldRegistry })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	p := &Proxy{sites: map[string]*cachedSite{
		"configured.test": {
			Site:    store.Site{Domain: "configured.test", Enabled: false},
			targets: []*upstreamTarget{{u: u}},
		},
	}}

	for i := 0; i < 20; i++ {
		host := fmt.Sprintf("random-%02d.invalid", i)
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("未知 Host 状态码 = %d, 期望 404", rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://configured.test/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("已配置站点状态码 = %d, 期望 200", rec.Code)
	}

	out := registry.Render()
	if !strings.Contains(out, `niubwaf_requests_total{result="blocked",site="unknown"} 20`) {
		t.Fatalf("20 个随机 Host 应聚合为一条 unknown 序列:\n%s", out)
	}
	if !strings.Contains(out, `niubwaf_requests_total{result="allowed",site="configured.test"} 1`) {
		t.Fatalf("已配置站点标签必须保持不变:\n%s", out)
	}
	var requestSeries int
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "niubwaf_requests_total{") {
			requestSeries++
		}
		if strings.Contains(line, "random-") {
			t.Fatalf("随机 Host 泄漏为指标标签: %s", line)
		}
	}
	if requestSeries != 2 {
		t.Fatalf("请求序列数 = %d, 期望 unknown 与 configured.test 共 2 条\n%s", requestSeries, out)
	}
}

func securityDisconnectServer(hits *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
}

func TestSecurityUnsafePostDoesNotRetryButGetFailsOver(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			var aHits, bHits atomic.Int32
			a := securityDisconnectServer(&aHits)
			defer a.Close()
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bHits.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = io.WriteString(w, "upstream-b")
			}))
			defer b.Close()

			site := mkSite(a.URL, b.URL)
			// cachedSite.pick 从 rr+1 开始；设为最大值可确定性选择 A。
			site.rr = ^uint64(0)
			site.Domain = "retry.test"
			var body io.Reader
			if method == http.MethodPost {
				body = bytes.NewBufferString("execute-once")
			}
			req := httptest.NewRequest(method, "http://retry.test/submit", body)
			rec := httptest.NewRecorder()
			p := &Proxy{}
			p.forward(rec, req, site, "192.0.2.10", "retry-req", false)

			switch method {
			case http.MethodPost:
				if rec.Code != http.StatusBadGateway {
					t.Fatalf("POST 断连后客户端状态码 = %d, 期望 502", rec.Code)
				}
				if aHits.Load() != 1 || bHits.Load() != 0 {
					t.Fatalf("POST 上游命中 A/B = %d/%d, 期望 1/0", aHits.Load(), bHits.Load())
				}
			case http.MethodGet:
				if rec.Code != http.StatusOK || rec.Body.String() != "upstream-b" {
					t.Fatalf("GET 未故障切换到 B: code=%d body=%q", rec.Code, rec.Body.String())
				}
				if aHits.Load() != 1 || bHits.Load() != 1 {
					t.Fatalf("GET 上游命中 A/B = %d/%d, 期望 1/1", aHits.Load(), bHits.Load())
				}
			}
		})
	}
}

func TestSecurityRetryMethodPolicy(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		if !isSafeRetryMethod(method) {
			t.Errorf("%s 应允许安全重试", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect} {
		if isSafeRetryMethod(method) {
			t.Errorf("%s 不应自动重试", method)
		}
	}
}

func TestClientCancellationKeepsUpstreamHealthy(t *testing.T) {
	started := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := &upstreamTarget{u: u}
	site := &cachedSite{targets: []*upstreamTarget{target}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/normal", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&Proxy{}).forward(httptest.NewRecorder(), req, site, "192.0.2.1", "cancel-test", false)
	}()
	select {
	case <-started:
		cancel()
	case <-ctx.Done():
		t.Fatal("request did not reach the upstream")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return after client cancellation")
	}
	if atomic.LoadInt64(&target.downUntil) != 0 {
		t.Fatal("cancelled client request marked a healthy upstream as down")
	}
}

func TestUpstreamPoolBackpressureLeavesOriginHealthy(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := &upstreamTarget{u: u, slots: make(chan struct{}, 1)}
	site := &cachedSite{targets: []*upstreamTarget{target}}
	p := &Proxy{upstreamTransport: newUpstreamTransport(1)}
	defer p.upstreamTransport.CloseIdleConnections()

	counter := func(report, name string) int {
		_, value, _ := strings.Cut("\n"+report, "\n"+name+" ")
		var count int
		fmt.Sscanf(value, "%d", &count)
		return count
	}
	rejectMetric := `niubwaf_overload_rejections_total{reason="origin_queue"}`
	waitMetric := "niubwaf_upstream_queue_duration_seconds_count"
	before := metrics.Default.Render()
	target.slots <- struct{}{}
	busy := httptest.NewRecorder()
	p.forward(busy, httptest.NewRequest("GET", "/normal", nil), site, "192.0.2.1", "busy", false)
	if busy.Code != http.StatusServiceUnavailable || busy.Header().Get("Retry-After") == "" {
		t.Fatalf("expected temporary overload response, got %d", busy.Code)
	}
	if hits.Load() != 0 || atomic.LoadInt64(&target.downUntil) != 0 {
		t.Fatal("local pool pressure should leave the origin untouched")
	}
	out := metrics.Default.Render()
	if counter(out, rejectMetric) != counter(before, rejectMetric)+1 ||
		counter(out, waitMetric) != counter(before, waitMetric)+1 ||
		!strings.Contains(out, "niubwaf_upstream_queue_requests 0\n") {
		t.Fatal("origin queue saturation was not reported")
	}

	<-target.slots
	ok := httptest.NewRecorder()
	p.forward(ok, httptest.NewRequest("GET", "/normal", nil), site, "192.0.2.1", "released", false)
	if ok.Code != http.StatusNoContent || hits.Load() != 1 || len(target.slots) != 0 {
		t.Fatalf("expected normal forwarding after capacity was released, got %d", ok.Code)
	}
}

func TestInterfaceRateLimitIsScopedAndKeepsCustomBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	p := newSecurityTestProxy(t, store.Site{
		Name: "app", Domain: "app.test", Upstream: upstream.URL, Enabled: true, CCRate: 1, CCBurst: 2,
	}, nil)
	loginConditions := `[{"field":"path","op":"eq","value":"/login"},{"field":"method","op":"eq","value":"GET"}]`
	rules := []store.CustomRule{
		{Name: "login quota", Enabled: true, Priority: 10, Logic: "and", Conditions: loginConditions, Action: engine.RuleActionRateLimit, ActionParam: "1,1"},
		{Name: "report quota", Enabled: true, Priority: 10, Logic: "and", Conditions: `[{"field":"path","op":"eq","value":"/report"}]`, Action: engine.RuleActionRateLimit, ActionParam: "1,2"},
		{Name: "preview quota", Enabled: true, Shadow: true, Priority: 1, Logic: "and", Conditions: `[{"field":"path","op":"eq","value":"/preview"}]`, Action: engine.RuleActionRateLimit, ActionParam: "1,1"},
		{Name: "deny restricted request", Enabled: true, Priority: 20, Logic: "and", Conditions: `[{"field":"path","op":"eq","value":"/login"},{"field":"header","name":"X-Access","op":"eq","value":"restricted"}]`, Action: "block"},
	}
	for i := range rules {
		if err := p.Store.CreateRule(&rules[i]); err != nil {
			t.Fatal(err)
		}
	}
	p.Reload()
	for _, tc := range []struct {
		method, path, ip, access string
		status                   int
	}{
		{http.MethodGet, "/login", "192.0.2.20", "restricted", http.StatusForbidden},
		{http.MethodGet, "/login", "192.0.2.20", "", http.StatusNoContent},
		{http.MethodGet, "/login", "192.0.2.20", "", http.StatusTooManyRequests},
		{http.MethodGet, "/login", "192.0.2.21", "", http.StatusNoContent},
		{http.MethodGet, "/report", "192.0.2.20", "", http.StatusNoContent},
		{http.MethodGet, "/report", "192.0.2.20", "", http.StatusNoContent},
		{http.MethodGet, "/report", "192.0.2.20", "", http.StatusTooManyRequests},
		{http.MethodHead, "/login", "192.0.2.20", "", http.StatusNoContent},
		{http.MethodGet, "/home", "192.0.2.20", "", http.StatusNoContent},
		{http.MethodGet, "/home", "192.0.2.20", "", http.StatusTooManyRequests},
		{http.MethodGet, "/preview", "192.0.2.22", "", http.StatusNoContent},
		{http.MethodGet, "/preview", "192.0.2.22", "", http.StatusNoContent},
	} {
		req := httptest.NewRequest(tc.method, "http://app.test"+tc.path, nil)
		req.RemoteAddr = tc.ip + ":12345"
		req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
		req.Header.Set("X-Access", tc.access)
		reply := httptest.NewRecorder()
		p.ServeHTTP(reply, req)
		if reply.Code != tc.status {
			t.Fatalf("%s %s from %s: got %d, want %d", tc.method, tc.path, tc.ip, reply.Code, tc.status)
		}
		if tc.status == http.StatusTooManyRequests && reply.Header().Get("Retry-After") != "1" {
			t.Fatal("rate limit response is missing Retry-After")
		}
	}
}

func TestUpstreamSlotsSharedAcrossSitesAndReload(t *testing.T) {
	p := newSecurityTestProxy(t, store.Site{
		Name: "first", Domain: "first.test", Upstream: "http://origin.test", Enabled: true,
	}, nil)
	slots := p.sites["first.test"].targets[0].slots
	if err := p.Store.CreateSite(&store.Site{
		Name: "second", Domain: "second.test", Upstream: "http://ORIGIN.test:80/nested", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	if cap(slots) != DefaultUpstreamConnections ||
		p.sites["first.test"].targets[0].slots != slots ||
		p.sites["second.test"].targets[0].slots != slots {
		t.Fatal("same origin must share its connection budget across sites and reloads")
	}
}

func TestSecurityRewriteRebuildsForwardingHeadersAfterConnectionStripping(t *testing.T) {
	type receivedRequest struct {
		header http.Header
		host   string
		path   string
		query  string
	}
	received := make(chan receivedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- receivedRequest{header: r.Header.Clone(), host: r.Host, path: r.URL.Path, query: r.URL.RawQuery}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "http://internal.invalid/original?x=1", nil)
	req.Host = "public.test:8443"
	req.TLS = &tls.ConnectionState{}
	for _, header := range []string{
		"Forwarded", "X-Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
		"X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server",
		"X-Forwarded-Ssl", "X-Original-Forwarded-For", "X-Real-IP", "X-NiuB-WAF-Req-ID",
	} {
		req.Header.Set(header, "attacker-controlled")
	}
	req.Header.Set("X-Normal-Header", "preserved")
	// 这些头即使被客户端列入 Connection，也必须在 Rewrite 中重新生成。
	req.Header.Set("Connection", "keep-alive, X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, X-Real-IP, X-NiuB-WAF-Req-ID")
	rec := httptest.NewRecorder()
	site := mkSite(upstream.URL)
	site.Domain = "public.test"
	(&Proxy{}).forward(rec, req, site, "203.0.113.9", "trusted-request-id", false)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("转发状态码 = %d, 期望 204: %s", rec.Code, rec.Body.String())
	}
	got := <-received
	if got.host != upstreamURL.Host || got.path != "/original" || got.query != "x=1" {
		t.Errorf("上游 URL/Host 行为改变: host=%q path=%q query=%q", got.host, got.path, got.query)
	}
	for header, want := range map[string]string{
		"X-Forwarded-For":   "203.0.113.9",
		"X-Real-IP":         "203.0.113.9",
		"X-Forwarded-Host":  "public.test:8443",
		"X-Forwarded-Proto": "https",
		"X-NiuB-WAF-Req-ID": "trusted-request-id",
		"X-Normal-Header":   "preserved",
	} {
		if value := got.header.Get(header); value != want {
			t.Errorf("%s = %q, 期望 %q", header, value, want)
		}
	}
	for _, header := range []string{
		"Forwarded", "X-Forwarded", "X-Forwarded-Port", "X-Forwarded-Server",
		"X-Forwarded-Ssl", "X-Original-Forwarded-For", "Connection",
	} {
		if value := got.header.Get(header); value != "" {
			t.Errorf("伪造/逐跳头 %s 不应透传, got %q", header, value)
		}
	}
}

func TestPublicServerHeaderDoesNotExposeUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "gunicorn-early")
		w.Header().Set("Link", "</main.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Server", "gunicorn")
		w.Header().Add("Server", "python")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "Server, X-Test-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin body")
		w.Header().Set("Server", "gunicorn-trailer")
		w.Header().Set("X-Test-Trailer", "preserved")
	}))
	defer upstream.Close()
	p := newSecurityTestProxy(t, store.Site{Domain: "site.test", Upstream: upstream.URL, Enabled: false}, nil)
	edge := httptest.NewServer(p)
	defer edge.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var early http.Header
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, headers textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints {
			early = http.Header(headers).Clone()
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, edge.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "site.test"
	resp, err := edge.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "origin body" {
		t.Fatalf("正文 = %q, %v", body, err)
	}
	for name, headers := range map[string]http.Header{"103": early, "200": resp.Header} {
		values := headers.Values("Server")
		if len(values) != 1 || values[0] != "NiuBWAF" {
			t.Errorf("%s Server = %v, 期望单个 NiuBWAF", name, values)
		}
	}
	if early.Get("Link") == "" || resp.Trailer.Get("Server") != "" || resp.Trailer.Get("X-Test-Trailer") != "preserved" {
		t.Fatalf("其他响应头或尾部字段未保留，或源站 Server 泄漏: 103 Link=%q, trailer=%v", early.Get("Link"), resp.Trailer)
	}

	local := httptest.NewRecorder()
	p.ServeHTTP(local, httptest.NewRequest(http.MethodGet, "http://unknown.test/", nil))
	if local.Code != http.StatusNotFound || local.Header().Get("Server") != "NiuBWAF" {
		t.Fatalf("WAF 本地响应 = %d, Server=%q", local.Code, local.Header().Get("Server"))
	}
}

func TestSecurityBodyDetectionIgnoresClientContentType(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "should-not-reach-origin")
	}))
	defer upstream.Close()
	p := newSecurityTestProxy(t, store.Site{
		Name: "body", Domain: "body.test", Upstream: upstream.URL, Enabled: true,
		WAFMode: "balanced", DynamicMode: "off",
	}, map[string]string{
		"allowed_content_types": "application/octet-stream",
		"semantic_mode":         "off",
	})
	if got := p.Engine.ScanLimit(); got != 16<<10 {
		t.Fatalf("body_scan_kb 默认限制改变: %d", got)
	}

	payload := `{"id":"1' OR '1'='1' -- "}`
	for _, contentType := range []string{"application/json", "application/octet-stream"} {
		t.Run(contentType, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://body.test/search", strings.NewReader(payload))
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("相同正文按 %s 检测的状态码 = %d, 期望 403; body=%s", contentType, rec.Code, rec.Body.String())
			}
		})
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("攻击正文不应到达上游, hits=%d", upstreamHits.Load())
	}
}

func TestSecurityReadTimeoutDoesNotTruncateSSE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: start\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, "data: after-timeout\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()
	p := newSecurityTestProxy(t, store.Site{
		Name: "sse", Domain: "sse.test", Upstream: upstream.URL, Enabled: false, DynamicMode: "off",
	}, nil)
	server := httptest.NewUnstartedServer(p)
	server.Config.ReadTimeout = 50 * time.Millisecond
	server.Start()
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	req.Host = "sse.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取期限不应截断 SSE 响应: %v", err)
	}
	if !strings.Contains(string(body), "after-timeout") {
		t.Fatalf("SSE 缺少超时后的后续帧: %q", body)
	}
}

func TestSecurityReadTimeoutClearedOnWebSocketHijack(t *testing.T) {
	const payload = "after-timeout"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nServer: gunicorn\r\n\r\n")
		_ = rw.Flush()
		time.Sleep(200 * time.Millisecond)
		_, _ = conn.Write([]byte(payload))
	}))
	defer upstream.Close()
	p := newSecurityTestProxy(t, store.Site{
		Name: "ws", Domain: "ws.test", Upstream: upstream.URL, Enabled: false, DynamicMode: "off",
	}, nil)
	server := httptest.NewUnstartedServer(p)
	server.Config.ReadTimeout = 50 * time.Millisecond
	server.Start()
	defer server.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("WebSocket 升级失败: status=%q err=%v", status, err)
	}
	headers, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		t.Fatal(err)
	}
	if values := http.Header(headers).Values("Server"); len(values) != 1 || values[0] != "NiuBWAF" {
		t.Fatalf("WebSocket Server = %v, 期望单个 NiuBWAF", values)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("劫持后读取期限未清除: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("WebSocket 后续数据 = %q, 期望 %q", got, payload)
	}
}
