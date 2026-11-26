package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"niubwaf/internal/store"
)

func TestIngressVerificationUsesNormalProxyPath(t *testing.T) {
	var originCalls atomic.Int32
	var leaked atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		leaked.Store(leaked.Load() || r.Header.Get(ingressVerificationHeader) != "")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	p, st := newShadowTestProxy(t, origin.URL)
	site := addShadowTestSite(t, st, "site.test", origin.URL)
	addShadowTestSite(t, st, "other.test", origin.URL)
	p.Reload()

	started, err := p.StartIngressVerification(site.ID, site.Domain, IngressVerificationOptions{
		Scheme: "https", Port: 9020, Path: "/ready", Source: "external",
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.Status.EntryURL != "https://site.test:9020/ready" ||
		started.Header != ingressVerificationHeader ||
		started.PassToken == started.BlockToken {
		t.Fatal("验收 URL 或验证标记无效")
	}

	request := func(method, url, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, url, nil)
		if token != "" {
			r.Header.Set(ingressVerificationHeader, token)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		return w
	}
	for _, url := range []string{
		"https://other.test/ready", "https://site.test:9020/Ready", "https://site.test:9020/ready?mode=other",
		"https://site.test/ready", "https://site.test:443/ready", "http://site.test:9020/ready",
	} {
		if w := request(http.MethodGet, url, started.BlockToken); w.Code != http.StatusNoContent {
			t.Fatalf("无关请求被拦截 %s: %d", url, w.Code)
		}
	}
	if before := p.SiteIngressStatus(site.ID, site.Domain); before == nil || before.Block != nil || before.Pass != nil {
		t.Fatalf("无关请求消耗了验收标记: %+v", before)
	}
	beforeOrigin := originCalls.Load()
	w := request(http.MethodGet, started.Status.EntryURL, started.BlockToken)
	if w.Code != http.StatusForbidden || w.Header().Get("X-NiuB-WAF") != "blocked" || originCalls.Load() != beforeOrigin {
		t.Fatalf("验收拦截未在本节点完成: status=%d origin=%d", w.Code, originCalls.Load())
	}
	if w := request(http.MethodGet, started.Status.EntryURL, started.BlockToken); w.Code != http.StatusNoContent {
		t.Fatalf("一次性拦截标记可以重放: %d", w.Code)
	}
	if w := request(http.MethodGet, started.Status.EntryURL, started.PassToken); w.Code != http.StatusNoContent {
		t.Fatalf("正常验收请求未回源: %d", w.Code)
	}
	if leaked.Load() {
		t.Fatal("验收标记被发送给源站")
	}
	result := p.SiteIngressStatus(site.ID, site.Domain)
	if result == nil || !result.Verified || result.Pass == nil || result.Pass.OriginStatus != http.StatusNoContent ||
		result.Pass.Status != http.StatusNoContent || result.Pass.RequestID == "" || result.Pass.Scheme != "https" || result.Pass.Port != 9020 ||
		result.Block == nil || result.Block.Status != http.StatusForbidden || result.Block.OriginStatus != 0 {
		t.Fatalf("验收证据错误: %+v", result)
	}
	if p.SiteTrafficObservedAt(site.ID, site.Domain) != nil {
		t.Fatal("验收请求不应被当成普通站点流量")
	}
	request(http.MethodGet, started.Status.EntryURL, "")
	beforeReload := p.SiteTrafficObservedAt(site.ID, site.Domain)
	p.Reload()
	if after := p.SiteTrafficObservedAt(site.ID, site.Domain); beforeReload == nil || after == nil || !after.Equal(*beforeReload) {
		t.Fatalf("站点流量观测在配置重载时丢失: before=%v after=%v", beforeReload, after)
	}
	if len(p.Ana.Snapshot(24).AttackIPs) != 0 {
		t.Fatal("合成验收拦截不应计入攻击榜")
	}
}

func TestIngressVerificationPassStillEnforcesSiteRules(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()
	p, st := newShadowTestProxy(t, origin.URL)
	site := addShadowTestSite(t, st, "site.test", origin.URL)
	rule := &store.CustomRule{SiteID: site.ID, Name: "限制访问", Enabled: true, Priority: 10, Logic: "and",
		Conditions: `[{"field":"path","op":"eq","value":"/private"}]`, Action: "block"}
	if err := st.CreateRule(rule); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	started, err := p.StartIngressVerification(site.ID, site.Domain, IngressVerificationOptions{
		Scheme: "https", Path: "/private", Source: "external",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, started.Status.EntryURL, nil)
		r.Header.Set(ingressVerificationHeader, token)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		return w
	}
	if w := request(started.PassToken); w.Code != http.StatusForbidden || originCalls.Load() != 0 {
		t.Fatalf("正常验收标记改变了已配置的防护动作: status=%d", w.Code)
	}
	result := p.SiteIngressStatus(site.ID, site.Domain)
	if result == nil || result.Verified || result.Pass == nil ||
		result.Pass.Matched || result.Pass.Reason != "no_origin_response" {
		t.Fatalf("拦截误报为回源成功: %+v", result)
	}
	p.ingress.mu.Lock()
	p.ingress.sessions[site.ID].status.ExpiresAt = time.Now().Add(-time.Second)
	p.ingress.mu.Unlock()
	if w := request(started.BlockToken); !strings.Contains(w.Body.String(), "命中自定义规则") {
		t.Fatal("已过期的拦截标记仍然触发验收")
	}
	if result := p.SiteIngressStatus(site.ID, site.Domain); result.Block != nil || result.Verified {
		t.Fatalf("已过期的拦截标记仍然被记录: %+v", result)
	}
}

func TestIngressEntryURLRejectsNonliteralOrReservedPaths(t *testing.T) {
	for _, invalidPath := range []string{
		"//other.test/", "/x/../y", "/a%20b", "/q?a=b", "/q#fragment", "/__niubwaf/captcha",
	} {
		options := IngressVerificationOptions{Scheme: "https", Path: invalidPath, Source: "external"}
		if _, err := ingressEntryURL("site.test", &options); err == nil {
			t.Errorf("接受了不受支持的路径 %q", invalidPath)
		}
	}
}
