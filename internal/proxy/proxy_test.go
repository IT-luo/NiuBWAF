package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func mkSite(urls ...string) *cachedSite {
	s := &cachedSite{}
	for _, raw := range urls {
		u, _ := url.Parse(raw)
		s.targets = append(s.targets, &upstreamTarget{u: u})
	}
	return s
}

func TestProbeUpstreamUserAgent(t *testing.T) {
	ua := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua <- r.UserAgent()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	if err := probeUpstream(upstream.Client(), upstream.URL); err != nil {
		t.Fatal(err)
	}
	if got := <-ua; got != healthCheckUserAgent {
		t.Fatalf("健康检查 UA = %q, 期望 %q", got, healthCheckUserAgent)
	}
}

func TestCheckUpstreamsOnlyProbesEnabledTargetsWithoutRedirects(t *testing.T) {
	var disabledHits, enabledHits atomic.Int64
	disabled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disabledHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer disabled.Close()
	enabled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enabledHits.Add(1)
		http.Redirect(w, r, disabled.URL+"/health", http.StatusTemporaryRedirect)
	}))
	defer enabled.Close()
	enabledSite := mkSite(enabled.URL)
	enabledSite.Domain, enabledSite.Enabled = "enabled.example", true
	disabledSite := mkSite(disabled.URL)
	disabledSite.Domain = "disabled.example"
	proxy := &Proxy{sites: map[string]*cachedSite{enabledSite.Domain: enabledSite, disabledSite.Domain: disabledSite}}
	results := proxy.checkUpstreams()
	if len(results) != 1 || results[0].Site != enabledSite.Domain || !results[0].Up {
		t.Fatalf("应仅报告启用站点，且 HTTP 重定向视为源站可达: %+v", results)
	}
	if enabledHits.Load() != 1 || disabledHits.Load() != 0 {
		t.Fatalf("探测请求次数不匹配，启用站点 %d，停用站点 %d", enabledHits.Load(), disabledHits.Load())
	}
}

func TestPickRoundRobin(t *testing.T) {
	s := mkSite("http://a:80", "http://b:80", "http://c:80")
	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		seen[s.pick().u.Host]++
	}
	for _, h := range []string{"a:80", "b:80", "c:80"} {
		if seen[h] != 3 {
			t.Fatalf("轮询不均: %v", seen)
		}
	}
}

func TestPickSkipsDown(t *testing.T) {
	s := mkSite("http://a:80", "http://b:80")
	atomic.StoreInt64(&s.targets[0].downUntil, time.Now().Unix()+60)
	for i := 0; i < 5; i++ {
		if got := s.pick().u.Host; got != "b:80" {
			t.Fatalf("应跳过故障上游, got %s", got)
		}
	}
	// 全部故障时仍返回一个尝试
	atomic.StoreInt64(&s.targets[1].downUntil, time.Now().Unix()+60)
	if s.pick() == nil {
		t.Fatal("全故障时不应返回 nil")
	}
	// 过期摘除自动恢复
	atomic.StoreInt64(&s.targets[0].downUntil, time.Now().Unix()-1)
	found := false
	for i := 0; i < 4; i++ {
		if s.pick().u.Host == "a:80" {
			found = true
		}
	}
	if !found {
		t.Fatal("摘除过期后应恢复选择")
	}
}
