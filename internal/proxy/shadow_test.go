package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/metrics"
	"niubwaf/internal/store"
)

func newShadowTestProxy(t *testing.T, upstream string) (*Proxy, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SetSetting("semantic_mode", "off"); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New()
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{
		Store: st, Engine: eng, Geo: &GeoIP{}, Limiter: NewLimiter(),
		Cap: NewCaptcha("shadow-test-secret"), Hub: NewHub(), Ana: NewAnalytics(st, &GeoIP{}),
		dynSecret: []byte("shadow-test-secret"),
	}
	return p, st
}

func addShadowTestSite(t *testing.T, st *store.Store, domain, upstream string) *store.Site {
	t.Helper()
	site := &store.Site{Name: domain, Domain: domain, Upstream: upstream, Enabled: true, WAFMode: "balanced", DynamicMode: "off", BotMode: "off"}
	if err := st.CreateSite(site); err != nil {
		t.Fatal(err)
	}
	return site
}

func shadowTestRule(action string) *store.CustomRule {
	r := &store.CustomRule{
		SiteID: 0, Name: "shadow-" + action, Enabled: true, Priority: 100, Logic: "and",
		Conditions: `[{"field":"path","op":"eq","value":"/hit"}]`, Action: action, Shadow: true,
	}
	if action == "redirect" {
		r.ActionParam = "/must-not-follow"
	}
	return r
}

func serveShadowTestRequest(p *Proxy, host, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.RemoteAddr = "192.0.2.20:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

func TestShadowActionsOnlyCountWithoutSideEffects(t *testing.T) {
	oldRegistry := metrics.Default
	registry := metrics.New()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = oldRegistry })

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("origin-ok"))
	}))
	defer upstream.Close()
	p, st := newShadowTestProxy(t, upstream.URL)
	addShadowTestSite(t, st, "shadow.test", upstream.URL)
	for _, action := range []string{"allow", "block", "captcha", "redirect", "log"} {
		if err := st.CreateRule(shadowTestRule(action)); err != nil {
			t.Fatal(err)
		}
	}
	p.Reload()
	p.mu.RLock()
	if len(p.sites["shadow.test"].rules) != 0 || len(p.sites["shadow.test"].shadowRules) != 5 {
		t.Fatalf("影子与真实规则未独立缓存: %+v", p.sites["shadow.test"])
	}
	p.mu.RUnlock()
	events := p.Hub.Subscribe()
	defer p.Hub.Unsubscribe(events)

	rec := serveShadowTestRequest(p, "shadow.test", "/hit")
	if rec.Code != http.StatusOK || rec.Body.String() != "origin-ok" || upstreamHits.Load() != 1 {
		t.Fatalf("五种影子动作均不得改变真实流程: status=%d body=%q upstream=%d location=%q",
			rec.Code, rec.Body.String(), upstreamHits.Load(), rec.Header().Get("Location"))
	}
	snapshot := p.ShadowSnapshot()
	if len(snapshot) != 5 {
		t.Fatalf("应有 5 条影子统计, got %+v", snapshot)
	}
	for _, stat := range snapshot {
		if stat.Evaluated != 1 || stat.Matched != 1 || stat.LastHit == "" || stat.Since == "" || !stat.Shadow {
			t.Errorf("影子统计错误: %+v", stat)
		}
		if stat.SiteID == 0 || stat.RuleSiteID != 0 || stat.Domain != "shadow.test" {
			t.Errorf("统计必须归属实际站点: %+v", stat)
		}
	}
	select {
	case msg := <-events:
		t.Fatalf("影子命中不得广播大屏攻击事件: %s", msg)
	default:
	}
	if got := p.Ana.Snapshot(1).AttackIPs; len(got) != 0 {
		t.Fatalf("影子命中不得进入安全分析: %+v", got)
	}
	if rendered := registry.Render(); strings.Contains(rendered, "niubwaf_attacks_total{") {
		t.Fatalf("影子命中不得增加攻击指标:\n%s", rendered)
	}
	// LogAttack 是异步队列，等待一次 flush 后确认没有攻击日志落盘。
	time.Sleep(1200 * time.Millisecond)
	if _, total, err := st.QueryLogs("", "", "", 10, 0); err != nil || total != 0 {
		t.Fatalf("影子命中不得写攻击日志: total=%d err=%v", total, err)
	}
}

func TestShadowAllowDoesNotBypassRealRule(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("origin-ok"))
	}))
	defer upstream.Close()
	p, st := newShadowTestProxy(t, upstream.URL)
	addShadowTestSite(t, st, "shadow.test", upstream.URL)
	allow := shadowTestRule("allow")
	allow.Priority = 1
	if err := st.CreateRule(allow); err != nil {
		t.Fatal(err)
	}
	realBlock := shadowTestRule("block")
	realBlock.Name = "real-block"
	realBlock.Shadow = false
	realBlock.Priority = 100
	if err := st.CreateRule(realBlock); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	if rec := serveShadowTestRequest(p, "shadow.test", "/hit"); rec.Code != http.StatusForbidden {
		t.Fatalf("影子 allow 不得绕过真实 block, got %d", rec.Code)
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("真实 block 仍应阻止请求到达上游")
	}
	snapshot := p.ShadowSnapshot()
	if len(snapshot) != 1 || snapshot[0].Evaluated != 1 || snapshot[0].Matched != 1 {
		t.Fatalf("真实规则执行前应先完成影子统计: %+v", snapshot)
	}
}

func TestShadowReloadPreservesOnlyUnchangedStats(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	p, st := newShadowTestProxy(t, upstream.URL)
	addShadowTestSite(t, st, "a.test", upstream.URL)
	addShadowTestSite(t, st, "b.test", upstream.URL)
	rule := shadowTestRule("log")
	rule.Conditions = `[{"field":"path","op":"prefix","value":"/"}]`
	if err := st.CreateRule(rule); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	if rec := serveShadowTestRequest(p, "a.test", "/"); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	p.mu.RLock()
	oldStats := p.sites["a.test"].shadowRules[0].stats
	p.mu.RUnlock()
	assertCounts := func(wantA, wantB uint64) {
		t.Helper()
		snapshot := p.ShadowSnapshot()
		if len(snapshot) != 2 {
			t.Fatalf("全局影子规则应逐实际站点展示: %+v", snapshot)
		}
		for _, stat := range snapshot {
			switch stat.Domain {
			case "a.test":
				if stat.Evaluated != wantA || stat.Matched != wantA {
					t.Fatalf("A 站统计 = %+v, 期望 %d", stat, wantA)
				}
			case "b.test":
				if stat.Evaluated != wantB || stat.Matched != wantB {
					t.Fatalf("B 站统计 = %+v, 期望 %d", stat, wantB)
				}
			}
		}
	}
	assertCounts(1, 0)

	p.Reload()
	assertCounts(1, 0)
	p.mu.RLock()
	unchanged := oldStats == p.sites["a.test"].shadowRules[0].stats
	p.mu.RUnlock()
	if !unchanged {
		t.Fatal("定义未变的 Reload 必须复用原统计")
	}

	rule.Name = "revised"
	if err := st.UpdateRule(rule); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	assertCounts(0, 0)
	p.mu.RLock()
	revised := oldStats != p.sites["a.test"].shadowRules[0].stats
	p.mu.RUnlock()
	if !revised {
		t.Fatal("规则修订后必须重置统计")
	}

	rule.Shadow = false
	if err := st.UpdateRule(rule); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	if got := p.ShadowSnapshot(); len(got) != 0 {
		t.Fatalf("退出影子后不应继续展示: %+v", got)
	}
	p.mu.RLock()
	realRules := len(p.sites["a.test"].rules)
	p.mu.RUnlock()
	if realRules != 1 {
		t.Fatal("退出影子后应回到真实规则缓存")
	}

	rule.Shadow = true
	if err := st.UpdateRule(rule); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	assertCounts(0, 0)
	if err := st.DeleteRule(rule.ID); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	if got := p.ShadowSnapshot(); len(got) != 0 {
		t.Fatalf("删除后不应保留统计: %+v", got)
	}
}
