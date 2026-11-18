package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"niubwaf/internal/store"
)

func acmeTestProxy(t *testing.T) *Proxy {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "acme.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &Proxy{Store: st}
}

func TestACMEDisabledByDefault(t *testing.T) {
	p := acmeTestProxy(t)
	p.InitACME(t.TempDir())
	if p.ACMEEnabled() || p.acme != nil {
		t.Fatal("默认未启用 ACME，管理器应为 nil")
	}
}

func TestACMEEnabledBuildsManager(t *testing.T) {
	p := acmeTestProxy(t)
	p.Store.SetSetting("acme_enabled", "on")
	p.Store.SetSetting("acme_domains", "a.example.com, b.example.com")
	p.Store.SetSetting("acme_staging", "on")
	p.Store.SetSetting("acme_email", "admin@example.com")
	p.InitACME(t.TempDir())
	if !p.ACMEEnabled() || p.acme == nil {
		t.Fatal("启用且配置域名后应构建管理器")
	}
	if p.acme.Client.DirectoryURL != stagingDirectory {
		t.Errorf("staging=on 应使用测试 CA, got %s", p.acme.Client.DirectoryURL)
	}
	if p.acme.Email != "admin@example.com" {
		t.Errorf("Email 未设置: %s", p.acme.Email)
	}
	if err := p.acme.HostPolicy(context.Background(), "a.example.com"); err != nil {
		t.Errorf("白名单域名应放行: %v", err)
	}
	if err := p.acme.HostPolicy(context.Background(), "evil.com"); err == nil {
		t.Error("非白名单域名应被 HostPolicy 拒绝")
	}
}

func TestACMEProdDirectory(t *testing.T) {
	p := acmeTestProxy(t)
	p.Store.SetSetting("acme_enabled", "on")
	p.Store.SetSetting("acme_domains", "a.example.com")
	p.Store.SetSetting("acme_staging", "off")
	p.InitACME(t.TempDir())
	if p.acme == nil || p.acme.Client.DirectoryURL == stagingDirectory {
		t.Fatalf("staging=off 应使用生产 CA, got %v", p.acme.Client.DirectoryURL)
	}
}

func TestACMESigCacheNoRebuild(t *testing.T) {
	p := acmeTestProxy(t)
	p.Store.SetSetting("acme_enabled", "on")
	p.Store.SetSetting("acme_domains", "a.example.com")
	p.InitACME(t.TempDir())
	first := p.acme
	p.refreshACME()
	if p.acme != first {
		t.Error("配置未变化时不应重建管理器（避免丢失签发状态）")
	}
	p.Store.SetSetting("acme_domains", "b.example.com")
	p.refreshACME()
	if p.acme == first {
		t.Error("域名变化后应重建管理器")
	}
}

func TestACMEDisableClearsManager(t *testing.T) {
	p := acmeTestProxy(t)
	p.Store.SetSetting("acme_enabled", "on")
	p.Store.SetSetting("acme_domains", "a.example.com")
	p.InitACME(t.TempDir())
	if !p.ACMEEnabled() {
		t.Fatal("应先启用")
	}
	p.Store.SetSetting("acme_enabled", "off")
	p.refreshACME()
	if p.ACMEEnabled() || p.acme != nil {
		t.Error("关闭后应清除管理器")
	}
}

func TestACMEEnabledNoDomains(t *testing.T) {
	p := acmeTestProxy(t)
	p.Store.SetSetting("acme_enabled", "on")
	p.InitACME(t.TempDir())
	if p.ACMEEnabled() {
		t.Error("启用但无域名时不应构建管理器")
	}
}

func TestTLSConfigSiteCertPriority(t *testing.T) {
	p := acmeTestProxy(t)
	p.Store.SetSetting("acme_enabled", "on")
	p.Store.SetSetting("acme_domains", "a.example.com")
	p.InitACME(t.TempDir())
	siteCert := &tls.Certificate{}
	p.certs = map[string]*tls.Certificate{"a.example.com": siteCert}
	// 已配置站点证书优先，绝不触发 ACME 网络签发
	got, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil || got != siteCert {
		t.Fatalf("应优先返回站点证书: got=%v err=%v", got, err)
	}
}

func TestTLSConfigNonWhitelistedNoFallback(t *testing.T) {
	p := acmeTestProxy(t)
	p.Store.SetSetting("acme_enabled", "on")
	p.Store.SetSetting("acme_domains", "a.example.com")
	p.InitACME(t.TempDir())
	// 非白名单且无默认证书：HostPolicy 立即拒绝，不发起网络请求
	_, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "evil.com"})
	if err == nil {
		t.Fatal("非白名单域名且无默认证书时应返回错误")
	}
}

func TestACMEHandlerDelegatesWhenDisabled(t *testing.T) {
	p := acmeTestProxy(t)
	p.InitACME(t.TempDir())
	called := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) })
	rec := httptest.NewRecorder()
	p.ACMEHandler(fallback).ServeHTTP(rec, httptest.NewRequest("GET", "/normal", nil))
	if !called {
		t.Error("ACME 关闭时普通请求应交给 fallback")
	}
	rec2 := httptest.NewRecorder()
	p.ACMEHandler(nil).ServeHTTP(rec2, httptest.NewRequest("GET", "/x", nil))
	if rec2.Code != http.StatusNotFound {
		t.Errorf("无 fallback 应 404, got %d", rec2.Code)
	}
}