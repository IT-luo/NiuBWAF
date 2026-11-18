package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionCookieFlags(t *testing.T) {
	a := &API{AdminTLS: true}
	ck := a.sessionCookie("tok", 43200)
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("TLS 下 Cookie 应 HttpOnly+Secure+SameSiteStrict, got %+v", ck)
	}
	a.AdminTLS = false
	ck = a.sessionCookie("tok", 43200)
	if ck.Secure {
		t.Fatal("HTTP 下不应置 Secure（否则浏览器拒绝下发）")
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatal("HttpOnly/SameSite 应始终启用")
	}
}

func TestLoginThrottle(t *testing.T) {
	a := &API{fails: map[string]*loginFail{}}
	key := "203.0.113.1"
	for i := 0; i < loginMaxFails-1; i++ {
		a.loginFailed(key)
		if a.loginLocked(key) {
			t.Fatalf("第 %d 次失败不应锁定", i+1)
		}
	}
	a.loginFailed(key)
	if !a.loginLocked(key) {
		t.Fatal("达到阈值应锁定")
	}
	a.loginSucceeded(key)
	if a.loginLocked(key) {
		t.Fatal("成功登录后应清除锁定")
	}
}

func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	rec := httptest.NewRecorder()
	securityHeaders(inner, true).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("缺少 nosniff/DENY 安全头")
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("TLS 下应下发 HSTS")
	}
	rec2 := httptest.NewRecorder()
	securityHeaders(inner, false).ServeHTTP(rec2, httptest.NewRequest("GET", "/", nil))
	if rec2.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("非 TLS 不应下发 HSTS")
	}
}

func TestRemoteKey(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "198.51.100.7:54321"
	if got := remoteKey(r); got != "198.51.100.7" {
		t.Fatalf("应去除端口, got %s", got)
	}
	r.RemoteAddr = "[2001:db8::1]:443"
	if got := remoteKey(r); got != "2001:db8::1" {
		t.Fatalf("IPv6 应去括号与端口, got %s", got)
	}
}
