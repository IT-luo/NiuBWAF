package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPurgeExpiredSessions(t *testing.T) {
	a := hardenAPI(t)
	now := time.Now()
	a.mu.Lock()
	a.sessions["expired1"] = now.Add(-2 * time.Hour)
	a.sessions["expired2"] = now.Add(-time.Second)
	a.sessions["valid"] = now.Add(time.Hour)
	a.mu.Unlock()

	a.PurgeExpiredSessions()

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.sessions["expired1"]; ok {
		t.Fatal("过期会话 expired1 应被清除")
	}
	if _, ok := a.sessions["expired2"]; ok {
		t.Fatal("过期会话 expired2 应被清除")
	}
	if _, ok := a.sessions["valid"]; !ok {
		t.Fatal("未过期会话 valid 不应被清除")
	}
	if len(a.sessions) != 1 {
		t.Fatalf("应仅剩 1 个有效会话, got %d", len(a.sessions))
	}
}

func TestAuthedLazyDeletesExpired(t *testing.T) {
	a := hardenAPI(t)
	a.mu.Lock()
	a.sessions["stale"] = time.Now().Add(-time.Hour)
	a.mu.Unlock()

	req := httptest.NewRequest("GET", "/api/sites", nil)
	req.AddCookie(&http.Cookie{Name: "niub_admin", Value: "stale"})

	if a.authed(req) {
		t.Fatal("过期会话不应通过鉴权")
	}
	a.mu.Lock()
	_, still := a.sessions["stale"]
	a.mu.Unlock()
	if still {
		t.Fatal("authed 应惰性删除已过期会话")
	}
}

func TestLoginSweepBoundsSessionMap(t *testing.T) {
	a := hardenAPI(t)
	// 预置大量过期会话，模拟长期运行后的陈旧累积
	a.mu.Lock()
	for i := 0; i < 50; i++ {
		a.sessions["old"+string(rune('a'+i%26))+string(rune('0'+i/26))] = time.Now().Add(-13 * time.Hour)
	}
	a.mu.Unlock()

	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	// 一次成功登录应顺带清扫全部过期会话
	loginCookie(t, h, "admin123")

	a.mu.Lock()
	n := len(a.sessions)
	a.mu.Unlock()
	if n != 1 {
		t.Fatalf("登录后应仅保留本次新会话, got %d", n)
	}
}
