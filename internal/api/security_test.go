package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestCSRFAndOriginProtectJSONAPI(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ck, _ := loginCookie(t, h, "admin123")
	token := csrfToken(t, h, ck)
	a.Store.SetSetting("must_change_pass", "off")

	do := func(body, csrf, origin, contentType string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("PUT", "http://admin.example.test/api/settings", strings.NewReader(body))
		r.AddCookie(ck)
		if csrf != "" {
			r.Header.Set("X-NiuB-CSRF", csrf)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		h.ServeHTTP(rec, r)
		return rec
	}

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"缺少 token": do(`{}`, "", "", "application/json"),
		"错误 token": do(`{}`, "wrong", "", "application/json"),
		"同站跨源":     do(`{}`, token, "http://evil.example.test", "application/json"),
		"同源不同端口":   do(`{}`, token, "http://admin.example.test:8080", "application/json"),
		"跨协议":      do(`{}`, token, "https://admin.example.test", "application/json"),
	} {
		if rec.Code != 403 {
			t.Errorf("%s应返回 403, got %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := do(`{}`, token, "http://admin.example.test:80", "application/json; charset=utf-8"); rec.Code != 200 {
		t.Fatalf("显式默认端口的同源请求应放行, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(`{}`, token, "", "application/json"); rec.Code != 200 {
		t.Fatalf("无 Origin 的非浏览器客户端可凭正确 token 调用, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(`{}`, token, "", "text/plain"); rec.Code != 415 {
		t.Fatalf("text/plain JSON 端点请求应返回 415, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLogoutRequiresCSRF(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ck, _ := loginCookie(t, h, "admin123")
	token := csrfToken(t, h, ck)

	missing := httptest.NewRecorder()
	missingReq := httptest.NewRequest("POST", "/api/logout", nil)
	missingReq.AddCookie(ck)
	h.ServeHTTP(missing, missingReq)
	if missing.Code != 403 {
		t.Fatalf("logout 缺少 CSRF token 应返回 403, got %d", missing.Code)
	}
	// 被拒绝的 logout 不能撤销会话。
	if got := csrfToken(t, h, ck); got != token {
		t.Fatal("CSRF 校验失败的 logout 不应改变会话状态")
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/logout", nil)
	r.AddCookie(ck)
	r.Header.Set("X-NiuB-CSRF", token)
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("正确 CSRF token 的 logout 应成功, got %d %s", rec.Code, rec.Body.String())
	}
	if got := adminCookie(t, rec); got.MaxAge >= 0 || got.Value != "" {
		t.Fatalf("logout 应清除会话 Cookie, got %+v", got)
	}
	after := httptest.NewRecorder()
	afterReq := httptest.NewRequest("GET", "/api/csrf", nil)
	afterReq.AddCookie(ck)
	h.ServeHTTP(after, afterReq)
	if after.Code != 401 {
		t.Fatalf("logout 后旧会话应失效, got %d", after.Code)
	}
}

func TestJSONBodyLimits(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	loginBody := `{"password":"` + strings.Repeat("x", int(loginBodyLimit)) + `"}`
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, testJSONRequest("POST", "/api/login", loginBody))
	if loginRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("登录正文超过 64KiB 应返回 413, got %d %s", loginRec.Code, loginRec.Body.String())
	}

	ck, _ := loginCookie(t, h, "admin123")
	token := csrfToken(t, h, ck)
	a.Store.SetSetting("must_change_pass", "off")
	settingsBody := `{"block_page":"` + strings.Repeat("x", int(jsonBodyLimit)) + `"}`
	settingsRec := httptest.NewRecorder()
	settingsReq := testJSONRequest("PUT", "/api/settings", settingsBody)
	settingsReq.AddCookie(ck)
	settingsReq.Header.Set("X-NiuB-CSRF", token)
	h.ServeHTTP(settingsRec, settingsReq)
	if settingsRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("普通 JSON 正文超过 2MiB 应返回 413, got %d %s", settingsRec.Code, settingsRec.Body.String())
	}
}

func TestLoginOriginCheckedWithoutCSRF(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	cross := httptest.NewRecorder()
	crossReq := testJSONRequest("POST", "http://admin.example.test/api/login", `{"password":"admin123"}`)
	crossReq.Header.Set("Origin", "http://evil.example.test")
	h.ServeHTTP(cross, crossReq)
	if cross.Code != 403 {
		t.Fatalf("登录虽免 CSRF token，但应拒绝同站跨源 Origin, got %d", cross.Code)
	}

	rec := httptest.NewRecorder()
	r := testJSONRequest("POST", "http://admin.example.test/api/login", `{"password":"admin123"}`)
	r.Header.Set("Origin", "http://admin.example.test")
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("同源登录不应要求 CSRF token, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestConcurrentLoginLockAndAudit(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	auditCount := func() int {
		var n int
		if err := a.Store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action IN ('登录失败','登录锁定')`).Scan(&n); err != nil {
			t.Fatalf("查询登录审计失败: %v", err)
		}
		return n
	}
	initialAudits := auditCount()
	const attempts = 12
	start := make(chan struct{})
	codes := make(chan int, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			r := testJSONRequest("POST", "/api/login", `{"password":"wrong"}`)
			r.RemoteAddr = "203.0.113.77:10000"
			h.ServeHTTP(rec, r)
			codes <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	close(codes)

	unauthorized, throttled := 0, 0
	for code := range codes {
		switch code {
		case http.StatusUnauthorized:
			unauthorized++
		case http.StatusTooManyRequests:
			throttled++
		default:
			t.Fatalf("并发错误登录出现意外状态码 %d", code)
		}
	}
	if unauthorized != loginMaxFails || throttled != attempts-loginMaxFails {
		t.Fatalf("12 路并发只能有 5 次真实校验，其余应 429: 401=%d 429=%d", unauthorized, throttled)
	}
	if !a.loginLocked("203.0.113.77") {
		t.Fatal("第五次真实失败后应进入锁定状态")
	}
	before := auditCount()
	if before-initialAudits != loginMaxFails {
		t.Fatalf("每次真实失败只应写一条必要审计，429 不应写入: got %d", before-initialAudits)
	}
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		r := testJSONRequest("POST", "/api/login", `{"password":"wrong"}`)
		r.RemoteAddr = "203.0.113.77:10000"
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("锁定期请求应返回 429, got %d", rec.Code)
		}
	}
	if after := auditCount(); after != before {
		t.Fatalf("重复 429 不应永久追加审计: before=%d after=%d", before, after)
	}
}
