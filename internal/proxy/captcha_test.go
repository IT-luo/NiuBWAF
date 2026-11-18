package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestJSChallengeFlow(t *testing.T) {
	c := NewCaptcha("test-secret")
	w := httptest.NewRecorder()
	c.Issue(w, "1.2.3.4", 7, "/orig?q=1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("挑战页状态码 = %d,  want 429", w.Code)
	}
	page := w.Body.String()
	if !strings.Contains(page, "<script>") || strings.Contains(page, "Math.imul") {
		t.Fatal("挑战页应包含混淆脚本且不含明文算法")
	}

	c.mu.Lock()
	var id string
	var ch *challenge
	for k, v := range c.items {
		id, ch = k, v
	}
	c.mu.Unlock()
	if ch == nil {
		t.Fatal("挑战未注册")
	}

	// 错误答案 → 403
	bad := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/__niubwaf/captcha", strings.NewReader(url.Values{"challenge": {id}, "answer": {"0"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Verify(bad, req, "1.2.3.4")
	if bad.Code != http.StatusForbidden {
		t.Fatalf("错误答案状态码 = %d, want 403", bad.Code)
	}

	// 正确答案（模拟浏览器 JS 计算结果）→ 302 + cookie
	c.mu.Lock()
	c.items[id] = ch
	c.mu.Unlock()
	good := httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/__niubwaf/captcha", strings.NewReader(url.Values{"challenge": {id}, "answer": {strconv.FormatUint(uint64(ch.answer), 10)}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Verify(good, req, "1.2.3.4")
	if good.Code != http.StatusFound {
		t.Fatalf("正确答案状态码 = %d, want 302", good.Code)
	}
	if loc := good.Header().Get("Location"); loc != "/orig?q=1" {
		t.Fatalf("跳转地址 = %q, want /orig?q=1", loc)
	}
	ck := good.Result().Cookies()
	var pass *http.Cookie
	for _, k := range ck {
		if k.Name == "niub_pass" {
			pass = k
		}
	}
	if pass == nil {
		t.Fatal("未下发 niub_pass cookie")
	}
	r2 := httptest.NewRequest("GET", "/orig", nil)
	r2.AddCookie(pass)
	if !c.ValidCookie(r2, "1.2.3.4", 7) {
		t.Fatal("合法 cookie 校验失败")
	}
	if c.ValidCookie(r2, "1.2.3.5", 7) {
		t.Fatal("cookie 不应跨 IP 生效")
	}
	if c.ValidCookie(r2, "1.2.3.4", 8) {
		t.Fatal("cookie 不应跨站点生效")
	}
}