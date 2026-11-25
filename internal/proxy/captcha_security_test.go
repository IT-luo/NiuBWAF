package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func captchaVerifyRequest(target, id, token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(url.Values{
		"challenge":             {id},
		"cf-turnstile-response": {token},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func captchaOnlyChallenge(t *testing.T, c *Captcha) (string, *challenge) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) != 1 {
		t.Fatalf("挑战数量 = %d, want 1", len(c.items))
	}
	for id, ch := range c.items {
		return id, ch
	}
	return "", nil
}

func TestCaptchaVerifyBodyLimitUnknownHost(t *testing.T) {
	c := NewCaptcha("body-limit-secret")
	p := &Proxy{Cap: c}
	body := "challenge=unknown&answer=1&padding=" + strings.Repeat("x", captchaMaxBody)
	req := httptest.NewRequest(http.MethodPost, "http://unknown.invalid/__niubwaf/captcha", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.10:1234"
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("未知 Host 的超限验证状态码 = %d, want 413", rec.Code)
	}
	c.mu.Lock()
	items := len(c.items)
	c.mu.Unlock()
	if items != 0 {
		t.Fatalf("超限请求不应注册挑战，当前数量 = %d", items)
	}
}

func TestCaptchaVerifyRejectsMalformedForm(t *testing.T) {
	c := NewCaptcha("malformed-form-secret")
	req := httptest.NewRequest(http.MethodPost, "http://unknown.invalid/__niubwaf/captcha", strings.NewReader("challenge=%zz&answer=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	c.Verify(rec, req, "192.0.2.10")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无效表单状态码 = %d, want 400", rec.Code)
	}
}

func TestCaptchaIssuePerIPLimitAndGC(t *testing.T) {
	c := configuredTestCaptcha("per-ip-limit-secret")
	const ip = "192.0.2.20"
	for i := 0; i < captchaMaxPerIP; i++ {
		c.Issue(httptest.NewRecorder(), ip, "site.test", 1, captchaBot, "/")
	}

	c.mu.Lock()
	items, count := len(c.items), c.ipCount[ip]
	c.mu.Unlock()
	if items != captchaMaxPerIP || count != captchaMaxPerIP {
		t.Fatalf("达到每 IP 上限后 items=%d count=%d, want %d", items, count, captchaMaxPerIP)
	}

	rejected := httptest.NewRecorder()
	c.Issue(rejected, ip, "site.test", 1, captchaBot, "/")
	if rejected.Code != http.StatusTooManyRequests || !strings.Contains(rejected.Body.String(), "挑战过多") {
		t.Fatalf("超过每 IP 上限应拒绝新挑战: code=%d body=%q", rejected.Code, rejected.Body.String())
	}
	c.mu.Lock()
	items = len(c.items)
	for _, ch := range c.items {
		ch.expires = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	if items != captchaMaxPerIP {
		t.Fatalf("拒绝后挑战表仍增长: %d", items)
	}

	// GC 间隔未满时不得因每个请求扫描并删除过期挑战。
	const otherIP = "192.0.2.21"
	c.Issue(httptest.NewRecorder(), otherIP, "site.test", 1, captchaBot, "/")
	c.mu.Lock()
	items, count = len(c.items), c.ipCount[ip]
	c.mu.Unlock()
	if items != captchaMaxPerIP+1 || count != captchaMaxPerIP {
		t.Fatalf("GC 间隔内不应扫描: items=%d oldIPCount=%d", items, count)
	}

	// 到期后的惰性 GC 应回收全部旧计数，再允许该 IP 获取新挑战。
	c.mu.Lock()
	c.lastGC = time.Now().Add(-captchaGCInterval - time.Millisecond)
	c.mu.Unlock()
	c.Issue(httptest.NewRecorder(), ip, "site.test", 1, captchaBot, "/")
	c.mu.Lock()
	items, count = len(c.items), c.ipCount[ip]
	otherCount := c.ipCount[otherIP]
	c.mu.Unlock()
	if items != 2 || count != 1 || otherCount != 1 {
		t.Fatalf("GC 后计数错误: items=%d oldIPCount=%d otherIPCount=%d", items, count, otherCount)
	}

	// 所有挑战过期后，空 IP 的计数项也必须删除，避免计数 map 长期增长。
	c.mu.Lock()
	for _, ch := range c.items {
		ch.expires = time.Now().Add(-time.Second)
	}
	c.lastGC = time.Now().Add(-captchaGCInterval - time.Millisecond)
	c.mu.Unlock()
	const thirdIP = "192.0.2.22"
	c.Issue(httptest.NewRecorder(), thirdIP, "site.test", 1, captchaBot, "/")
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) != 1 || len(c.ipCount) != 1 || c.ipCount[thirdIP] != 1 {
		t.Fatalf("GC 应清除空 IP 计数: items=%d ipCount=%v", len(c.items), c.ipCount)
	}
	if _, ok := c.ipCount[ip]; ok {
		t.Fatalf("已过期 IP %s 的计数未删除", ip)
	}
}

func TestCaptchaIssueGlobalLimit(t *testing.T) {
	c := configuredTestCaptcha("global-limit-secret")
	c.mu.Lock()
	for i := 0; i < captchaMaxChallenges; i++ {
		id := "bulk-" + strconv.Itoa(i)
		ip := "198.51.100." + strconv.Itoa(i/captchaMaxPerIP)
		c.items[id] = &challenge{ip: ip, expires: time.Now().Add(time.Minute)}
		c.ipCount[ip]++
	}
	c.mu.Unlock()

	const newIP = "203.0.113.9"
	rec := httptest.NewRecorder()
	c.Issue(rec, newIP, "site.test", 1, captchaBot, "/")

	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "挑战过多") {
		t.Fatalf("达到全局上限应拒绝新挑战: code=%d body=%q", rec.Code, rec.Body.String())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) != captchaMaxChallenges {
		t.Fatalf("全局上限后挑战数量 = %d, want %d", len(c.items), captchaMaxChallenges)
	}
	if _, ok := c.ipCount[newIP]; ok {
		t.Fatal("被拒绝的请求不应新增每 IP 计数")
	}
}

func TestCaptchaVerifyConsumesChallenge(t *testing.T) {
	c := configuredTestCaptcha("single-use-secret")
	const ip = "192.0.2.30"
	c.Issue(httptest.NewRecorder(), ip, "site.test", 7, captchaBot, "/private")
	id, _ := captchaOnlyChallenge(t, c)
	target := "http://site.test/__niubwaf/captcha"
	token := "verified-token"

	first := httptest.NewRecorder()
	c.Verify(first, captchaVerifyRequest(target, id, token), ip)
	if first.Code != http.StatusSeeOther {
		t.Fatalf("首次验证状态码 = %d, want 303", first.Code)
	}
	c.mu.Lock()
	items, count := len(c.items), c.ipCount[ip]
	_, countExists := c.ipCount[ip]
	c.mu.Unlock()
	if items != 0 || countExists {
		t.Fatalf("验证后挑战和计数应回收: items=%d ipCount=%d", items, count)
	}

	second := httptest.NewRecorder()
	c.Verify(second, captchaVerifyRequest(target, id, token), ip)
	if second.Code != http.StatusForbidden {
		t.Fatalf("重复验证状态码 = %d, want 403", second.Code)
	}
	if second.Header().Get("Set-Cookie") != "" {
		t.Fatal("重复验证不应再次下发通过 Cookie")
	}
}

func TestCaptchaCookieSecurityAttributes(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			c := configuredTestCaptcha("cookie-secret")
			const ip = "192.0.2.40"
			c.Issue(httptest.NewRecorder(), ip, "site.test", 7, captchaBot, "/")
			id, _ := captchaOnlyChallenge(t, c)
			rec := httptest.NewRecorder()
			req := captchaVerifyRequest(scheme+"://site.test/__niubwaf/captcha", id, "verified-token")

			c.Verify(rec, req, ip)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("验证状态码 = %d, want 303", rec.Code)
			}
			var pass *http.Cookie
			for _, ck := range rec.Result().Cookies() {
				if ck.Name == "niub_pass_"+captchaBot {
					pass = ck
					break
				}
			}
			if pass == nil {
				t.Fatal("未下发 niub_pass Cookie")
			}
			if !pass.HttpOnly {
				t.Error("niub_pass 必须保留 HttpOnly")
			}
			if pass.Secure != (scheme == "https") {
				t.Errorf("%s 请求 Secure=%v, want %v", scheme, pass.Secure, scheme == "https")
			}
			if pass.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite=%v, want Lax", pass.SameSite)
			}
			if pass.MaxAge != 1800 {
				t.Errorf("MaxAge=%d, want 1800", pass.MaxAge)
			}
			if pass.Path != "/" {
				t.Errorf("Path=%q, want /", pass.Path)
			}
		})
	}
}
