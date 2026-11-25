package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func configuredTestCaptcha(secret string) *Captcha {
	c := NewCaptcha(secret)
	c.siteKey = "test-site-key"
	c.verify = func(_ context.Context, token, _ string, _ *challenge) bool {
		return token == "verified-token"
	}
	return c
}

type captchaTestTransport func(*http.Request) (*http.Response, error)

func (f captchaTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestTurnstileValidationBindsServiceResponse(t *testing.T) {
	for _, tt := range []struct {
		name, result string
		want         bool
	}{
		{"verified", `{"success":true,"hostname":"site.test","action":"niubwaf","cdata":"challenge-id"}`, true},
		{"wrong hostname", `{"success":true,"hostname":"other.test","action":"niubwaf","cdata":"challenge-id"}`, false},
		{"wrong action", `{"success":true,"hostname":"site.test","action":"other","cdata":"challenge-id"}`, false},
		{"wrong challenge", `{"success":true,"hostname":"site.test","action":"niubwaf","cdata":"old-id"}`, false},
		{"service rejection", `{"success":false}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: captchaTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.Host != "challenges.cloudflare.com" {
					t.Fatalf("预期发送至固定验证端点, got %s %s", r.Method, r.URL.Host)
				}
				if err := r.ParseForm(); err != nil || r.PostForm.Get("response") != "fixture" {
					t.Fatal("服务端验证请求缺少令牌")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.result))}, nil
			})}
			verify := turnstileVerifier(client, "test-secret")
			if got := verify(context.Background(), "fixture", "challenge-id", &challenge{host: "site.test"}); got != tt.want {
				t.Fatalf("验证结果 = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCaptchaFlow(t *testing.T) {
	const host, ip = "site.test", "192.0.2.15"
	const endpoint = "https://" + host + "/__niubwaf/captcha"
	c := configuredTestCaptcha("test-secret")

	issue := func() string {
		rec := httptest.NewRecorder()
		c.Issue(rec, ip, host, 7, captchaBot, "/orig?q=1")
		if rec.Code != http.StatusTooManyRequests ||
			!strings.Contains(rec.Body.String(), "challenges.cloudflare.com/turnstile/") {
			t.Fatalf("期望 Turnstile 验证页, got %d", rec.Code)
		}
		id, _ := captchaOnlyChallenge(t, c)
		return id
	}

	bad := httptest.NewRecorder()
	c.Verify(bad, captchaVerifyRequest(endpoint, issue(), "rejected-token"), ip)
	if bad.Code != http.StatusForbidden || bad.Header().Get("Set-Cookie") != "" {
		t.Fatalf("验证失败时仍接受请求, got %d", bad.Code)
	}

	id := issue()
	wrongHost := httptest.NewRecorder()
	c.Verify(wrongHost, captchaVerifyRequest("https://other.test/__niubwaf/captcha", id, "verified-token"), ip)
	if wrongHost.Code != http.StatusForbidden {
		t.Fatal("挑战必须绑定域名")
	}
	good := httptest.NewRecorder()
	c.Verify(good, captchaVerifyRequest(endpoint, id, "verified-token"), ip)
	if good.Code != http.StatusSeeOther || good.Header().Get("Location") != "/orig?q=1" {
		t.Fatalf("验证成功后应跳回原路径, got %d", good.Code)
	}
	r := httptest.NewRequest("GET", "https://"+host+"/orig", nil)
	for _, cookie := range good.Result().Cookies() {
		r.AddCookie(cookie)
	}
	if !c.ValidCookie(r, ip, 7, captchaBot) {
		t.Fatal("合法 Cookie 校验失败")
	}
	if c.ValidCookie(r, ip, 7, captchaRate) || c.ValidCookie(r, ip, 8, captchaBot) ||
		c.ValidCookie(r, "192.0.2.16", 7, captchaBot) {
		t.Fatal("Cookie 必须绑定来源 IP、站点和用途")
	}
}
