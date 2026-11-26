package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"niubwaf/internal/store"
)

type challenge struct {
	ip, host, purpose, origURL string
	siteID                     int64
	expires                    time.Time
}

const (
	captchaMaxBody       = 32 << 10
	captchaMaxChallenges = 10000
	captchaMaxPerIP      = 32
	captchaGCInterval    = 30 * time.Second
	captchaBot           = "bot"
	captchaRate          = "rate"
	captchaAction        = "niubwaf"
)

type Captcha struct {
	secret  []byte
	siteKey string
	verify  func(context.Context, string, string, *challenge) bool
	mu      sync.Mutex
	items   map[string]*challenge
	ipCount map[string]int
	lastGC  time.Time
}

func NewCaptcha(secret string) *Captcha {
	return &Captcha{
		secret: []byte(secret), items: map[string]*challenge{},
		ipCount: map[string]int{}, lastGC: time.Now(),
	}
}

// ConfigureTurnstile 在启动时设置验证服务。缺少密钥时，挑战请求仍会被拦截。
func (c *Captcha) ConfigureTurnstile(siteKey, secretKey string) bool {
	siteKey, secretKey = strings.TrimSpace(siteKey), strings.TrimSpace(secretKey)
	if siteKey == "" || secretKey == "" {
		return false
	}
	c.siteKey = siteKey
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	c.verify = turnstileVerifier(client, secretKey)
	return true
}

func turnstileVerifier(client *http.Client, secret string) func(context.Context, string, string, *challenge) bool {
	return func(ctx context.Context, token, id string, ch *challenge) bool {
		values := url.Values{"secret": {secret}, "response": {token}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(values.Encode()))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
		if err != nil || len(raw) > 16<<10 {
			return false
		}
		var result struct {
			Success  bool   `json:"success"`
			Hostname string `json:"hostname"`
			Action   string `json:"action"`
			CData    string `json:"cdata"`
		}
		return json.Unmarshal(raw, &result) == nil &&
			result.Success && strings.EqualFold(result.Hostname, ch.host) &&
			result.Action == captchaAction && result.CData == id
	}
}

// deleteChallengeLocked 同时维护挑战表和每 IP 计数，调用方须持有 c.mu。
func (c *Captcha) deleteChallengeLocked(id string) {
	ch, ok := c.items[id]
	if !ok {
		return
	}
	delete(c.items, id)
	if c.ipCount[ch.ip] <= 1 {
		delete(c.ipCount, ch.ip)
	} else {
		c.ipCount[ch.ip]--
	}
}

func (c *Captcha) gcExpiredLocked(now time.Time) {
	if now.Sub(c.lastGC) < captchaGCInterval {
		return
	}
	c.lastGC = now
	for id, ch := range c.items {
		if !now.Before(ch.expires) {
			c.deleteChallengeLocked(id)
		}
	}
}

func (c *Captcha) sign(ip string, siteID int64, purpose string, expiry int64) string {
	mac := hmac.New(sha256.New, c.secret)
	fmt.Fprintf(mac, "captcha|%s|%d|%s|%d", ip, siteID, purpose, expiry)
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Captcha) ValidCookie(r *http.Request, ip string, siteID int64, purpose string) bool {
	if c.verify == nil {
		return false
	}
	ck, err := r.Cookie("niub_pass_" + purpose)
	if err != nil {
		return false
	}
	expiryText, signature, ok := strings.Cut(ck.Value, ".")
	if !ok {
		return false
	}
	expiry, err := strconv.ParseInt(expiryText, 10, 64)
	if err != nil || time.Now().Unix() >= expiry {
		return false
	}
	return hmac.Equal([]byte(signature), []byte(c.sign(ip, siteID, purpose, expiry)))
}

// safeOrigURL 仅允许同源相对路径。
func safeOrigURL(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") && !strings.HasPrefix(s, "/\\") {
		return s
	}
	return "/"
}

func (c *Captcha) Issue(w http.ResponseWriter, ip, host string, siteID int64, purpose, origURL string) {
	w.Header().Set("Cache-Control", "no-store")
	if c.verify == nil {
		http.Error(w, "请求已拦截，站点尚未配置人机验证", http.StatusTooManyRequests)
		return
	}
	now := time.Now()
	c.mu.Lock()
	c.gcExpiredLocked(now)
	if len(c.items) >= captchaMaxChallenges || c.ipCount[ip] >= captchaMaxPerIP {
		c.mu.Unlock()
		http.Error(w, "人机验证挑战过多，请稍后重试", http.StatusTooManyRequests)
		return
	}
	id := store.RandToken()
	c.items[id] = &challenge{
		ip: ip, host: host, siteID: siteID, purpose: purpose,
		origURL: safeOrigURL(origURL), expires: now.Add(5 * time.Minute),
	}
	c.ipCount[ip]++
	c.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusTooManyRequests)
	captchaPage.Execute(w, struct{ SiteKey, ID, Action string }{c.siteKey, id, captchaAction})
}

func (c *Captcha) Verify(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, captchaMaxBody)
	if err := r.ParseForm(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "人机验证请求体过大", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "人机验证表单无效", http.StatusBadRequest)
		}
		return
	}
	id := r.PostForm.Get("challenge")
	token := r.PostForm.Get("cf-turnstile-response")
	if c.verify == nil || token == "" || len(token) > 2048 {
		http.Error(w, "人机验证未通过，请返回重试", http.StatusForbidden)
		return
	}

	c.mu.Lock()
	ch, exists := c.items[id]
	valid := exists && ch.ip == ip && strings.EqualFold(ch.host, stripPort(r.Host)) && time.Now().Before(ch.expires)
	if valid {
		c.deleteChallengeLocked(id)
	}
	c.mu.Unlock()
	if !valid || !c.verify(r.Context(), token, id, ch) {
		http.Error(w, "人机验证未通过或已过期，请返回重试", http.StatusForbidden)
		return
	}

	expiry := time.Now().Add(30 * time.Minute).Unix()
	http.SetCookie(w, &http.Cookie{
		Name: "niub_pass_" + ch.purpose, Value: fmt.Sprintf("%d.%s", expiry, c.sign(ip, ch.siteID, ch.purpose, expiry)),
		Path: "/", MaxAge: 1800, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, ch.origURL, http.StatusSeeOther)
}

var captchaPage = template.Must(template.New("captcha").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NiuB WAF - 人机验证</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070a12;color:#e6edf7;font:16px system-ui}
main{background:#131b2e;border:1px solid #243654;border-radius:20px;padding:32px}
h1{font-size:20px;margin:0 0 24px}button{margin-top:16px;padding:8px 16px}
</style></head><body><main>
<h1>请完成人机验证</h1>
<form action="/__niubwaf/captcha" method="post">
<input type="hidden" name="challenge" value="{{.ID}}">
<div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-action="{{.Action}}" data-cdata="{{.ID}}"></div>
<button type="submit">继续访问</button>
</form><noscript>请启用 JavaScript 后刷新页面。</noscript>
</main></body></html>`))
