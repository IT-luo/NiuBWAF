package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 挑战参数与 ID 必须不可预测：math/rand 的状态可由攻击者自己收到的 ID 序列反推
func randIntn(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic("crypto/rand 不可用: " + err.Error())
	}
	return v.Int64()
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用: " + err.Error())
	}
	return hex.EncodeToString(b)
}

type challenge struct {
	answer  uint32
	ip      string
	siteID  int64
	origURL string
	expires time.Time
}

type Captcha struct {
	secret []byte
	mu     sync.Mutex
	items  map[string]*challenge
}

func NewCaptcha(secret string) *Captcha {
	return &Captcha{secret: []byte(secret), items: map[string]*challenge{}}
}

func (c *Captcha) sign(ip string, siteID int64, expiry int64) string {
	mac := hmac.New(sha256.New, c.secret)
	fmt.Fprintf(mac, "%s|%d|%d", ip, siteID, expiry)
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Captcha) ValidCookie(r *http.Request, ip string, siteID int64) bool {
	ck, err := r.Cookie("niub_pass")
	if err != nil {
		return false
	}
	parts := strings.SplitN(ck.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(c.sign(ip, siteID, expiry)))
}

// jsEsc 转义嵌入 <script> 的 JS 单引号字符串，防止 </script> 截断与引号逃逸
func jsEsc(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "<", `\x3c`, ">", `\x3e`, "\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}

// safeOrigURL 仅放行同源相对路径，杜绝 //evil.com、/\evil.com 及绝对 URL 开放重定向
func safeOrigURL(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") && !strings.HasPrefix(s, "/\\") {
		return s
	}
	return "/"
}

func (c *Captcha) Issue(w http.ResponseWriter, ip string, siteID int64, origURL string) {
	c.mu.Lock()
	for k, v := range c.items {
		if time.Now().After(v.expires) {
			delete(c.items, k)
		}
	}
	a := int(randIntn(900000)) + 100000
	b := int(randIntn(900000)) + 100000
	cc := int(randIntn(90000)) + 10000
	// 与页面 JS 的 (Math.imul(a^b,c)+a)>>>0 保持一致
	answer := uint32(int64(int32(int64(a^b)*int64(cc))) + int64(a))
	id := randHex(8)
	origURL = safeOrigURL(origURL)
	c.items[id] = &challenge{answer: answer, ip: ip, siteID: siteID, origURL: origURL, expires: time.Now().Add(5 * time.Minute)}
	c.mu.Unlock()

	core := fmt.Sprintf("var a=%d,b=%d,c=%d;var v=(Math.imul(a^b,c)+a)>>>0;"+
		"fetch('/__niubwaf/captcha',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'challenge=%s&answer='+v})"+
		".then(function(r){if(r.ok){location.replace('%s')}else{document.getElementById('st').textContent='验证失败，请刷新页面重试'}})"+
		".catch(function(){document.getElementById('st').textContent='网络错误，请刷新页面重试'});",
		a, b, cc, id, jsEsc(origURL))
	codes := make([]string, len(core))
	for i := range core {
		codes[i] = strconv.Itoa(int(core[i]))
	}
	vn := "_0x" + randHex(4)
	script := fmt.Sprintf("var %s=[%s];var %s=String.fromCharCode.apply(null,%s);(0,eval)(%s);",
		vn, strings.Join(codes, ","), vn+"s", vn, vn+"s")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, jsChallengePage, script)
}

func (c *Captcha) Verify(w http.ResponseWriter, r *http.Request, ip string) {
	r.ParseForm()
	id := r.FormValue("challenge")
	ans, err := strconv.ParseUint(r.FormValue("answer"), 10, 32)
	c.mu.Lock()
	ch, ok := c.items[id]
	if ok {
		delete(c.items, id)
	}
	c.mu.Unlock()
	if !ok || err != nil || time.Now().After(ch.expires) || ch.ip != ip || ch.answer != uint32(ans) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>牛B WAF</title><body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#070a12;font-family:'Inter','Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;color:#e6edf7"><div style="background:linear-gradient(180deg,rgba(23,32,55,.8),rgba(13,19,35,.86));border:1px solid rgba(148,163,184,.2);border-radius:22px;padding:40px 48px;text-align:center"><h2 style="font-size:18px;margin:0 0 10px">验证失败</h2><p style="color:#94a3b8;font-size:14px;margin:0 0 18px">浏览器校验未通过或验证已过期。</p><a href="javascript:history.back()" style="color:#38bdf8;font-size:13px;text-decoration:none">返回重试</a></div></body>`)
		return
	}
	expiry := time.Now().Add(30 * time.Minute).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:  "niub_pass",
		Value: fmt.Sprintf("%d.%s", expiry, c.sign(ip, ch.siteID, expiry)),
		Path:  "/", MaxAge: 1800, HttpOnly: true,
	})
	http.Redirect(w, r, ch.origURL, http.StatusFound)
}

const jsChallengePage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>牛B WAF - 人机验证</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(900px 460px at 50%% -10%%,rgba(34,211,238,.1),transparent 60%%),radial-gradient(800px 500px at 100%% 110%%,rgba(168,85,247,.08),transparent 55%%),#070a12;font-family:"Inter","SF Pro Display",-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#e6edf7;padding:20px}
.card{background:linear-gradient(180deg,rgba(23,32,55,.8),rgba(13,19,35,.86));border:1px solid rgba(148,163,184,.2);border-radius:22px;padding:40px 48px;text-align:center;box-shadow:0 24px 80px rgba(2,6,16,.6);max-width:440px;width:100%%}
.logo{font-size:22px;font-weight:800;background:linear-gradient(135deg,#22d3ee,#6366f1 55%%,#a855f7);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:8px}
h2{font-size:15px;font-weight:400;color:#94a3b8;margin:0 0 24px}
.spin{width:34px;height:34px;margin:0 auto 18px;border:3px solid rgba(148,163,184,.2);border-top-color:#22d3ee;border-radius:50%%;animation:sp 1s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.tip{margin-top:22px;font-size:12px;color:#5b6b85}
</style></head><body>
<div class="card">
<div class="logo">牛B WAF</div>
<h2>访问频率异常，正在验证您的浏览器</h2>
<div class="spin"></div>
<div id="st">请稍候，验证通过后自动继续访问…</div>
<noscript><p style="color:#ff6b6b">请启用 JavaScript 后刷新页面</p></noscript>
<div class="tip">验证通过后 30 分钟内免验证 · 牛B WAF 人机防护</div>
</div>
<script>%s</script>
</body></html>`