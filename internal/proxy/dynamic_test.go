package proxy

import (
	"fmt"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func dynTestProxy() *Proxy { return &Proxy{dynSecret: []byte("unit-test-secret")} }

// decodeDynScript 还原字符码数组混淆，验证植入脚本的真实内容
func decodeDynScript(t *testing.T, script string) string {
	t.Helper()
	start := strings.Index(script, "=[")
	end := strings.Index(script, "];")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("脚本缺少字符码数组: %s", script)
	}
	var b strings.Builder
	for _, n := range strings.Split(script[start+2:end], ",") {
		v, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			t.Fatalf("非法字符码 %q: %v", n, err)
		}
		b.WriteByte(byte(v))
	}
	return b.String()
}

func TestDynTokenRoundTrip(t *testing.T) {
	p := dynTestProxy()
	tok := p.issueDynToken("1.2.3.4", 7)
	if p.consumeDynTokenValue(tok, "9.9.9.9", 7) {
		t.Fatal("跨 IP 令牌必须拒绝")
	}
	if p.consumeDynTokenValue(tok, "1.2.3.4", 8) {
		t.Fatal("跨站点令牌必须拒绝")
	}
	if p.consumeDynTokenValue(tok+"0", "1.2.3.4", 7) {
		t.Fatal("篡改签名必须拒绝")
	}
	if p.consumeDynTokenValue("garbage", "1.2.3.4", 7) {
		t.Fatal("畸形令牌必须拒绝")
	}
	if !p.consumeDynTokenValue(tok, "1.2.3.4", 7) {
		t.Fatal("自签发令牌应通过校验")
	}
}

func TestDynTokenExpiry(t *testing.T) {
	p := dynTestProxy()
	expired := time.Now().Add(-time.Minute).Unix()
	nonce := strings.Repeat("a", 48)
	tok := strconv.FormatInt(expired, 10) + "." + nonce + "." + p.dynSign("1.2.3.4", 7, expired, nonce)
	if p.consumeDynTokenValue(tok, "1.2.3.4", 7) {
		t.Fatal("过期令牌必须拒绝")
	}
}

func TestDynTokenSecretIsolation(t *testing.T) {
	p := dynTestProxy()
	other := &Proxy{dynSecret: []byte("different-secret")}
	tok := p.issueDynToken("1.2.3.4", 7)
	if other.consumeDynTokenValue(tok, "1.2.3.4", 7) {
		t.Fatal("不同密钥签发的令牌不可互认")
	}
}

func TestIsStateChanging(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if !isStateChanging(m) {
			t.Fatalf("%s 应为写操作", m)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		if isStateChanging(m) {
			t.Fatalf("%s 不应为写操作", m)
		}
	}
}

func TestDynTokenFromHeader(t *testing.T) {
	p := dynTestProxy()
	tok := p.issueDynToken("1.2.3.4", 7)
	r := httptest.NewRequest("POST", "/submit", nil)
	r.Header.Set("X-NiuB-Dyn-Token", "bad")
	if p.consumeDynToken(r, nil, "1.2.3.4", 7) {
		t.Fatal("非法请求头令牌应拒绝")
	}
	r.Header.Set("X-NiuB-Dyn-Token", tok)
	if !p.consumeDynToken(r, nil, "1.2.3.4", 7) {
		t.Fatal("请求头令牌应通过")
	}
}

func TestDynTokenFromBody(t *testing.T) {
	p := dynTestProxy()
	cases := map[string]string{
		"urlencoded": "a=1&niub_dyn_token=%s&b=2",
		"json":       `{"niub_dyn_token":"%s","x":1}`,
		"multipart":  "--B\r\nContent-Disposition: form-data; name=\"niub_dyn_token\"\r\n\r\n%s\r\n--B--\r\n",
	}
	for name, format := range cases {
		body := fmt.Sprintf(format, p.issueDynToken("1.2.3.4", 7))
		r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
		if !p.consumeDynToken(r, []byte(body), "1.2.3.4", 7) {
			t.Fatalf("%s 承载的令牌应通过", name)
		}
	}
	r := httptest.NewRequest("POST", "/submit", nil)
	if p.consumeDynToken(r, []byte("a=1&b=2"), "1.2.3.4", 7) {
		t.Fatal("无令牌请求体应拒绝")
	}
}

func TestDynScriptObfuscation(t *testing.T) {
	p := dynTestProxy()
	tok := p.issueDynToken("1.2.3.4", 7)
	script := string(dynScript(tok))
	if strings.Contains(script, tok) {
		t.Fatal("混淆脚本不得明文暴露令牌")
	}
	if strings.Contains(script, "niub_dyn_token") {
		t.Fatal("混淆脚本不得明文暴露字段名")
	}
	if !strings.Contains(script, "String.fromCharCode") || !strings.Contains(script, "eval") {
		t.Fatal("脚本应使用字符码还原 + eval")
	}
	core := decodeDynScript(t, script)
	for _, want := range []string{tok, "niub_dyn_token", "X-NiuB-Dyn-Token", "XMLHttpRequest", "fetch", "MutationObserver", "getResponseHeader", "headers.get"} {
		if !strings.Contains(core, want) {
			t.Fatalf("还原后的脚本缺少 %q", want)
		}
	}
}

func TestInjectDynamic(t *testing.T) {
	p := dynTestProxy()
	html := []byte("<html><body><h1>hi</h1></body></html>")
	out := p.injectDynamic(html, "1.2.3.4", 7)
	s := string(out)
	idxScript := strings.Index(s, "<script>")
	idxBody := strings.Index(s, "</body>")
	if idxScript < 0 || idxBody < 0 || idxScript > idxBody {
		t.Fatal("脚本应植入在 </body> 之前")
	}
	if !strings.Contains(s, "<h1>hi</h1>") {
		t.Fatal("原始页面内容必须保留")
	}
	// 从植入脚本还原令牌并校验，确认 issue/inject/validate 一致
	core := decodeDynScript(t, s[idxScript:])
	m := regexp.MustCompile(`var T='([^']+)'`).FindStringSubmatch(core)
	if m == nil {
		t.Fatal("脚本中未找到令牌变量")
	}
	if !p.consumeDynTokenValue(m[1], "1.2.3.4", 7) {
		t.Fatal("植入的令牌应能通过校验")
	}
}

func TestInjectDynamicUppercaseAndFragment(t *testing.T) {
	p := dynTestProxy()
	upper := p.injectDynamic([]byte("<HTML><BODY>x</BODY></HTML>"), "1.2.3.4", 7)
	if strings.Index(string(upper), "<script>") > strings.Index(string(upper), "</BODY>") {
		t.Fatal("大写 </BODY> 也应正确定位")
	}
	frag := p.injectDynamic([]byte("<div>fragment</div>"), "1.2.3.4", 7)
	if !strings.HasSuffix(string(frag), "</script>") {
		t.Fatal("无 </body> 的片段应追加脚本")
	}
	if !strings.HasPrefix(string(frag), "<div>fragment</div>") {
		t.Fatal("片段原内容必须保留")
	}
}
