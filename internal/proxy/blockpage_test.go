package proxy

import (
	"strings"
	"testing"
)

func TestRenderBlockPageEscapesVars(t *testing.T) {
	payload := `<script>alert(1)</script>`
	vars := map[string]string{
		"REQ_ID":    "abc123",
		"REASON":    `命中 " onload="alert(1)`,
		"CLIENT_IP": payload,
		"DOMAIN":    `<img src=x onerror=alert(1)>`,
		"TIME":      "2026-11-17 00:00:00",
		"RULE_ID":   "100001",
	}
	out := RenderBlockPage("", vars)
	if strings.Contains(out, payload) {
		t.Fatal("CLIENT_IP 未转义，存在反射型 XSS")
	}
	if strings.Contains(out, "<img src=x") {
		t.Fatal("DOMAIN 未转义")
	}
	if strings.Contains(out, `" onload="`) {
		t.Fatal("REASON 未转义引号")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("CLIENT_IP 应被 HTML 转义")
	}
	if !strings.Contains(out, "&#34;") {
		t.Fatal("REASON 中的双引号应被转义")
	}
}

func TestRenderBlockPageCustomTemplateEscapes(t *testing.T) {
	out := RenderBlockPage(`<p>{{CLIENT_IP}}</p><b>{{REASON}}</b>`, map[string]string{
		"CLIENT_IP": `<svg/onload=alert(1)>`,
		"REASON":    `a<b>c`,
	})
	if strings.Contains(out, "<svg/onload") {
		t.Fatal("自定义模板 CLIENT_IP 未转义")
	}
	if !strings.Contains(out, "&lt;svg/onload=alert(1)&gt;") || !strings.Contains(out, "a&lt;b&gt;c") {
		t.Fatalf("自定义模板转义结果异常: %s", out)
	}
}
