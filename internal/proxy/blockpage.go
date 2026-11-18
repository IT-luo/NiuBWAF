package proxy

import (
	"html"
	"net/http"
	"strings"
	"time"
)

const DefaultBlockPage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>牛B WAF - 请求被拦截</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(900px 460px at 50% -10%,rgba(251,113,133,.1),transparent 60%),radial-gradient(800px 500px at 100% 110%,rgba(99,102,241,.08),transparent 55%),#070a12;font-family:"Inter","SF Pro Display",-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#e6edf7;padding:20px}
.card{background:linear-gradient(180deg,rgba(23,32,55,.8),rgba(13,19,35,.86));border:1px solid rgba(148,163,184,.2);border-radius:22px;padding:44px 52px;max-width:560px;width:100%;text-align:center;box-shadow:0 24px 80px rgba(2,6,16,.6)}
.mark{width:60px;height:60px;margin:0 auto 16px;border-radius:17px;background:linear-gradient(135deg,#fb7185,#f43f5e);display:flex;align-items:center;justify-content:center;box-shadow:0 8px 28px rgba(244,63,94,.4)}
.mark svg{width:30px;height:30px;stroke:#fff}
.logo{font-size:21px;font-weight:800;background:linear-gradient(135deg,#22d3ee,#6366f1 55%,#a855f7);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:4px}
h1{font-size:20px;margin:14px 0 8px;font-weight:700}
p{color:#94a3b8;font-size:14px;line-height:1.7;margin:6px 0}
.meta{margin-top:22px;padding-top:18px;border-top:1px solid rgba(148,163,184,.14);font-size:12px;color:#5b6b85;text-align:left}
.meta div{margin:5px 0}
code{color:#94a3b8;font-family:"SF Mono","Cascadia Code",Consolas,monospace}
</style></head><body>
<div class="card">
<div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg></div>
<div class="logo">牛B WAF</div>
<h1>您的请求已被拦截</h1>
<p>检测到潜在恶意行为，本次访问已被防火墙阻断。</p>
<p>原因：{{REASON}}</p>
<div class="meta">
<div>请求 ID：<code>{{REQ_ID}}</code></div>
<div>客户端 IP：<code>{{CLIENT_IP}}</code></div>
<div>目标站点：<code>{{DOMAIN}}</code></div>
<div>时间：<code>{{TIME}}</code></div>
</div>
<p style="margin-top:18px;font-size:12px">如您认为这是误拦截，请携带请求 ID 联系站点管理员。</p>
</div></body></html>`

func RenderBlockPage(tpl string, vars map[string]string) string {
	if strings.TrimSpace(tpl) == "" {
		tpl = DefaultBlockPage
	}
	// 所有占位符值均来自请求侧（REASON 含命中载荷、CLIENT_IP/DOMAIN 可伪造），必须 HTML 转义防反射型 XSS
	esc := func(k string) string { return html.EscapeString(vars[k]) }
	r := strings.NewReplacer(
		"{{REQ_ID}}", esc("REQ_ID"),
		"{{REASON}}", esc("REASON"),
		"{{CLIENT_IP}}", esc("CLIENT_IP"),
		"{{DOMAIN}}", esc("DOMAIN"),
		"{{TIME}}", esc("TIME"),
		"{{RULE_ID}}", esc("RULE_ID"),
	)
	return r.Replace(tpl)
}

func WriteBlock(w http.ResponseWriter, status int, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-NiuB-WAF", "blocked")
	w.WriteHeader(status)
	w.Write([]byte(html))
}

func nowStr() string {
	return time.Now().Format("2006-01-02 15:04:05")
}
