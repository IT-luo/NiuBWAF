package proxy

import (
	"html"
	"net/http"
	"strings"
	"time"
)

const DefaultBlockPage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>请求已拦截 · 牛B WAF</title>
<style>
:root{
  color-scheme:light;
  --ink:#172a46;--muted:#4c6180;--line:#dfe8f3;--paper:#fff;
  --soft-blue:#edf4ff;--blue:#2857bd;--soft-red:#fff3f5;--red:#a5304b;
  --mono:"Cascadia Code",Consolas,"Liberation Mono",monospace;
}
*,*::before,*::after{box-sizing:border-box}
body{
  margin:0;min-height:100vh;min-height:100svh;display:grid;place-items:center;padding:24px;
  background:radial-gradient(ellipse at 12% 6%,#e7efff,transparent 56%),
    radial-gradient(ellipse at 90% 90%,#e6f5f0,transparent 55%),#f5f8fc;
  color:var(--ink);font:15px/1.55 "Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
}
.card{
  width:min(100%,640px);padding:clamp(20px,5vw,36px);border:1px solid var(--line);
  border-radius:24px;background:var(--paper);box-shadow:0 20px 65px rgba(42,72,115,.12);
}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:28px;font-size:16px;font-weight:800}
.brand-mark,.status-mark{display:grid;place-items:center;flex:none}
.brand-mark{width:36px;height:36px;border-radius:11px;background:var(--soft-blue);color:var(--blue)}
.status-mark{width:52px;height:52px;border-radius:15px;color:var(--red);background:#ffe3e9}
.brand-mark svg{width:22px;height:22px}
.status-mark svg{width:27px;height:27px}
.status{display:flex;align-items:flex-start;gap:15px;padding:18px;border-radius:17px;background:var(--soft-red)}
.status-copy{flex:1;min-width:0}
h1{margin:0 0 10px;font-size:clamp(23px,5vw,30px);line-height:1.2;letter-spacing:-.025em}
.reason-label{display:block;color:var(--red);font-size:12px;font-weight:700;margin-bottom:2px}
.reason{margin:0;color:var(--ink);overflow-wrap:anywhere}
.request-id{
  display:flex;align-items:baseline;gap:10px 16px;flex-wrap:wrap;
  margin-top:18px;padding:13px 16px;border-radius:12px;background:var(--soft-blue);color:var(--blue);
}
.request-id span{font-size:12px;font-weight:700}
code{font-family:var(--mono);overflow-wrap:anywhere}
.request-id code{font-size:17px;font-weight:700;user-select:all}
.details{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px 18px;margin:18px 0 0}
.details .site{grid-column:1/-1}
dt{font-size:12px;font-weight:650;color:var(--muted)}
dd{margin:3px 0 0;font-size:13px;overflow-wrap:anywhere}
.help{margin:22px 0 0;padding-top:15px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
@media(max-width:440px){
  body{padding:12px}.card{border-radius:18px}.brand{margin-bottom:17px}
  .status{padding:13px;gap:11px}.status-mark{width:40px;height:40px;border-radius:11px}
  .status-mark svg{width:22px;height:22px}.details{grid-template-columns:minmax(0,1fr);gap:11px}
}
</style>
</head>
<body>
<main class="card" aria-labelledby="block-title">
  <div class="brand">
    <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path fill="#fff" d="M12.55 6.5 7.05 13.1h4.9l-.5 4.4 5.55-6.6h-5z"/></svg></span>
    <span>牛B WAF</span>
  </div>
  <div class="status">
    <span class="status-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg></span>
    <div class="status-copy">
      <h1 id="block-title">请求已被拦截</h1>
      <span class="reason-label">拦截原因</span>
      <p class="reason">{{REASON}}</p>
    </div>
  </div>
  <div class="request-id"><span>请求 ID</span><code>{{REQ_ID}}</code></div>
  <dl class="details">
    <div class="site"><dt>目标站点</dt><dd><code>{{DOMAIN}}</code></dd></div>
    <div><dt>客户端 IP</dt><dd><code>{{CLIENT_IP}}</code></dd></div>
    <div><dt>拦截时间</dt><dd><code>{{TIME}}</code></dd></div>
  </dl>
  <p class="help">如果您认为这是误拦截，请将请求 ID 提供给站点管理员。</p>
</main>
</body>
</html>`

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
