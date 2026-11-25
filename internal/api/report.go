package api

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"niubwaf/internal/store"
)

func (a *API) report(w http.ResponseWriter, r *http.Request) {
	st := a.Store.Stats()
	sites, _ := a.Store.ListSites()
	topIPs, _ := a.Store.TopIPs(10)
	topRules, _ := a.Store.TopRules(10)
	topDomains, _ := a.Store.TopDomains(10)
	topCountries, _ := a.Store.TopCountries(10)
	logs, total, _ := a.Store.QueryLogs("", "", "", 50, 0)
	a.audit(r, "导出防护报告", "")

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>牛B WAF 防护报告</title><style>
body{font-family:"Microsoft YaHei",sans-serif;margin:40px auto;max-width:900px;color:#222;line-height:1.6}
h1{color:#1a56b0;border-bottom:3px solid #1a56b0;padding-bottom:10px}
h2{color:#1a56b0;margin-top:32px;font-size:18px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
th,td{border:1px solid #ccd;padding:6px 10px;text-align:left}
th{background:#eef3fb}
.cards{display:flex;gap:16px;flex-wrap:wrap}
.card{flex:1;min-width:160px;background:#f4f8ff;border:1px solid #d5e2f5;border-radius:8px;padding:16px;text-align:center}
.card .n{font-size:28px;font-weight:700;color:#1a56b0}
.meta{color:#777;font-size:13px}
@media print{body{margin:10mm}}
</style></head><body>`)
	fmt.Fprintf(&b, `<h1>牛B WAF 防护报告</h1><p class="meta">生成时间：%s · 本报告由牛B WAF 自动生成</p>`, time.Now().Format("2006-01-02 15:04:05"))
	b.WriteString(`<h2>一、总体概况</h2><div class="cards">`)
	fmt.Fprintf(&b, `<div class="card"><div class="n">%d</div>累计请求</div>`, st.TotalReqs)
	fmt.Fprintf(&b, `<div class="card"><div class="n">%d</div>累计拦截</div>`, st.TotalBlocks)
	fmt.Fprintf(&b, `<div class="card"><div class="n">%d</div>今日请求</div>`, st.TodayReqs)
	fmt.Fprintf(&b, `<div class="card"><div class="n">%d</div>今日拦截</div>`, st.TodayBlocks)
	fmt.Fprintf(&b, `<div class="card"><div class="n">%d</div>防护站点</div>`, len(sites))
	b.WriteString(`</div>`)

	b.WriteString(`<h2>二、防护站点清单</h2><table><tr><th>名称</th><th>域名</th><th>上游</th><th>防护模式</th><th>状态</th></tr>`)
	for _, s := range sites {
		status := "启用"
		if !s.Enabled {
			status = "停用"
		}
		fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, html.EscapeString(s.Name), html.EscapeString(s.Domain), html.EscapeString(s.Upstream), html.EscapeString(s.WAFMode), status)
	}
	b.WriteString(`</table>`)

	kvTable := func(title string, kvs []store.KV) {
		fmt.Fprintf(&b, `<h2>%s</h2><table><tr><th>#</th><th>项目</th><th>次数</th></tr>`, title)
		for i, kv := range kvs {
			fmt.Fprintf(&b, `<tr><td>%d</td><td>%s</td><td>%d</td></tr>`, i+1, html.EscapeString(kv.Key), kv.Count)
		}
		b.WriteString(`</table>`)
	}
	kvTable("三、攻击源 IP Top10", topIPs)
	kvTable("四、攻击类型 Top10", topRules)
	kvTable("五、受攻击站点 Top10", topDomains)
	kvTable("六、攻击来源国家/地区 Top10", topCountries)

	fmt.Fprintf(&b, `<h2>七、最近攻击事件（共 %d 条，展示最近 50 条）</h2>`, total)
	b.WriteString(`<table><tr><th>时间</th><th>站点</th><th>IP</th><th>动作</th><th>描述</th><th>状态码</th></tr>`)
	for _, l := range logs {
		fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>`,
			html.EscapeString(l.Ts), html.EscapeString(l.Domain), html.EscapeString(l.ClientIP), html.EscapeString(l.Action), html.EscapeString(l.Msg), l.Status)
	}
	b.WriteString(`</table>`)
	b.WriteString(`<p class="meta" style="margin-top:40px">—— 报告结束 · 牛B WAF ——</p></body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Content-Disposition", "attachment; filename=niubwaf-report.html")
	w.Write([]byte(b.String()))
}
