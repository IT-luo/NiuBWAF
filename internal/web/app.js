'use strict';
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* 线性图标（stroke 风格，与侧边栏一致） */
const ICONS = {
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
  layers: '<path d="m12 2 10 5-10 5L2 7l10-5z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  pin: '<path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  refresh: '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
  report: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>',
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
};
const ico = n => `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[n] || ''}</svg>`;
const pageHead = (title, sub, actions) => `<div class="page-head"><div><h1>${title}</h1><p>${sub}</p></div>${actions ? `<div class="page-actions">${actions}</div>` : ''}</div>`;
const emptyHTML = (cols, msg) => `<tr><td colspan="${cols}" class="empty">${ico('inbox')}${msg}</td></tr>`;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: {'Content-Type': 'application/json'},
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && !path.includes('/login')) { showLogin(); throw new Error('未登录'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('请求失败 ' + res.status));
  return data;
}

function toast(msg, isErr) {
  const el = document.createElement('div');
  el.className = 'toast-item' + (isErr ? ' error' : '');
  el.textContent = msg;
  $('#toast').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

function showLogin() { $('#login').classList.remove('hidden'); $('#app').classList.add('hidden'); $('#force-change').classList.add('hidden'); }
function showApp() { $('#login').classList.add('hidden'); $('#force-change').classList.add('hidden'); $('#app').classList.remove('hidden'); route(); }
function showForceChange() { $('#login').classList.add('hidden'); $('#app').classList.add('hidden'); $('#force-change').classList.remove('hidden'); $('#fc-err').textContent = ''; setTimeout(() => $('#fc-new').focus(), 50); }

let lastLoginPass = '';
async function doLogin() {
  try {
    const pass = $('#login-pass').value;
    const d = await api('/api/login', {method: 'POST', body: {password: pass}});
    $('#login-err').textContent = '';
    if (d.must_change) { lastLoginPass = pass; showForceChange(); }
    else showApp();
  } catch (e) { $('#login-err').textContent = e.message; }
}
async function doForceChange() {
  const nw = $('#fc-new').value, cf = $('#fc-confirm').value;
  const err = m => { $('#fc-err').textContent = m; };
  if (nw.length < 8) return err('新密码至少 8 位');
  if (!/[0-9]/.test(nw) || !/[a-zA-Z]/.test(nw)) return err('新密码需同时包含字母和数字');
  if (nw === 'admin123') return err('新密码不能为默认口令 admin123');
  if (nw !== cf) return err('两次输入的新密码不一致');
  try {
    await api('/api/password', {method: 'PUT', body: {old: lastLoginPass, new: nw}});
    lastLoginPass = ''; $('#fc-new').value = ''; $('#fc-confirm').value = '';
    toast('密码已修改');
    showApp();
  } catch (e) { err(e.message); }
}
async function doLogout() { await api('/api/logout', {method: 'POST'}); showLogin(); }
$('#login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('#fc-confirm').addEventListener('keydown', e => { if (e.key === 'Enter') doForceChange(); });
$('#fc-new').addEventListener('keydown', e => { if (e.key === 'Enter') $('#fc-confirm').focus(); });

const charts = [];
function disposeCharts() { charts.forEach(c => c.dispose()); charts.length = 0; }
function mkChart(el, opt) { const c = echarts.init(el); c.setOption(opt); charts.push(c); return c; }
const axisStyle = {
  axisLine: {lineStyle: {color: 'rgba(148,163,184,.18)'}}, axisTick: {show: false},
  axisLabel: {color: '#7d8db0', fontSize: 11}, splitLine: {lineStyle: {color: 'rgba(148,163,184,.07)'}},
};
const tipStyle = {
  backgroundColor: 'rgba(14,21,38,.96)', borderColor: 'rgba(148,163,184,.2)',
  textStyle: {color: '#e6edf7', fontSize: 12},
  extraCssText: 'box-shadow:0 8px 24px rgba(2,6,16,.5);border-radius:10px;',
};
const areaGrad = (rgb) => new echarts.graphic.LinearGradient(0, 0, 0, 1, [
  {offset: 0, color: `rgba(${rgb},.3)`}, {offset: 1, color: `rgba(${rgb},0)`}]);

let liveES = null;
let dashTimer = null;
function closeLive() { if (liveES) { liveES.close(); liveES = null; } }

function route() {
  disposeCharts(); closeLive();
  if (repTimer) { clearInterval(repTimer); repTimer = null; }
  if (dashTimer) { clearInterval(dashTimer); dashTimer = null; }
  const view = (location.hash.replace('#/', '') || 'dashboard').split('?')[0];
  document.querySelectorAll('.sidebar nav a[data-view]').forEach(a =>
    a.classList.toggle('active', a.dataset.view === view));
  const views = {dashboard, sites, logs, tuning, rules, ips, reputation, settings, audit};
  (views[view] || dashboard)();
}
window.addEventListener('hashchange', route);

/* ---------------- 仪表盘 ---------------- */
async function dashboard() {
  const m = $('#main');
  m.innerHTML = pageHead('仪表盘', '全局防护态势 · 数据实时聚合 · 每 10 秒自动刷新') + `
  <div class="cards" id="stat-cards"></div>
  <div class="panel"><h3>流量趋势（近 24 小时）</h3><div id="trend" class="chart"></div></div>
  <div class="grid2">
    <div class="panel"><h3>攻击源 IP Top10</h3><div id="top-ips" class="chart"></div></div>
    <div class="panel"><h3>攻击类型 Top10</h3><div id="top-rules" class="chart"></div></div>
  </div>
  <div class="panel"><h3><span class="live-dot"></span>实时攻击事件</h3>
    <table><thead><tr><th>时间</th><th>站点</th><th>IP</th><th>动作</th><th>描述</th></tr></thead>
    <tbody id="live-body">${emptyHTML(5, '等待事件…')}</tbody></table>
  </div>`;
  let trendChart = null, ipsChart = null, rulesChart = null;
  const paint = async first => {
    const [stats, trend, ips, rules] = await Promise.all([
      api('/api/stats'), api('/api/trend?hours=24'), api('/api/top/ips'), api('/api/top/rules')]);
    $('#stat-cards').innerHTML = `
      ${card('今日请求', stats.today_reqs, '', 'activity', '')}
      ${card('今日拦截', stats.today_blocks, 'red', 'zap', 'red')}
      ${card('累计请求', stats.total_reqs, '', 'layers', 'violet')}
      ${card('累计拦截', stats.total_blocks, 'red', 'shield', 'red')}
      ${card('防护站点', stats.sites_enabled + ' / ' + stats.sites, 'green', 'globe', 'green')}
      ${card('GeoIP 库', stats.geoip_available ? '已加载' : '未加载', stats.geoip_available ? 'green' : '', 'pin', 'amber')}`;
    if (first) countUp(); else fmtCards();
    const trendOpt = {
      tooltip: {trigger: 'axis', ...tipStyle},
      legend: {data: ['请求', '拦截'], textStyle: {color: '#94a3b8'}, icon: 'roundRect', itemWidth: 12, itemHeight: 4},
      grid: {left: 50, right: 20, top: 40, bottom: 30},
      xAxis: {type: 'category', boundaryGap: false, data: trend.map(p => p.minute.slice(11)), ...axisStyle},
      yAxis: {type: 'value', ...axisStyle},
      series: [
        {name: '请求', type: 'line', smooth: true, showSymbol: false, data: trend.map(p => p.reqs), lineStyle: {width: 2, color: '#38bdf8'}, itemStyle: {color: '#38bdf8'}, areaStyle: {color: areaGrad('56,189,248')}},
        {name: '拦截', type: 'line', smooth: true, showSymbol: false, data: trend.map(p => p.blocks), lineStyle: {width: 2, color: '#fb7185'}, itemStyle: {color: '#fb7185'}, areaStyle: {color: areaGrad('251,113,133')}}]
    };
    if (first) trendChart = mkChart($('#trend'), trendOpt); else trendChart.setOption(trendOpt);
    const ipKvs = ips.map(r => ({key: r.city ? r.key + ' · ' + r.city : r.key, count: r.count}));
    const ruleKvs = rules.map(r => ({key: r.key.length > 26 ? r.key.slice(0, 26) + '…' : r.key, count: r.count}));
    if (first) {
      ipsChart = barChart($('#top-ips'), ipKvs, '#fbbf24');
      rulesChart = barChart($('#top-rules'), ruleKvs, '#fb7185');
    } else {
      ipsChart.setOption(barOpt(ipKvs, '#fbbf24'));
      rulesChart.setOption(barOpt(ruleKvs, '#fb7185'));
    }
  };
  try {
    await paint(true);
    const recent = await api('/api/logs?size=8');
    renderLiveRows(recent.list);
    liveES = new EventSource('/api/events');
    liveES.onmessage = ev => {
      const d = JSON.parse(ev.data);
      if (d.type !== 'attack') return;
      const tb = $('#live-body');
      if (tb.querySelector('.empty')) tb.innerHTML = '';
      tb.insertAdjacentHTML('afterbegin', liveRow(d));
      while (tb.children.length > 12) tb.lastChild.remove();
    };
    dashTimer = setInterval(() => {
      if (document.visibilityState === 'visible') paint(false).catch(() => {});
    }, 10000);
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
function fmtCards() {
  document.querySelectorAll('#stat-cards .num').forEach(el => {
    const raw = el.textContent.trim();
    if (/^\d+$/.test(raw)) el.textContent = (+raw).toLocaleString();
  });
}
function card(label, num, cls, iconName, iconCls) {
  return `<div class="card"><div class="card-top"><div class="label">${label}</div><div class="card-icon ${iconCls}">${ico(iconName)}</div></div><div class="num ${cls || ''}">${num}</div></div>`;
}
function countUp() {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.querySelectorAll('#stat-cards .num').forEach(el => {
    const raw = el.textContent.trim();
    if (!/^\d+$/.test(raw)) return;
    const target = +raw;
    el.textContent = target.toLocaleString();
    if (reduce || document.visibilityState !== 'visible') return;
    const t0 = performance.now(), dur = 700;
    const step = t => {
      const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * e).toLocaleString();
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}
function barOpt(kvs, color) {
  return {
    tooltip: tipStyle, grid: {left: 10, right: 30, top: 10, bottom: 10, containLabel: true},
    xAxis: {type: 'value', ...axisStyle},
    yAxis: {type: 'category', inverse: true, data: kvs.map(k => k.key), ...axisStyle, axisLabel: {color: '#7d8db0', fontSize: 11, width: 150, overflow: 'truncate'}},
    series: [{type: 'bar', data: kvs.map(k => k.count), barMaxWidth: 14,
      itemStyle: {borderRadius: [0, 6, 6, 0], color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{offset: 0, color: color + '40'}, {offset: 1, color}])}}]
  };
}
function barChart(el, kvs, color) { return mkChart(el, barOpt(kvs, color)); }
const actionTag = a => ({waf: '<span class="tag red">WAF拦截</span>', resp: '<span class="tag red">响应拦截</span>', cc: '<span class="tag orange">CC限频</span>', blacklist: '<span class="tag red">黑名单</span>', geo: '<span class="tag blue">地区限制</span>', semantic: '<span class="tag blue">语义检测</span>', reputation: '<span class="tag orange">信誉封禁</span>', custom: '<span class="tag violet">自定义</span>', dynamic: '<span class="tag cyan">动态防护</span>'}[a] || esc(a));
function liveRow(d) {
  const ip = d.ip || d.client_ip;
  const geo = [d.city, d.country].filter(Boolean).map(esc).join(' / ');
  return `<tr><td class="mono">${esc(d.ts)}</td><td>${esc(d.domain)}</td><td class="mono">${esc(ip)}${geo ? `<div class="hint">${geo}</div>` : ''}</td><td>${actionTag(d.action)}</td><td class="url-cell" title="${esc(d.msg)}">${esc(d.msg)}</td></tr>`;
}
function renderLiveRows(list) {
  const tb = $('#live-body');
  tb.innerHTML = list.length ? list.map(liveRow).join('') : emptyHTML(5, '暂无攻击事件');
}

/* ---------------- 防护站点 ---------------- */
async function sites() {
  const m = $('#main');
  m.innerHTML = pageHead('防护站点', '将域名解析指向本 WAF 即可开启防护 · 多上游自动负载均衡与健康检查',
    `<button class="btn" onclick="siteForm()">${ico('plus')}添加站点</button>
     <button class="btn ghost" onclick="sites()">${ico('refresh')}刷新状态</button>`) + `
  <div class="panel" style="padding:0;overflow:hidden"><table>
  <thead><tr><th>名称</th><th>域名</th><th>上游地址</th><th>模式</th><th>CC防护</th><th>身份认证</th><th>状态</th><th>操作</th></tr></thead>
  <tbody id="site-body"></tbody></table></div>`;
  try {
    const [list, health] = await Promise.all([api('/api/sites'), api('/api/upstreams')]);
    const hmap = {};
    health.forEach(h => { hmap[h.domain] = h.targets; });
    const upCell = s => (hmap[s.domain] || []).map(t =>
      `<div><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${t.up ? '#34d399' : '#fb7185'};margin-right:6px;box-shadow:0 0 6px ${t.up ? 'rgba(52,211,153,.6)' : 'rgba(251,113,133,.6)'}"></span>${esc(t.url)}</div>`).join('') || esc(s.upstream);
    $('#site-body').innerHTML = list.length ? list.map(s => `<tr>
      <td>${esc(s.name)}</td><td class="mono">${esc(s.domain)}</td><td class="mono">${upCell(s)}</td>
      <td>${s.waf_mode === 'strict' ? '<span class="tag orange">严格</span>' : '<span class="tag blue">平衡</span>'}${s.dynamic_mode === 'block' ? ' <span class="tag cyan">动态拦截</span>' : s.dynamic_mode === 'observe' ? ' <span class="tag cyan">动态观察</span>' : ''}</td>
      <td>${s.cc_rate > 0 ? s.cc_rate + ' req/s' + (s.captcha ? ' +人机验证' : '') : '<span class="hint">关闭</span>'}</td>
      <td>${s.auth_user ? '<span class="tag on">开启</span>' : '<span class="hint">关闭</span>'}</td>
      <td>${s.enabled ? '<span class="tag on">防护中</span>' : '<span class="tag off">已停用</span>'}</td>
      <td><button class="btn ghost sm" onclick='siteForm(${JSON.stringify(s)})'>编辑</button>
          <button class="btn danger sm" onclick="delSite(${s.id},'${esc(s.domain)}')">删除</button></td>
    </tr>`).join('') : emptyHTML(8, '还没有防护站点，点击右上角添加');
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

function siteForm(s) {
  s = s || {name: '', domain: '', upstream: 'http://', enabled: true, waf_mode: 'balanced', cc_rate: 0, cc_burst: 0, captcha: false, auth_user: '', auth_pass: '', resp_detect: false, dynamic_mode: 'off', cert_pem: '', key_pem: '', http_redirect: false};
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()"><div class="modal">
  <h3>${s.id ? '编辑站点' : '添加防护站点'}</h3>
  <div class="form-grid">
    <div class="form-row"><label>站点名称</label><input id="f-name" value="${esc(s.name)}"></div>
    <div class="form-row"><label>防护域名</label><input id="f-domain" placeholder="www.example.com" value="${esc(s.domain)}"></div>
  </div>
  <div class="form-row"><label>上游地址（真实服务器，多个用逗号分隔，自动负载均衡与健康检查）</label><input id="f-upstream" placeholder="http://192.168.1.10:80, http://192.168.1.11:80" value="${esc(s.upstream)}"></div>
  <div class="form-grid">
    <div class="form-row"><label>防护模式</label><select id="f-mode">
      <option value="balanced" ${s.waf_mode === 'balanced' ? 'selected' : ''}>平衡（推荐，低误报）</option>
      <option value="strict" ${s.waf_mode === 'strict' ? 'selected' : ''}>严格（更高检出）</option></select></div>
    <div class="form-row"><label>CC 限频（req/s，0=关闭）</label><input id="f-cc" type="number" min="0" value="${s.cc_rate}"></div>
  </div>
  <div class="form-grid">
    <div class="form-row"><label>CC 突发容量</label><input id="f-burst" type="number" min="0" value="${s.cc_burst}"></div>
    <div class="form-row"><label>认证用户名（留空关闭）</label><input id="f-authu" value="${esc(s.auth_user)}"></div>
  </div>
  <div class="form-row"><label>认证密码（哈希存储，不回显）</label><input id="f-authp" type="password" value="" autocomplete="new-password" placeholder="${s.auth_user ? '留空保持原密码不变' : '设置认证密码'}"></div>
  <label class="check"><input id="f-enabled" type="checkbox" ${s.enabled ? 'checked' : ''}> 启用防护</label>
  <label class="check"><input id="f-captcha" type="checkbox" ${s.captcha ? 'checked' : ''}> CC 触发时启用人机验证（而非直接拦截）</label>
  <label class="check"><input id="f-resp" type="checkbox" ${s.resp_detect ? 'checked' : ''}> 响应内容检测（防信息泄露/网页挂马）</label>
  <div class="form-row"><label>动态防护（向页面植入混淆令牌，拦截无令牌的自动化写操作 / 重放 / CSRF）</label><select id="f-dyn">
    <option value="off" ${s.dynamic_mode !== 'observe' && s.dynamic_mode !== 'block' ? 'selected' : ''}>关闭</option>
    <option value="observe" ${s.dynamic_mode === 'observe' ? 'selected' : ''}>观察（仅记录，不拦截）</option>
    <option value="block" ${s.dynamic_mode === 'block' ? 'selected' : ''}>拦截（缺失令牌即 403）</option></select></div>
  <details class="https-box" ${s.cert_pem ? 'open' : ''}>
    <summary>HTTPS 证书配置（TLS 监听默认 :8443，按域名 SNI 匹配）</summary>
    <div class="form-row"><label>证书（PEM 格式，含证书链）</label><textarea id="f-cert" rows="4" placeholder="-----BEGIN CERTIFICATE-----">${esc(s.cert_pem || '')}</textarea></div>
    <div class="form-row"><label>私钥（PEM 格式）</label><textarea id="f-key" rows="4" placeholder="-----BEGIN PRIVATE KEY-----">${esc(s.key_pem || '')}</textarea></div>
    <label class="check"><input id="f-redirect" type="checkbox" ${s.http_redirect ? 'checked' : ''}> HTTP 自动跳转 HTTPS（301）</label>
  </details>
  <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">取消</button>
  <button class="btn" onclick="saveSite(${s.id || 0})">保存</button></div>
  </div></div>`;
}
function closeModal() { $('#modal-root').innerHTML = ''; }
async function saveSite(id) {
  const body = {
    name: $('#f-name').value.trim(), domain: $('#f-domain').value.trim(),
    upstream: $('#f-upstream').value.trim(), waf_mode: $('#f-mode').value,
    cc_rate: +$('#f-cc').value || 0, cc_burst: +$('#f-burst').value || 0,
    auth_user: $('#f-authu').value.trim(), auth_pass: $('#f-authp').value,
    enabled: $('#f-enabled').checked, captcha: $('#f-captcha').checked, resp_detect: $('#f-resp').checked,
    dynamic_mode: $('#f-dyn').value,
    cert_pem: $('#f-cert').value.trim(), key_pem: $('#f-key').value.trim(), http_redirect: $('#f-redirect').checked,
  };
  try {
    await api('/api/sites' + (id ? '/' + id : ''), {method: id ? 'PUT' : 'POST', body});
    closeModal(); toast('站点已保存'); sites();
  } catch (e) { toast(e.message, true); }
}
async function delSite(id, domain) {
  if (!confirm(`确认删除站点 ${domain}？`)) return;
  try { await api('/api/sites/' + id, {method: 'DELETE'}); toast('已删除'); sites(); }
  catch (e) { toast(e.message, true); }
}

/* ---------------- 攻击日志 ---------------- */
let logPage = 1;
let logRows = [];
async function logs() {
  const m = $('#main');
  m.innerHTML = pageHead('攻击日志', '全量攻击事件检索 · 支持一键豁免误报') + `
  <div class="toolbar">
    <input id="q-ip" placeholder="客户端 IP">
    <input id="q-domain" placeholder="站点域名">
    <select id="q-action"><option value="">全部动作</option><option value="waf">WAF拦截</option><option value="semantic">语义检测</option><option value="reputation">信誉封禁</option><option value="cc">CC限频</option><option value="blacklist">黑名单</option><option value="geo">地区限制</option><option value="resp">响应拦截</option><option value="custom">自定义规则</option><option value="dynamic">动态防护</option></select>
    <button class="btn" onclick="logPage=1;loadLogs()">${ico('search')}查询</button>
    <button class="btn ghost" onclick="exportCSV()">${ico('download')}导出 CSV</button>
    <button class="btn ghost" onclick="window.open('/api/report')">${ico('report')}导出防护报告</button>
    <button class="btn danger" onclick="clearAttackLogs()">清空日志</button>
  </div>
  <div class="panel" style="padding:0;overflow:hidden"><table>
  <thead><tr><th>时间</th><th>站点</th><th>IP</th><th>国家</th><th>城市</th><th>方法</th><th>URL</th><th>动作</th><th>描述</th><th>状态</th><th>操作</th></tr></thead>
  <tbody id="log-body"></tbody></table></div>
  <div class="pager" id="log-pager"></div>`;
  loadLogs();
}
function logQuery() {
  return `ip=${encodeURIComponent($('#q-ip').value)}&domain=${encodeURIComponent($('#q-domain').value)}&action=${encodeURIComponent($('#q-action').value)}`;
}
async function loadLogs() {
  try {
    const d = await api(`/api/logs?page=${logPage}&size=20&${logQuery()}`);
    logRows = d.list;
    $('#log-body').innerHTML = d.list.length ? d.list.map((l, i) => `<tr>
      <td class="mono">${esc(l.ts)}</td><td>${esc(l.domain)}</td><td class="mono">${esc(l.client_ip)}</td>
      <td>${esc(l.country || '-')}</td><td>${esc(l.city || '-')}</td><td>${esc(l.method)}</td>
      <td class="mono url-cell" title="${esc(l.url)}">${esc(l.url)}</td>
      <td>${actionTag(l.action)}</td><td class="url-cell" title="${esc(l.msg)}">${esc(l.msg)}</td>
      <td class="mono">${l.status}</td>
      <td>${l.rule_id > 0 && (l.action === 'waf' || l.action === 'resp' || l.action === 'semantic') ? `<button class="btn ghost sm" onclick="exclFromLog(${i})">豁免</button>` : ''}</td></tr>`).join('')
      : emptyHTML(11, '暂无记录');
    const pages = Math.max(1, Math.ceil(d.total / d.size));
    $('#log-pager').innerHTML = `共 ${d.total} 条 · ${logPage}/${pages} 页
      <button class="btn ghost sm" ${logPage <= 1 ? 'disabled' : ''} onclick="logPage--;loadLogs()">上一页</button>
      <button class="btn ghost sm" ${logPage >= pages ? 'disabled' : ''} onclick="logPage++;loadLogs()">下一页</button>`;
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
function exportCSV() { window.open('/api/logs/export?' + logQuery()); }
async function clearAttackLogs() {
  if (!confirm('确认清空全部攻击日志？此操作不可撤销（审计日志与生效中的信誉封禁不受影响）。')) return;
  try {
    const d = await api('/api/logs', {method: 'DELETE'});
    toast(`已清空 ${d.deleted} 条攻击日志`);
    logPage = 1;
    loadLogs();
  } catch (e) { toast(e.message, true); }
}

/* ---------------- 规则调优（误报豁免） ---------------- */
let pendingExcl = null;
let exclSites = [];
async function tuning() {
  const m = $('#main');
  m.innerHTML = pageHead('规则调优', '对误报规则按站点 / URL 前缀 / 参数精细豁免，修改即时生效',
    `<button class="btn" onclick="exclForm()">${ico('plus')}添加豁免</button>`) + `
  <div class="panel" style="padding:0;overflow:hidden"><table>
  <thead><tr><th>作用站点</th><th>规则 ID</th><th>URL 前缀</th><th>参数</th><th>备注</th><th>添加时间</th><th>操作</th></tr></thead>
  <tbody id="excl-body"></tbody></table></div>
  <p class="hint" style="margin-top:10px">URL 前缀与参数均为空 = 整站（或全局）豁免该规则；填写参数则仅豁免该参数上的命中。可在攻击日志中点击「豁免」快速创建。</p>`;
  try {
    const [list, sites] = await Promise.all([api('/api/exclusions'), api('/api/sites')]);
    exclSites = sites;
    const nameOf = id => id === 0 ? '<span class="tag orange">全局</span>' : esc((sites.find(s => s.id === id) || {}).domain || ('站点#' + id));
    $('#excl-body').innerHTML = list.length ? list.map(e => `<tr>
      <td>${nameOf(e.site_id)}</td><td class="mono">${e.rule_id}</td>
      <td class="mono">${esc(e.url_prefix || '全部路径')}</td><td class="mono">${esc(e.param || '全部参数')}</td>
      <td>${esc(e.note || '-')}</td><td class="mono">${esc(e.created_at)}</td>
      <td><button class="btn danger sm" onclick="delExcl(${e.id})">删除</button></td></tr>`).join('')
      : emptyHTML(7, '暂无豁免规则');
    if (pendingExcl) { const p = pendingExcl; pendingExcl = null; exclForm(p); }
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
function exclFromLog(i) {
  const l = logRows[i];
  if (!l) return;
  pendingExcl = {site_id: l.site_id, rule_id: l.rule_id, url_prefix: (l.url || '').split('?')[0], param: '', note: l.msg || ''};
  if ((location.hash.replace('#/', '') || 'dashboard').split('?')[0] === 'tuning') {
    const p = pendingExcl; pendingExcl = null; exclForm(p);
  } else location.hash = '#/tuning';
}
function exclForm(e) {
  e = e || {site_id: 0, rule_id: '', url_prefix: '', param: '', note: ''};
  const opts = ['<option value="0">全局（所有站点）</option>'].concat(
    exclSites.map(s => `<option value="${s.id}" ${e.site_id === s.id ? 'selected' : ''}>${esc(s.domain)}</option>`)).join('');
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()"><div class="modal">
  <h3>添加规则豁免</h3>
  <div class="form-grid">
    <div class="form-row"><label>作用站点</label><select id="x-site">${opts}</select></div>
    <div class="form-row"><label>规则 ID（攻击日志中的规则编号）</label><input id="x-rule" type="number" min="1" value="${e.rule_id || ''}" placeholder="如 942100"></div>
  </div>
  <div class="form-row"><label>URL 前缀（留空 = 全部路径）</label><input id="x-prefix" value="${esc(e.url_prefix || '')}" placeholder="/api/upload"></div>
  <div class="form-row"><label>参数名（留空 = 全部参数；仅作用于 URL 参数）</label><input id="x-param" value="${esc(e.param || '')}" placeholder="content"></div>
  <div class="form-row"><label>备注</label><input id="x-note" value="${esc(e.note || '')}" placeholder="误报原因说明"></div>
  <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">取消</button>
  <button class="btn" onclick="saveExcl()">保存</button></div>
  </div></div>`;
}
async function saveExcl() {
  const body = {
    site_id: +$('#x-site').value || 0, rule_id: +$('#x-rule').value || 0,
    url_prefix: $('#x-prefix').value.trim(), param: $('#x-param').value.trim(), note: $('#x-note').value.trim(),
  };
  if (!body.rule_id) return toast('请填写规则 ID', true);
  try {
    await api('/api/exclusions', {method: 'POST', body});
    closeModal(); toast('豁免已生效'); tuning();
  } catch (e) { toast(e.message, true); }
}
async function delExcl(id) {
  if (!confirm('确认删除该豁免？删除后对应规则将恢复拦截。')) return;
  try { await api('/api/exclusions/' + id, {method: 'DELETE'}); toast('已删除'); tuning(); }
  catch (e) { toast(e.message, true); }
}

/* ---------------- 黑白名单 ---------------- */
let ipKind = 'black';
async function ips() {
  const m = $('#main');
  m.innerHTML = pageHead('黑白名单', '白名单优先于黑名单 · 白名单 IP 跳过全部检测 · 修改即时生效') + `
  <div class="toolbar">
    <div class="seg">
      <button class="btn ${ipKind === 'black' ? 'on' : ''}" onclick="ipKind='black';ips()">黑名单</button>
      <button class="btn ${ipKind === 'white' ? 'on' : ''}" onclick="ipKind='white';ips()">白名单</button>
    </div>
    <span style="flex:1"></span>
    <input id="ip-val" placeholder="IP 或 CIDR，如 1.2.3.4 或 10.0.0.0/8">
    <input id="ip-note" placeholder="备注">
    <input id="ip-exp" placeholder="过期时间 2026-12-31 00:00:00（可空）" style="min-width:230px">
    <button class="btn" onclick="addIP()">${ico('plus')}添加</button>
  </div>
  <div class="panel" style="padding:0;overflow:hidden"><table>
  <thead><tr><th>IP / 网段</th><th>备注</th><th>过期时间</th><th>添加时间</th><th>操作</th></tr></thead>
  <tbody id="ip-body"></tbody></table></div>`;
  try {
    const list = await api('/api/ips?kind=' + ipKind);
    $('#ip-body').innerHTML = list.length ? list.map(e => `<tr>
      <td class="mono">${esc(e.ip)}</td><td>${esc(e.note || '-')}</td>
      <td class="mono">${esc(e.expires_at || '永久')}</td><td class="mono">${esc(e.created_at)}</td>
      <td><button class="btn danger sm" onclick="delIP(${e.id})">删除</button></td></tr>`).join('')
      : emptyHTML(5, '暂无条目');
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
async function addIP() {
  const ip = $('#ip-val').value.trim();
  if (!ip) return toast('请输入 IP', true);
  try {
    await api('/api/ips', {method: 'POST', body: {kind: ipKind, ip, note: $('#ip-note').value, expires_at: $('#ip-exp').value.trim()}});
    toast('已添加'); ips();
  } catch (e) { toast(e.message, true); }
}
async function delIP(id) {
  try { await api('/api/ips/' + id, {method: 'DELETE'}); toast('已删除'); ips(); }
  catch (e) { toast(e.message, true); }
}

/* ---------------- 自定义规则（条件匹配 + 动作编排） ---------------- */
let ruleSites = [];
let ruleCache = [];
const FIELD_LABEL = {ip: 'IP', path: '路径', url: 'URL', method: '方法', header: '请求头', param: '参数', country: '地域'};
const OP_LABEL = {eq: '等于', ne: '不等于', contains: '包含', prefix: '前缀', suffix: '后缀', regex: '正则', cidr: '网段', in: '属于'};
const ruleActionTag = a => ({allow: '<span class="tag green">放行</span>', block: '<span class="tag red">拦截</span>', captcha: '<span class="tag orange">人机验证</span>', log: '<span class="tag blue">观察</span>', redirect: '<span class="tag violet">重定向</span>'}[a] || esc(a));
function condSummary(r) {
  let cs = []; try { cs = JSON.parse(r.conditions || '[]'); } catch {}
  const joiner = r.logic === 'or' ? ' 或 ' : ' 且 ';
  return cs.map(c => `${FIELD_LABEL[c.field] || c.field}${c.name ? '[' + c.name + ']' : ''} ${OP_LABEL[c.op] || c.op} ${c.value}`).join(joiner) || '无条件';
}
async function rules() {
  const m = $('#main');
  m.innerHTML = pageHead('自定义规则', '按 IP/路径/URL/方法/请求头/参数/地域精细匹配 · 放行/拦截/人机验证/观察/重定向',
    `<button class="btn" onclick="ruleForm()">${ico('plus')}添加规则</button>`) + `
  <div class="panel" style="padding:0;overflow:hidden"><table>
  <thead><tr><th>名称</th><th>作用站点</th><th>优先级</th><th>匹配条件</th><th>动作</th><th>状态</th><th>操作</th></tr></thead>
  <tbody id="rule-body"></tbody></table></div>
  <p class="hint" style="margin-top:10px">规则按优先级升序评估，命中即执行动作。放行=跳过 WAF 检测；拦截=403；人机验证=JS 挑战；观察=仅记录；重定向=302（仅站内路径或 http(s) 地址）。自定义规则在黑名单/信誉/地域策略之后、CC/认证/WAF 之前生效。</p>`;
  try {
    const [list, sites] = await Promise.all([api('/api/rules'), api('/api/sites')]);
    ruleSites = sites; ruleCache = list;
    const nameOf = id => id === 0 ? '<span class="tag orange">全局</span>' : esc((sites.find(s => s.id === id) || {}).domain || ('站点#' + id));
    $('#rule-body').innerHTML = list.length ? list.map(r => `<tr>
      <td>${esc(r.name)}</td><td>${nameOf(r.site_id)}</td><td class="mono">${r.priority}</td>
      <td class="url-cell" title="${esc(condSummary(r))}">${esc(condSummary(r))}</td>
      <td>${ruleActionTag(r.action)}</td>
      <td>${r.enabled ? '<span class="tag on">启用</span>' : '<span class="tag off">停用</span>'}</td>
      <td><button class="btn ghost sm" onclick="editRule(${r.id})">编辑</button>
          <button class="btn danger sm" onclick="delRule(${r.id})">删除</button></td></tr>`).join('')
      : emptyHTML(7, '暂无自定义规则');
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
function editRule(id) { const r = ruleCache.find(x => x.id === id); if (r) ruleForm(r); }
function condRowHTML(c) {
  c = c || {field: 'path', op: 'prefix', value: '', name: ''};
  const fopts = Object.keys(FIELD_LABEL).map(f => `<option value="${f}" ${c.field === f ? 'selected' : ''}>${FIELD_LABEL[f]}</option>`).join('');
  const oopts = Object.keys(OP_LABEL).map(o => `<option value="${o}" ${c.op === o ? 'selected' : ''}>${OP_LABEL[o]}</option>`).join('');
  const showName = c.field === 'header' || c.field === 'param';
  return `<div class="cond-row toolbar" style="margin-bottom:6px">
    <select class="c-field" onchange="condFieldChange(this)" style="width:90px">${fopts}</select>
    <select class="c-op" style="width:96px">${oopts}</select>
    <input class="c-name" placeholder="名称" value="${esc(c.name || '')}" style="width:110px;${showName ? '' : 'display:none'}">
    <input class="c-value" placeholder="值" value="${esc(c.value || '')}" style="flex:1;min-width:120px">
    <button class="btn danger sm" type="button" onclick="this.closest('.cond-row').remove()">×</button>
  </div>`;
}
function addCondRow() { $('#r-conds').insertAdjacentHTML('beforeend', condRowHTML()); }
function condFieldChange(sel) {
  const show = sel.value === 'header' || sel.value === 'param';
  sel.closest('.cond-row').querySelector('.c-name').style.display = show ? '' : 'none';
}
function toggleActionParam() {
  const a = $('#r-action').value, row = $('#r-param-row'), label = $('#r-param-label');
  if (a === 'redirect') { row.style.display = ''; label.textContent = '重定向目标（/ 站内路径或 http(s) 地址）'; }
  else if (a === 'block') { row.style.display = ''; label.textContent = '拦截原因（可选）'; }
  else { row.style.display = 'none'; }
}
function ruleForm(r) {
  r = r || {name: '', site_id: 0, priority: 100, logic: 'and', conditions: '[]', action: 'block', action_param: '', enabled: true, note: ''};
  let cs = []; try { cs = JSON.parse(r.conditions || '[]'); } catch {}
  if (!cs.length) cs = [{field: 'path', op: 'prefix', value: '', name: ''}];
  const opts = ['<option value="0">全局（所有站点）</option>'].concat(
    ruleSites.map(s => `<option value="${s.id}" ${r.site_id === s.id ? 'selected' : ''}>${esc(s.domain)}</option>`)).join('');
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()"><div class="modal">
  <h3>${r.id ? '编辑自定义规则' : '添加自定义规则'}</h3>
  <div class="form-grid">
    <div class="form-row"><label>规则名称</label><input id="r-name" value="${esc(r.name)}"></div>
    <div class="form-row"><label>作用站点</label><select id="r-site">${opts}</select></div>
  </div>
  <div class="form-grid">
    <div class="form-row"><label>优先级（越小越先）</label><input id="r-priority" type="number" min="0" max="100000" value="${r.priority}"></div>
    <div class="form-row"><label>条件逻辑</label><select id="r-logic">
      <option value="and" ${r.logic !== 'or' ? 'selected' : ''}>全部满足（AND）</option>
      <option value="or" ${r.logic === 'or' ? 'selected' : ''}>任一满足（OR）</option></select></div>
  </div>
  <div class="form-row"><label>匹配条件</label><div id="r-conds">${cs.map(condRowHTML).join('')}</div>
    <button class="btn ghost sm" type="button" onclick="addCondRow()" style="margin-top:8px">${ico('plus')}添加条件</button></div>
  <div class="form-grid">
    <div class="form-row"><label>动作</label><select id="r-action" onchange="toggleActionParam()">
      <option value="block" ${r.action === 'block' ? 'selected' : ''}>拦截（403）</option>
      <option value="allow" ${r.action === 'allow' ? 'selected' : ''}>放行（跳过检测）</option>
      <option value="captcha" ${r.action === 'captcha' ? 'selected' : ''}>人机验证</option>
      <option value="log" ${r.action === 'log' ? 'selected' : ''}>观察（仅记录）</option>
      <option value="redirect" ${r.action === 'redirect' ? 'selected' : ''}>重定向（302）</option></select></div>
    <div class="form-row" id="r-param-row"><label id="r-param-label">拦截原因（可选）</label><input id="r-param" value="${esc(r.action_param || '')}"></div>
  </div>
  <label class="check"><input id="r-enabled" type="checkbox" ${r.enabled ? 'checked' : ''}> 启用规则</label>
  <div class="form-row"><label>备注</label><input id="r-note" value="${esc(r.note || '')}"></div>
  <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">取消</button>
  <button class="btn" onclick="saveRule(${r.id || 0})">保存</button></div>
  </div></div>`;
  toggleActionParam();
}
async function saveRule(id) {
  const conds = [...document.querySelectorAll('#r-conds .cond-row')].map(row => ({
    field: row.querySelector('.c-field').value, op: row.querySelector('.c-op').value,
    name: row.querySelector('.c-name').value.trim(), value: row.querySelector('.c-value').value,
  })).filter(c => c.value !== '' || c.op === 'eq' || c.op === 'ne');
  if (!conds.length) return toast('请至少填写一个有效匹配条件', true);
  const body = {
    name: $('#r-name').value.trim(), site_id: +$('#r-site').value || 0,
    priority: +$('#r-priority').value || 0, logic: $('#r-logic').value,
    conditions: JSON.stringify(conds), action: $('#r-action').value,
    action_param: $('#r-param').value.trim(), enabled: $('#r-enabled').checked, note: $('#r-note').value.trim(),
  };
  if (!body.name) return toast('请填写规则名称', true);
  try {
    await api('/api/rules' + (id ? '/' + id : ''), {method: id ? 'PUT' : 'POST', body});
    closeModal(); toast('规则已保存，即时生效'); rules();
  } catch (e) { toast(e.message, true); }
}
async function delRule(id) {
  if (!confirm('确认删除该自定义规则？')) return;
  try { await api('/api/rules/' + id, {method: 'DELETE'}); toast('已删除'); rules(); }
  catch (e) { toast(e.message, true); }
}

/* ---------------- IP 信誉（本地攻击历史自动封禁） ---------------- */
let repTimer = null;
const pad2 = n => String(n).padStart(2, '0');
const fmtNow = () => { const d = new Date(); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`; };
async function reputation() {
  if (repTimer) { clearInterval(repTimer); repTimer = null; }
  const m = $('#main');
  m.innerHTML = pageHead('IP 信誉', '本地攻击历史加权评分 · 超阈值自动封禁 · 白名单优先 · 封禁时长逐次递增',
    `<button class="btn ghost" onclick="loadRep()">${ico('refresh')}刷新</button>`) + `
  <div class="panel"><h3>信誉评分配置</h3>
    <div class="toolbar">
      <label class="hint">状态</label>
      <select id="rep-enabled"><option value="on">启用</option><option value="off">关闭</option></select>
      <label class="hint">统计窗口</label><input id="rep-window" type="number" min="1" max="168" style="width:70px"> 小时
      <label class="hint">封禁阈值</label><input id="rep-threshold" type="number" min="1" style="width:80px"> 分
      <label class="hint">首次封禁</label><input id="rep-ttl" type="number" min="1" style="width:80px"> 分钟
      <label class="hint">封禁上限</label><input id="rep-maxttl" type="number" min="1" style="width:90px"> 分钟
      <button class="btn" onclick="saveRepConfig()">保存</button>
    </div>
    <p class="hint">评分权重：CRITICAL×3 / WARNING×2 / 其它×1，仅统计真实攻击检测（WAF/响应/CC/语义），不含处置动作。达到阈值自动封禁，重复封禁时长按 2 倍递增直至上限；白名单 IP 永不自动封禁；人工解封后赦免一个窗口期。修改即时生效。</p>
  </div>
  <div class="panel"><h3>IP 情报源</h3>
    <div class="toolbar">
      <span id="intel-geo" class="hint"></span>
      <span id="intel-idc" class="hint"></span>
      <span id="intel-tor" class="hint"></span>
      <button class="btn ghost" onclick="intelRefresh()">${ico('refresh')}刷新情报</button>
    </div>
    <p class="hint">中国城市/运营商优先来自 ip2region（data/ip2region.xdb，离线免费、精确到市），海外城市与 ASN 来自 mmdb 城市库（data/geoip_city.mmdb、geoip_asn.mmdb）；IDC 机房归属聚合主流云商公开 CIDR（每日刷新）；Tor 出口来自官方列表（每小时刷新）。情报仅作裁决参考标签，不参与自动封禁评分。</p>
    <div class="toolbar" style="margin-top:10px">
      <label class="hint">付费情报</label>
      <select id="intel-provider"><option value="off">关闭</option><option value="generic">通用 JSON 接口</option></select>
      <input id="intel-key" type="password" placeholder="API Key（Bearer）" style="min-width:180px" autocomplete="off">
      <input id="intel-url" placeholder="https://api.vendor.com/ip/{ip}" style="min-width:280px">
      <button class="btn" onclick="saveIntel()">保存</button>
      <button class="btn ghost" onclick="testIntel()">测试连通</button>
      <span id="intel-threat" class="hint"></span>
    </div>
    <p class="hint">可选接入第三方威胁情报（代理/VPN/Tor/僵尸网络/扫描器等标签）。通用接口需返回 JSON，URL 用 <code>{ip}</code> 占位待查 IP，密钥以 Bearer 头发送；识别 proxy/vpn/tor/botnet/malicious/scanner/hosting 等布尔字段与 tags 数组、threat_score/risk_score 评分。默认关闭，零密钥可运行；结果按 IP 缓存 24 小时。仅作展示标签，不参与自动封禁。</p>
    <div id="intel-test-result"></div>
  </div>
  <div class="panel"><h3>IP 裁决查询</h3>
    <div class="toolbar">
      <input id="rep-lookup-ip" placeholder="输入 IP，如 1.2.3.4" style="min-width:220px">
      <button class="btn" onclick="repLookup()">${ico('search')}查询</button>
    </div>
    <div id="rep-lookup-result"></div>
  </div>
  <div class="panel" style="padding:0;overflow:hidden"><table>
  <thead><tr><th>IP</th><th>评分</th><th>封禁次数</th><th>状态</th><th>封禁到期</th><th>原因</th><th>操作</th></tr></thead>
  <tbody id="rep-body"></tbody></table></div>`;
  try {
    const s = await api('/api/settings');
    $('#rep-enabled').value = s.reputation_enabled || 'on';
    $('#rep-window').value = s.rep_window || 24;
    $('#rep-threshold').value = s.rep_threshold || 30;
    $('#rep-ttl').value = s.rep_ban_ttl || 60;
    $('#rep-maxttl').value = s.rep_max_ttl || 1440;
    $('#intel-provider').value = s.intel_provider || 'off';
    $('#intel-key').value = s.intel_api_key || '';
    $('#intel-url').value = s.intel_api_url || '';
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
  loadRep();
  loadIntel();
  repTimer = setInterval(loadRep, 10000);
}
async function loadIntel() {
  const g = $('#intel-geo'), idc = $('#intel-idc'), tor = $('#intel-tor');
  if (!g) return;
  try {
    const s = await api('/api/intel/status');
    const dot = ok => ok ? '<span class="tag green">已加载</span>' : '<span class="tag">未加载</span>';
    g.innerHTML = `地理 ${dot(s.geo_country)} 城市 ${dot(s.geo_city)} ASN ${dot(s.geo_asn)} ip2region ${dot(s.geo_xdb)}`;
    idc.innerHTML = `IDC CIDR <b>${s.idc.count}</b> 条 · ${esc(s.idc.source)} · ${esc(s.idc.updated)}`;
    tor.innerHTML = `Tor 出口 <b>${s.tor.count}</b> 个 · ${esc(s.tor.source)} · ${esc(s.tor.updated)}`;
    const th = $('#intel-threat');
    if (th && s.threat) th.innerHTML = s.threat.enabled
      ? `<span class="tag green">付费情报已启用</span> 缓存 ${s.threat.cache_size} 条`
      : '<span class="tag">付费情报未启用</span>';
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
async function saveIntel() {
  try {
    await api('/api/settings', {method: 'PUT', body: {
      intel_provider: $('#intel-provider').value,
      intel_api_key: $('#intel-key').value,
      intel_api_url: $('#intel-url').value.trim(),
    }});
    toast('付费情报配置已保存，即时生效'); loadIntel();
  } catch (e) { toast(e.message, true); }
}
async function testIntel() {
  const box = $('#intel-test-result');
  const ip = ($('#rep-lookup-ip').value.trim()) || '8.8.8.8';
  box.innerHTML = '<div class="hint" style="margin-top:8px">测试中…</div>';
  try {
    const d = await api('/api/intel/test?ip=' + encodeURIComponent(ip), {method: 'POST'});
    if (!d.enabled) { box.innerHTML = `<div class="hint" style="margin-top:8px">${esc(d.message || '付费情报未启用，请先选择接口并填写密钥与 URL')}</div>`; return; }
    const tags = (d.tags && d.tags.length) ? d.tags.map(t => `<span class="tag orange">${esc(t)}</span>`).join(' ') : '<span class="tag blue">无威胁标签</span>';
    box.innerHTML = `<div class="toolbar" style="margin-top:8px"><span class="mono"><b>${esc(d.ip)}</b></span><span class="tag green">${esc(d.provider)}</span>${tags}<span class="hint">评分 ${d.score}</span></div>`;
  } catch (e) { box.innerHTML = ''; toast(e.message, true); }
}
async function intelRefresh() {
  try {
    await api('/api/intel/refresh', {method: 'POST'});
    toast('情报刷新已触发，后台拉取中…');
    setTimeout(loadIntel, 4000);
  } catch (e) { toast(e.message, true); }
}
async function loadRep() {
  const tb = $('#rep-body');
  if (!tb) return;
  try {
    const list = await api('/api/reputation');
    const now = fmtNow();
    tb.innerHTML = list.length ? list.map(r => {
      const banned = r.banned_until && r.banned_until > now;
      const pardoned = r.pardoned_until && r.pardoned_until > now;
      const st = banned ? '<span class="tag red">封禁中</span>' : pardoned ? '<span class="tag green">已赦免</span>' : '<span class="tag blue">观察</span>';
      return `<tr>
        <td class="mono">${esc(r.ip)}</td>
        <td class="mono"><b>${r.score}</b></td>
        <td class="mono">${r.ban_count}</td>
        <td>${st}</td>
        <td class="mono">${esc(r.banned_until || '-')}</td>
        <td class="url-cell" title="${esc(r.reason)}">${esc(r.reason || '-')}</td>
        <td style="white-space:nowrap">
          ${banned ? `<button class="btn ghost sm" onclick="repUnban('${esc(r.ip)}')">解封</button>` : ''}
          <button class="btn ghost sm" onclick="repWhitelist('${esc(r.ip)}')">加白</button>
        </td></tr>`;
    }).join('') : emptyHTML(7, '暂无评分记录');
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
async function saveRepConfig() {
  try {
    await api('/api/settings', {method: 'PUT', body: {
      reputation_enabled: $('#rep-enabled').value,
      rep_window: $('#rep-window').value,
      rep_threshold: $('#rep-threshold').value,
      rep_ban_ttl: $('#rep-ttl').value,
      rep_max_ttl: $('#rep-maxttl').value,
    }});
    toast('信誉配置已保存，即时生效'); loadRep();
  } catch (e) { toast(e.message, true); }
}
async function repLookup() {
  const ip = $('#rep-lookup-ip').value.trim();
  if (!ip) return toast('请输入 IP', true);
  const box = $('#rep-lookup-result');
  try {
    const d = await api('/api/reputation/lookup?ip=' + encodeURIComponent(ip));
    const r = d.reputation;
    const flags = [
      d.whitelisted ? '<span class="tag green">白名单</span>' : '',
      d.blacklisted ? '<span class="tag red">黑名单</span>' : '',
      d.banned ? '<span class="tag red">自动封禁中</span>' : '',
      d.idc ? `<span class="tag orange">IDC · ${esc(d.idc)}</span>` : '',
      d.tor ? '<span class="tag red">Tor 出口</span>' : '',
      ...(d.threat_tags || []).map(t => `<span class="tag orange">${esc(t)}</span>`),
    ].filter(Boolean).join(' ') || '<span class="tag blue">无特殊标记</span>';
    const geo = [d.country, d.region, d.city].filter(Boolean).map(esc).join(' / ') || '未知';
    const asn = d.asn ? `AS${d.asn} ${esc(d.asn_org || '')}` : '未知';
    const isp = d.isp ? ` · ${esc(d.isp)}` : '';
    const threat = d.threat_provider ? `<div class="hint">付费情报 ${esc(d.threat_provider)} · 威胁评分 ${d.threat_score} · 标签 ${(d.threat_tags || []).map(esc).join(', ') || '无'}</div>` : '';
    box.innerHTML = `<div style="margin-top:12px;display:flex;flex-direction:column;gap:8px">
      <div class="toolbar"><span class="mono"><b>${esc(d.ip)}</b></span>${flags}</div>
      <div class="hint">地理 ${geo}${isp} · ASN ${asn} · 累计攻击 ${d.attack_count} 次</div>
      ${threat}
      ${r ? `<div class="hint">评分 ${r.score} · 封禁 ${r.ban_count} 次 · 到期 ${esc(r.banned_until || '-')} · 赦免至 ${esc(r.pardoned_until || '-')}</div>` : '<div class="hint">暂无信誉记录</div>'}
    </div>`;
  } catch (e) { box.innerHTML = ''; toast(e.message, true); }
}
async function repUnban(ip) {
  try { await api('/api/reputation/' + encodeURIComponent(ip), {method: 'DELETE'}); toast('已解封 ' + ip); loadRep(); }
  catch (e) { toast(e.message, true); }
}
async function repWhitelist(ip) {
  try { await api('/api/ips', {method: 'POST', body: {kind: 'white', ip, note: '信誉赦免加白'}}); toast('已加入白名单 ' + ip); loadRep(); }
  catch (e) { toast(e.message, true); }
}

/* ---------------- 安全设置 ---------------- */
async function settings() {
  const m = $('#main');
  m.innerHTML = pageHead('安全设置', '语义检测引擎 · GeoIP 地域策略 · 拦截页定制 · 日志保留与账户安全') + `
  <div class="panel"><h3>语义检测引擎（抗混淆绕过）</h3>
    <div class="toolbar">
      <select id="sem-mode"><option value="observe">观察模式（仅记录，不拦截）</option><option value="block">拦截模式</option><option value="off">关闭</option></select>
      <button class="btn" onclick="saveSemantic()">保存</button>
    </div>
    <p class="hint">对请求做递归解码 / 全角还原 / JS 转义还原 / 注释折叠 / Base64 还原后，进行 SQL 语法级、XSS 上下文级、文件包含/SSRF 与代码注入评分，可识别双重编码、全角字符、注释分隔等 CRS 易漏报的混淆载荷。建议先以观察模式运行，在攻击日志中确认无误报后再切换拦截模式；命中规则 100200-100203 支持规则调优豁免。</p>
  </div>
  <div class="panel"><h3>地理位置访问控制（GeoIP）</h3>
    <div class="toolbar">
      <select id="geo-mode"><option value="off">关闭</option><option value="block">禁止指定国家/地区访问</option><option value="allow">仅允许指定国家/地区访问</option></select>
      <input id="geo-countries" placeholder="国家代码，逗号分隔，如 CN,US,JP" style="min-width:280px">
      <button class="btn" onclick="saveGeo()">保存</button>
      <span id="geo-status" class="hint"></span>
    </div>
    <p class="hint">需要将 mmdb 格式的 GeoIP 数据库文件放置于 data/geoip.mmdb 后重启。ip2region.xdb 仅补充城市展示，地域限制策略仍以 mmdb 国家库（ISO 码）为准。</p>
  </div>
  <div class="panel"><h3>可信代理（真实客户端 IP 解析）</h3>
    <div class="toolbar">
      <input id="trusted-proxies" placeholder="可信代理 IP/CIDR，逗号分隔，如 10.0.0.0/8,192.168.1.5" style="min-width:320px">
      <button class="btn" onclick="saveTrusted()">保存</button>
    </div>
    <p class="hint">仅当 WAF 部署在反向代理/负载均衡之后时填写上游代理地址。留空（默认）则忽略 X-Forwarded-For / X-Real-IP，一律以直连 IP 为准，防止客户端伪造 IP 绕过黑名单/白名单/信誉/地域策略；填写后从右向左跳过可信代理，取首个不可信 IP 作为真实客户端。</p>
  </div>
  <div class="panel"><h3>告警通知（攻击激增推送）</h3>
    <div class="toolbar">
      <select id="alert-enabled"><option value="off">关闭</option><option value="on">启用</option></select>
      <label class="hint">阈值</label><input id="alert-threshold" type="number" min="1" style="width:80px"> 次
      <label class="hint">窗口</label><input id="alert-window" type="number" min="10" style="width:70px"> 秒
      <label class="hint">冷却</label><input id="alert-cooldown" type="number" min="10" style="width:80px"> 秒
    </div>
    <div class="form-row"><label>通用 Webhook（POST JSON）</label><input id="alert-webhook" placeholder="https://example.com/hook" style="width:100%"></div>
    <div class="form-grid">
      <div class="form-row"><label>钉钉机器人 Webhook</label><input id="alert-dingtalk" placeholder="https://oapi.dingtalk.com/robot/send?access_token=..." style="width:100%"></div>
      <div class="form-row"><label>企业微信机器人 Webhook</label><input id="alert-wecom" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." style="width:100%"></div>
    </div>
    <div style="margin-top:12px;display:flex;gap:10px"><button class="btn" onclick="saveAlert()">保存</button>
    <button class="btn ghost" onclick="testAlert()">发送测试</button></div>
    <p class="hint">启用后，窗口内攻击事件数达到阈值即向已配置通道推送告警，冷却期内不重复发送。钉钉/企业微信填群机器人 Webhook；通用 Webhook 接收 {event,message,count,window,threshold,ts} JSON。修改即时生效。</p>
  </div>
  <div class="panel"><h3>ACME 自动证书（Let's Encrypt）</h3>
    <div class="toolbar">
      <select id="acme-enabled"><option value="off">关闭</option><option value="on">启用</option></select>
      <select id="acme-staging"><option value="on">测试 CA（staging，不触发速率限制）</option><option value="off">生产 CA（受信任证书）</option></select>
      <button class="btn" onclick="saveACME()">保存</button>
    </div>
    <div class="form-row"><label>域名（逗号分隔，需公网解析到本机）</label><input id="acme-domains" placeholder="www.example.com,example.com" style="width:100%"></div>
    <div class="form-row"><label>联系邮箱（证书到期通知）</label><input id="acme-email" placeholder="admin@example.com" style="width:100%"></div>
    <p class="hint">启用后自动向 Let's Encrypt 申请并续期证书，缓存于 data/acme。要求域名公网解析到本服务器，且 80（HTTP-01）或 443（TLS-ALPN-01）端口可被 Let's Encrypt 访问；内网/无公网域名无法签发。首次启用需重启以监听 :80（-acme-http 可改地址）。建议先用测试 CA 联调，确认无误再切生产 CA。已手动配置证书的站点优先使用手动证书。</p>
  </div>
  <div class="panel"><h3>Prometheus 指标</h3>
    <div class="toolbar">
      <input id="metrics-token" placeholder="抓取令牌（留空仅允许本机 127.0.0.1 访问）" style="min-width:340px">
      <button class="btn" onclick="saveMetrics()">保存</button>
      <button class="btn ghost" onclick="copyScrape()">复制抓取配置</button>
    </div>
    <p class="hint">抓取端点 <code>/metrics</code>（管理端口，默认 9443）。设置令牌后 Prometheus 需携带 <code>Authorization: Bearer &lt;令牌&gt;</code>；留空则仅允许环回地址访问，防止站点/上游拓扑泄露。指标含请求量与时延直方图、攻击计数、上游健康、信誉封禁数、响应字节与 Go 运行时。</p>
  </div>
  <div class="panel"><h3>自定义拦截页面</h3>
    <p class="hint" style="margin-bottom:10px">支持占位符：{{REQ_ID}} {{REASON}} {{CLIENT_IP}} {{DOMAIN}} {{TIME}} {{RULE_ID}}，留空使用默认页面。</p>
    <textarea id="block-page" style="width:100%;min-height:180px;font-family:var(--mono);font-size:12px"></textarea>
    <div style="margin-top:12px;display:flex;gap:10px"><button class="btn" onclick="saveBlockPage()">保存</button>
    <button class="btn ghost" onclick="previewBlock()">预览</button></div>
  </div>
  <div class="grid2">
    <div class="panel"><h3>日志保留</h3>
      <div class="toolbar"><input id="retention" type="number" min="1" style="width:100px"> 天
      <button class="btn" onclick="saveRetention()">保存</button></div>
    </div>
    <div class="panel"><h3>修改管理密码</h3>
      <div class="form-row"><input id="pw-old" type="password" placeholder="原密码" style="width:100%"></div>
      <div class="form-row"><input id="pw-new" type="password" placeholder="新密码（至少 8 位，含字母和数字）" style="width:100%"></div>
      <button class="btn" onclick="changePass()">修改密码</button>
    </div>
  </div>
  <div class="panel"><h3>请求体检查上限（内存 / 安全权衡）</h3>
    <div class="toolbar">
      <label class="hint">上限</label><input id="body-inspect-kb" type="number" min="64" max="102400" style="width:120px"> KB
      <button class="btn" onclick="saveBodyInspect()">保存</button>
    </div>
    <p class="hint">WAF 检测请求体时缓冲的上限（默认 2048 KB = 2MB）。超过上限的请求体不再整体缓冲，改为流式透传并仅检测前缀，以约束单请求内存占用、避免大文件上传被静默截断。调大可提升超大请求体的检测覆盖但增加内存压力，调小更省内存。范围 64–102400 KB，修改即时生效。</p>
  </div>
  <div class="panel"><h3>请求体送检上限（CPU / 检测覆盖权衡）</h3>
    <div class="toolbar">
      <label class="hint">送检</label><input id="body-scan-kb" type="number" min="16" max="1024" style="width:120px"> KB
      <button class="btn" onclick="saveBodyScan()">保存</button>
    </div>
    <p class="hint">实际交给检测引擎的请求体前缀长度（默认 16 KB，范围 16–1024 KB）。规则集对请求体做正则扫描，成本约每 16 KB 耗 70 毫秒 CPU，因此该值决定单请求检测的 CPU 上界，可防止大请求体被用作低成本拒绝服务。二进制 Content-Type（镜像层/压缩包/音视频等）自动跳过扫体。超出送检上限的部分原样转发给上游、不做内容检测；实际送检量 = min(检查上限, 送检上限)。发生截断时自动豁免 200002/200003 两条“请求体解析完整性”规则，避免正常大文件上传被误判为 400。修改即时生效。</p>
  </div>
  <div class="panel"><h3>允许的请求体 Content-Type</h3>
    <div class="toolbar">
      <input id="allowed-ct" type="text" placeholder="例如 text/plain,application/octet-stream" style="flex:1">
      <button class="btn" onclick="saveAllowedCT()">保存</button>
    </div>
    <p class="hint">默认已允许：x-www-form-urlencoded、multipart/form-data、multipart/related、text/xml、application/xml、application/soap+xml、application/json、application/cloudevents+json、application/cloudevents-batch+json。若业务提交 text/plain 等类型请求体被拦截（规则 920420 请求体类型不受支持），在此追加即可放行该类型。逗号分隔，最多 32 项；保存会重建检测引擎（约 1 秒）并即时生效，追加的类型越多、可绕过的协议面越宽，按需最小化。</p>
  </div>
  <div class="panel"><h3>数据备份（SQLite 热备份）</h3>
    <div class="toolbar">
      <button class="btn" onclick="doBackup()">立即备份</button>
      <button class="btn ghost" onclick="loadBackups()">刷新列表</button>
      <span id="backup-status" class="hint"></span>
    </div>
    <div id="backup-list" class="hint" style="margin-top:10px"></div>
    <p class="hint">服务每 6 小时自动备份一次，保留最近 7 份，存放于 data/backups/。备份使用 VACUUM INTO 生成一致性副本，可在运行中安全执行；恢复时停止服务后用备份文件替换 data/niubwaf.db 再启动。</p>
  </div>`;
  try {
    const s = await api('/api/settings');
    $('#sem-mode').value = s.semantic_mode || 'observe';
    $('#geo-mode').value = s.geoip_mode || 'off';
    $('#geo-countries').value = s.geoip_countries || '';
    $('#geo-status').textContent = s.geoip_available === 'true' ? 'GeoIP 库已加载' : 'GeoIP 库未加载，功能不可用';
    $('#block-page').value = s.block_page || '';
    $('#trusted-proxies').value = s.trusted_proxies || '';
    $('#retention').value = s.log_retention_days || 30;
    $('#alert-enabled').value = s.alert_enabled || 'off';
    $('#alert-threshold').value = s.alert_threshold || 50;
    $('#alert-window').value = s.alert_window || 60;
    $('#alert-cooldown').value = s.alert_cooldown || 300;
    $('#alert-webhook').value = s.alert_webhook || '';
    $('#alert-dingtalk').value = s.alert_dingtalk || '';
    $('#alert-wecom').value = s.alert_wecom || '';
    $('#acme-enabled').value = s.acme_enabled || 'off';
    $('#acme-staging').value = s.acme_staging || 'on';
    $('#acme-domains').value = s.acme_domains || '';
    $('#acme-email').value = s.acme_email || '';
    $('#metrics-token').value = s.metrics_token || '';
    $('#body-inspect-kb').value = s.body_inspect_kb || 2048;
    $('#body-scan-kb').value = s.body_scan_kb || 16;
    $('#allowed-ct').value = s.allowed_content_types || '';
    loadBackups();
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
async function saveSemantic() {
  try {
    await api('/api/settings', {method: 'PUT', body: {semantic_mode: $('#sem-mode').value}});
    toast('语义引擎模式已保存，即时生效');
  } catch (e) { toast(e.message, true); }
}
async function saveGeo() {
  try {
    await api('/api/settings', {method: 'PUT', body: {geoip_mode: $('#geo-mode').value, geoip_countries: $('#geo-countries').value}});
    toast('GeoIP 策略已保存');
  } catch (e) { toast(e.message, true); }
}
async function saveTrusted() {
  try {
    await api('/api/settings', {method: 'PUT', body: {trusted_proxies: $('#trusted-proxies').value}});
    toast('可信代理已保存，即时生效');
  } catch (e) { toast(e.message, true); }
}
async function saveBodyInspect() {
  try {
    await api('/api/settings', {method: 'PUT', body: {body_inspect_kb: $('#body-inspect-kb').value}});
    toast('请求体检查上限已保存，即时生效');
  } catch (e) { toast(e.message, true); }
}
async function saveBodyScan() {
  try {
    await api('/api/settings', {method: 'PUT', body: {body_scan_kb: $('#body-scan-kb').value}});
    toast('请求体送检上限已保存，即时生效');
  } catch (e) { toast(e.message, true); }
}
async function saveAllowedCT() {
  try {
    await api('/api/settings', {method: 'PUT', body: {allowed_content_types: $('#allowed-ct').value.trim()}});
    toast('允许内容类型已保存，检测引擎已重建');
  } catch (e) { toast(e.message, true); }
}
async function doBackup() {
  try {
    const d = await api('/api/backup', {method: 'POST'});
    toast('备份已生成：' + d.name);
    loadBackups();
  } catch (e) { toast(e.message, true); }
}
async function loadBackups() {
  const el = $('#backup-list');
  if (!el) return;
  try {
    const list = await api('/api/backups');
    if (!list.length) { el.textContent = '暂无备份'; return; }
    el.innerHTML = list.map(b => `<div>${esc(b.name)} · ${(b.size / 1024).toFixed(1)} KB · ${esc(b.mtime)}</div>`).join('');
  } catch (e) { el.textContent = '加载备份列表失败：' + esc(e.message); }
}
async function saveAlert() {
  try {
    await api('/api/settings', {method: 'PUT', body: {
      alert_enabled: $('#alert-enabled').value, alert_threshold: $('#alert-threshold').value,
      alert_window: $('#alert-window').value, alert_cooldown: $('#alert-cooldown').value,
      alert_webhook: $('#alert-webhook').value.trim(), alert_dingtalk: $('#alert-dingtalk').value.trim(), alert_wecom: $('#alert-wecom').value.trim(),
    }});
    toast('告警配置已保存，即时生效');
  } catch (e) { toast(e.message, true); }
}
async function testAlert() {
  try {
    const r = await api('/api/alert/test', {method: 'POST'});
    toast('测试结果 · ' + Object.entries(r).map(([k, v]) => k + '=' + v).join(' · '));
  } catch (e) { toast(e.message, true); }
}
async function saveBlockPage() {
  try { await api('/api/settings', {method: 'PUT', body: {block_page: $('#block-page').value}}); toast('拦截页面已保存'); }
  catch (e) { toast(e.message, true); }
}
async function saveACME() {
  try {
    await api('/api/settings', {method: 'PUT', body: {
      acme_enabled: $('#acme-enabled').value, acme_staging: $('#acme-staging').value,
      acme_domains: $('#acme-domains').value.trim(), acme_email: $('#acme-email').value.trim(),
    }});
    toast('ACME 配置已保存；首次启用请重启服务以监听 :80');
  } catch (e) { toast(e.message, true); }
}
async function saveMetrics() {
  try {
    await api('/api/settings', {method: 'PUT', body: {metrics_token: $('#metrics-token').value.trim()}});
    toast('指标令牌已保存，即时生效');
  } catch (e) { toast(e.message, true); }
}
function copyScrape() {
  const token = $('#metrics-token').value.trim();
  const port = location.port || '9443';
  let cfg = `scrape_configs:\n  - job_name: niubwaf\n    scrape_interval: 15s\n    static_configs:\n      - targets: ['${location.hostname}:${port}']\n`;
  if (token) cfg += `    authorization:\n      type: Bearer\n      credentials: ${token}\n`;
  navigator.clipboard.writeText(cfg).then(() => toast('抓取配置已复制到剪贴板')).catch(() => toast('复制失败，请手动选择', true));
}
function previewBlock() {
  const tpl = $('#block-page').value || '';
  const html = tpl.replace(/\{\{REQ_ID\}\}/g, 'demo123').replace(/\{\{REASON\}\}/g, 'SQL 注入攻击').replace(/\{\{CLIENT_IP\}\}/g, '1.2.3.4').replace(/\{\{DOMAIN\}\}/g, 'www.example.com').replace(/\{\{TIME\}\}/g, new Date().toLocaleString()).replace(/\{\{RULE_ID\}\}/g, '949110');
  const w = window.open('', '_blank');
  w.document.write(html || '<p style="font-family:sans-serif;padding:40px">当前使用默认拦截页面（保存后生效）</p>');
}
async function saveRetention() {
  try { await api('/api/settings', {method: 'PUT', body: {log_retention_days: $('#retention').value}}); toast('已保存'); }
  catch (e) { toast(e.message, true); }
}
async function changePass() {
  try {
    await api('/api/password', {method: 'PUT', body: {old: $('#pw-old').value, new: $('#pw-new').value}});
    toast('密码已修改，请重新登录'); doLogout();
  } catch (e) { toast(e.message, true); }
}

/* ---------------- 审计日志 ---------------- */
async function audit() {
  const m = $('#main');
  m.innerHTML = pageHead('审计日志', '控制台全部操作留痕') + `
  <div class="panel" style="padding:0;overflow:hidden"><table>
  <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>详情</th></tr></thead>
  <tbody id="audit-body"></tbody></table></div>`;
  try {
    const list = await api('/api/audit');
    $('#audit-body').innerHTML = list.length ? list.map(a => `<tr>
      <td class="mono">${esc(a.ts)}</td><td>${esc(a.user)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('')
      : emptyHTML(4, '暂无审计记录');
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

window.addEventListener('resize', () => charts.forEach(c => c.resize()));
(async () => {
  try { await api('/api/stats'); showApp(); }
  catch { showLogin(); }
})();