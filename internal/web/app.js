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
const ico = n => `<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[n] || ''}</svg>`;
const pageHead = (title, sub, actions) => `<div class="page-head"><div><h1>${title}</h1><p>${sub}</p></div>${actions ? `<div class="page-actions">${actions}</div>` : ''}</div>`;
const emptyHTML = (cols, msg) => `<tr><td colspan="${cols}" class="empty">${ico('inbox')}${msg}</td></tr>`;

let csrfToken = '';
let csrfRequest = null;
let currentAccount = null;
const roleNames = {admin: '管理员', operator: '操作员', viewer: '只读'};
function canOpen(view) {
  if (currentAccount?.role === 'admin') return true;
  if (['dashboard', 'traffic', 'posture', 'sites', 'logs', 'profile'].includes(view)) return true;
  return currentAccount?.role === 'operator' && ['ips', 'rules', 'tuning'].includes(view);
}
async function getCSRFToken() {
  if (csrfToken) return csrfToken;
  if (!csrfRequest) {
    csrfRequest = api('/api/csrf').then(d => {
      csrfToken = d.token;
      return csrfToken;
    }).finally(() => { csrfRequest = null; });
  }
  return csrfRequest;
}
async function api(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = {'Content-Type': 'application/json', ...opts.headers};
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && path !== '/api/login') {
    headers['X-NiuB-CSRF'] = await getCSRFToken();
  }
  const res = await fetch(path, {
    ...opts,
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && !path.includes('/login')) { showLogin(); throw new Error('未登录'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || ('请求失败 ' + res.status));
    err.status = res.status;
    throw err;
  }
  return data;
}

function toast(msg, isErr) {
  const el = document.createElement('div');
  el.className = 'toast-item' + (isErr ? ' error' : '');
  el.textContent = msg;
  $('#toast').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

function showLogin() {
  csrfToken = '';
  currentAccount = null;
  closeLive();
  closeModal();
  $('#login').classList.remove('hidden');
  $('#app').classList.add('hidden');
  $('#force-change').classList.add('hidden');
  $('#login-pass').focus({preventScroll: true});
}
function showApp() { $('#login').classList.add('hidden'); $('#force-change').classList.add('hidden'); $('#app').classList.remove('hidden'); route(); }
function showForceChange() { $('#login').classList.add('hidden'); $('#app').classList.add('hidden'); $('#force-change').classList.remove('hidden'); $('#fc-err').textContent = ''; setTimeout(() => $('#fc-new').focus(), 50); }

let lastLoginPass = '';
async function doLogin() {
  try {
    const pass = $('#login-pass').value;
    const d = await api('/api/login', {method: 'POST', body: {username: $('#login-user').value.trim(), password: pass}});
    currentAccount = d;
    $('#login-pass').value = '';
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
  if (nw !== cf) return err('两次输入的新密码不一致');
  try {
    await api('/api/password', {method: 'PUT', body: {old: lastLoginPass, new: nw}});
    csrfToken = '';
    currentAccount.must_change = false;
    lastLoginPass = ''; $('#fc-new').value = ''; $('#fc-confirm').value = '';
    toast('密码已修改');
    showApp();
  } catch (e) { err(e.message); }
}
async function doLogout() { await api('/api/logout', {method: 'POST'}); showLogin(); }
$('#login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('#login-user').addEventListener('keydown', e => { if (e.key === 'Enter') $('#login-pass').focus(); });
$('#fc-confirm').addEventListener('keydown', e => { if (e.key === 'Enter') doForceChange(); });
$('#fc-new').addEventListener('keydown', e => { if (e.key === 'Enter') $('#fc-confirm').focus(); });

const charts = [];
function disposeCharts() { charts.forEach(c => c.dispose()); charts.length = 0; }
function mkChart(el, opt) { const c = echarts.init(el); c.setOption(opt); charts.push(c); return c; }
const axisStyle = {
  axisLine: {lineStyle: {color: '#d7e3f0'}}, axisTick: {show: false},
  axisLabel: {color: '#5d718d', fontSize: 11}, splitLine: {lineStyle: {color: '#e8eff7'}},
};
const tipStyle = {
  backgroundColor: '#fff', borderColor: 'rgba(148,163,184,.2)',
  textStyle: {color: '#172a46', fontSize: 12},
  extraCssText: 'box-shadow:0 8px 24px rgba(40,70,110,.14);border-radius:10px;',
};
const areaGrad = (rgb) => new echarts.graphic.LinearGradient(0, 0, 0, 1, [
  {offset: 0, color: `rgba(${rgb},.3)`}, {offset: 1, color: `rgba(${rgb},0)`}]);

let liveES = null;
let dashTimer = null;
function closeLive() {
  if (liveES) { liveES.close(); liveES = null; }
}

function route() {
  if (!currentAccount || $('#app').classList.contains('hidden')) return;
  disposeCharts(); closeLive();
  if (repTimer) { clearInterval(repTimer); repTimer = null; }
  if (dashTimer) { clearInterval(dashTimer); dashTimer = null; }
  const requested = location.hash.replace('#/', '').split('?')[0];
  const views = {dashboard, traffic, posture, sites, logs, tuning, rules, ips, reputation, settings, operations, audit, accounts, profile};
  const view = Object.hasOwn(views, requested) && canOpen(requested) ? requested : 'dashboard';
  const nav = $('.sidebar nav');
  nav.querySelectorAll('a[data-view]').forEach(a => {
    a.classList.toggle('hidden', !canOpen(a.dataset.view));
    if (a.classList.toggle('active', a.dataset.view === view)) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  if (matchMedia('(max-width: 650px)').matches) {
    const bounds = nav.getBoundingClientRect();
    const link = nav.querySelector('[aria-current]').getBoundingClientRect();
    if (link.left < bounds.left || link.right > bounds.right) {
      nav.scrollLeft += (link.left + link.right - bounds.left - bounds.right) / 2;
    }
  }
  views[view]();
}
window.addEventListener('hashchange', route);

/* ---------------- 仪表盘 ---------------- */
async function dashboard() {
  const m = $('#main');
  const date = new Intl.DateTimeFormat('zh-CN', {month: 'long', day: 'numeric', weekday: 'long'}).format(new Date());
  m.innerHTML = `<section class="dashboard-hero">
    <div class="hero-rings" aria-hidden="true"></div>
    <div>
      <div class="dashboard-date">${esc(date)}</div>
      <h1>仪表盘</h1>
      <p>流量趋势与防护事件 · 每 10 秒更新</p>
    </div>
    <div class="page-actions">
      <a href="#/sites" class="btn">${ico('globe')}防护站点</a>
      <a href="#/logs" class="btn ghost">${ico('report')}攻击日志</a>
    </div>
  </section>
  <div class="cards" id="stat-cards"></div>
  <div class="dashboard-overview">
    <div class="panel"><h3>流量趋势<span class="section-caption">近 24 小时</span></h3><div id="trend" class="chart"></div></div>
    ${qpsPanel('q')}
  </div>
  <div class="panel"><h3><span class="live-dot"></span>实时攻击事件</h3>
    <div class="table-scroll"><table><thead><tr><th>时间</th><th>站点</th><th>IP</th><th>动作</th><th>描述</th></tr></thead>
    <tbody id="live-body">${emptyHTML(5, '等待事件…')}</tbody></table></div>
  </div>`;
  const trendEl = m.querySelector('#trend');
  let trendChart = null;
  const paint = async first => {
    const [stats, trend] = await Promise.all([api('/api/stats'), api('/api/trend?hours=24')]);
    if (!trendEl.isConnected || $('#app').classList.contains('hidden')) return;
    $('#stat-cards').innerHTML = `
      ${card('今日请求', stats.today_reqs, '', 'activity', '')}
      ${card('今日拦截', stats.today_blocks, 'red', 'zap', 'red')}
      ${card('累计拦截', stats.total_blocks, 'red', 'shield', 'red')}
      ${card('防护站点', stats.sites_enabled + ' / ' + stats.sites, 'green', 'globe', 'green')}`;
    if (first) countUp(); else fmtCards();
    const trendOpt = {
      tooltip: {trigger: 'axis', ...tipStyle},
      title: chartEmptyTitle(trend),
      legend: {show: !!trend.length, data: ['请求', '拦截'], textStyle: {color: '#5d718d'}, icon: 'roundRect', itemWidth: 12, itemHeight: 4},
      grid: {left: 50, right: 20, top: 40, bottom: 30},
      xAxis: {type: 'category', boundaryGap: false, data: trend.map(p => p.minute.slice(11)), ...axisStyle, show: !!trend.length},
      yAxis: {type: 'value', ...axisStyle, show: !!trend.length},
      series: [
        {name: '请求', type: 'line', smooth: true, showSymbol: false, data: trend.map(p => p.reqs), lineStyle: {width: 2, color: '#3b71df'}, itemStyle: {color: '#3b71df'}, areaStyle: {color: areaGrad('59,113,223')}},
        {name: '拦截', type: 'line', smooth: true, showSymbol: false, data: trend.map(p => p.blocks), lineStyle: {width: 2, color: '#d14c6b'}, itemStyle: {color: '#d14c6b'}, areaStyle: {color: areaGrad('209,76,107')}}]
    };
    if (first) trendChart = mkChart(trendEl, trendOpt); else trendChart.setOption(trendOpt);
  };
  try {
    await paint(true);
    if (!trendEl.isConnected || $('#app').classList.contains('hidden')) return;
    qpsInit('q');
    const recent = await api('/api/logs?size=8&attack_only=1');
    if (!trendEl.isConnected || $('#app').classList.contains('hidden')) return;
    renderLiveRows(recent.list || []);
    liveES = new EventSource('/api/events');
    liveES.onmessage = ev => {
      const d = JSON.parse(ev.data);
      if (d.type === 'qps') { qpsTick('q', d); return; }
      if (d.type !== 'attack' || d.status === 200) return;
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
  return `<div class="card tone-${iconCls}"><div class="card-top"><div class="label">${esc(label)}</div><div class="card-icon">${ico(iconName)}</div></div><div class="num ${cls || ''}">${esc(num)}</div></div>`;
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
function chartEmptyTitle(data) {
  return {show: !data.length, text: '暂无数据', left: 'center', top: 'center', textStyle: {color: '#5d718d', fontSize: 13, fontWeight: 400}};
}
function barOpt(kvs, color) {
  return {
    tooltip: tipStyle, grid: {left: 10, right: 30, top: 10, bottom: 10, containLabel: true},
    title: chartEmptyTitle(kvs),
    xAxis: {type: 'value', ...axisStyle, show: !!kvs.length},
    yAxis: {type: 'category', inverse: true, show: !!kvs.length, data: kvs.map(k => k.key), ...axisStyle, axisLabel: {color: '#5d718d', fontSize: 11, width: 150, overflow: 'truncate'}},
    series: [{type: 'bar', data: kvs.map(k => k.count), barMaxWidth: 14,
      itemStyle: {borderRadius: [0, 6, 6, 0], color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{offset: 0, color: color + '40'}, {offset: 1, color}])}}]
  };
}
const actionTag = a => ({waf: '<span class="tag red">WAF拦截</span>', resp: '<span class="tag red">响应拦截</span>', cc: '<span class="tag orange">CC限频</span>', blacklist: '<span class="tag red">黑名单</span>', geo: '<span class="tag blue">地区限制</span>', semantic: '<span class="tag blue">语义检测</span>', reputation: '<span class="tag orange">信誉封禁</span>', custom: '<span class="tag violet">自定义</span>', dynamic: '<span class="tag cyan">动态防护</span>', bot: '<span class="tag violet">Bot防护</span>', api_schema: '<span class="tag cyan">API 契约</span>'}[a] || esc(a));
function liveRow(d) {
  const ip = d.ip || d.client_ip;
  const geo = [d.city, d.country].filter(Boolean).map(esc).join(' / ');
  return `<tr><td class="mono">${esc(d.ts)}</td><td>${esc(d.domain)}</td><td class="mono">${esc(ip)}${geo ? `<div class="hint">${geo}</div>` : ''}</td><td>${actionTag(d.action)}</td><td class="url-cell" title="${esc(d.msg)}">${esc(d.msg)}</td></tr>`;
}
function renderLiveRows(list) {
  const tb = $('#live-body');
  tb.innerHTML = list.length ? list.map(liveRow).join('') : emptyHTML(5, '暂无攻击事件');
}

/* ---------------- 实时 QPS 组件（SSE 每秒一帧驱动） ---------------- */
const qpsState = {};
function qpsPanel(id) {
  return `<div class="panel qps-panel"><h3><span class="live-dot"></span>实时 QPS<span class="qps-hint">5s 滚动均值 · 近 60 秒曲线</span></h3>
  <div class="qps-row">
    <div class="qps-item"><div class="qps-v" id="${id}-cur">0</div><div class="qps-l">当前 QPS</div></div>
    <div class="qps-item"><div class="qps-v amber" id="${id}-peak">0</div><div class="qps-l">60s 峰值</div></div>
    <div class="qps-item"><div class="qps-v red" id="${id}-blk">0</div><div class="qps-l">拦截 QPS</div></div>
    <canvas class="qps-spark" id="${id}-spark"></canvas>
  </div></div>`;
}
function qpsSet(id, d) {
  const cur = $('#' + id + '-cur');
  if (!cur) return;
  cur.textContent = d.qps;
  $('#' + id + '-peak').textContent = d.peak;
  $('#' + id + '-blk').textContent = d.blocked_qps;
}
function qpsDraw(id) {
  const st = qpsState[id], cv = $('#' + id + '-spark');
  if (!st || !cv) return;
  const dpr = window.devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight;
  if (!W) return;
  const width = Math.round(W * dpr), height = Math.round(H * dpr);
  if (cv.width !== width || cv.height !== height) { cv.width = width; cv.height = height; }
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(1, ...st.series.map(p => p.req));
  const n = st.series.length;
  const line = (key, color, fill) => {
    ctx.beginPath();
    st.series.forEach((p, i) => {
      const x = n > 1 ? i * W / (n - 1) : 0, y = H - 2 - (p[key] / max) * (H - 6);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = color; ctx.lineWidth = 1.6; ctx.stroke();
    if (fill && n > 1) {
      ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();
    }
  };
  line('req', '#3b71df', 'rgba(59,113,223,.10)');
  line('blocked', '#d14c6b');
}
async function qpsInit(id) {
  try {
    const d = await api('/api/qps');
    qpsState[id] = {series: d.series || []};
    qpsSet(id, d);
    qpsDraw(id);
  } catch (e) { /* 播种失败不影响 SSE 后续驱动 */ }
}
function qpsTick(id, d) {
  const st = qpsState[id];
  if (!st) return;
  st.series.push({ts: d.ts, req: d.req, blocked: d.blocked});
  if (st.series.length > 60) st.series.shift();
  qpsSet(id, d);
  qpsDraw(id);
}

/* ---------------- 分析公共组件 ---------------- */
const fmtN = n => (+n || 0).toLocaleString();
const DONUT_COLORS = ['#3b71df', '#805cca', '#168a70', '#bc771e', '#d14c6b', '#16899e', '#bb5a9b', '#ad8543', '#548eb1', '#5d718d'];
const STATUS_NAME = {200: 'OK', 201: 'Created', 204: 'No Content', 301: 'Moved', 302: 'Found', 304: 'Not Modified', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Not Allowed', 429: 'Too Many Requests', 500: 'Server Error', 502: 'Bad Gateway', 503: 'Unavailable', 504: 'Timeout'};
function donutOpt(kvs, center) {
  return {
    color: DONUT_COLORS,
    tooltip: {...tipStyle, formatter: p => `${esc(p.name)}<br/><b>${fmtN(p.value)}</b>（${p.percent}%）`},
    title: center ? {text: center.num, subtext: center.label, left: 'center', top: '40%', textStyle: {color: '#172a46', fontSize: 20, fontWeight: 700}, subtextStyle: {color: '#5d718d', fontSize: 11}} : undefined,
    series: [{type: 'pie', radius: ['54%', '74%'], center: ['50%', '50%'],
      data: kvs.map(k => ({name: k.name || k.key, value: k.count})),
      label: {color: '#5d718d', fontSize: 11, formatter: '{b} {d}%'},
      labelLine: {length: 8, length2: 8, lineStyle: {color: 'rgba(148,163,184,.3)'}},
      itemStyle: {borderColor: '#fff', borderWidth: 2}}]
  };
}
function rankList(kvs, blocked, urls) {
  const arr = (kvs || []).map(k => ({name: k.name || k.key, count: blocked ? (+k.blocked || 0) : (+k.count || 0)}))
    .filter(k => !blocked || k.count > 0);
  if (!arr.length) return '<div class="rank-empty">暂无数据</div>';
  const max = Math.max(...arr.map(k => k.count)) || 1;
  return `<div class="rank-list${urls ? ' rank-urls' : ''}">${arr.map((k, i) =>
    `<div class="rank-row${blocked ? ' blocked' : ''}"><span class="rank-i${i < 3 ? ' hot' : ''}">${i + 1}</span><span class="rank-k" title="${esc(k.name)}">${esc(k.name)}</span><span class="rank-bar"><i style="width:${(k.count / max * 100).toFixed(1)}%"></i></span><span class="rank-v">${fmtN(k.count)}</span></div>`).join('')}</div>`;
}
function rankPanel(title, id, key) {
  return `<div class="panel"><div class="panel-head"><h3>${title}</h3><button class="btn ghost sm rank-more" data-rank="${key}" data-title="${title}">查看更多</button></div><div id="${id}"></div></div>`;
}
function showRankModal(title, kvs, urls) {
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()"><div class="modal modal-wide" role="dialog" aria-modal="true" aria-label="${esc(title)}">
  <div class="panel-head"><h3>${esc(title)}</h3><button class="btn ghost sm rank-more" onclick="closeModal()">关闭</button></div>
  <div class="hint" style="margin-bottom:14px">按请求量排序，最多展示 Top 50</div>${rankList(kvs, false, urls)}
  </div></div>`;
}
const SPANS = [[6, '6小时'], [24, '24小时'], [72, '3天'], [168, '7天']];
const spanSeg = (id, cur) => `<div class="seg" id="${id}">${SPANS.map(([v, t]) => `<button class="btn${v === cur ? ' on' : ''}" data-h="${v}">${t}</button>`).join('')}</div>`;
const hourLbl = (ts, span) => {
  const d = new Date(ts * 1000), p = n => String(n).padStart(2, '0');
  return span > 48 ? `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}时` : `${p(d.getHours())}:00`;
};

/* ---------------- 流量分析 ---------------- */
async function traffic() {
  const m = $('#main');
  let span = 24, geoMode = 'world', geoMetric = 'visit', geoData = null, trafficData = null;
  m.innerHTML = pageHead('流量分析', '请求构成 · 客户端画像 · 地域与来源洞察 · 每 30 秒自动刷新', spanSeg('t-span', span)) + `
  <div class="cards" id="t-cards"></div>
  <div class="panel"><h3>请求 / 拦截趋势（按小时）</h3><div id="t-trend" class="chart"></div></div>
  <div class="grid2">
    <div class="panel"><h3>状态码分布</h3><div id="t-status" class="chart"></div></div>
    <div class="panel"><div class="panel-head"><h3>地域分布</h3><div class="seg" id="t-geo-mode"><button class="btn on" data-v="world">世界</button><button class="btn" data-v="cn">中国</button></div><div class="seg" id="t-geo-metric"><button class="btn on" data-v="visit">访问</button><button class="btn" data-v="block">仅拦截</button></div></div><div id="t-geo"></div></div>
  </div>
  <div class="panel"><h3>客户端画像</h3><div class="profile-grid">
    <div><div class="sub-h">操作系统</div><div id="t-os"></div></div>
    <div><div class="sub-h">浏览器</div><div id="t-br"></div></div>
    <div><div class="sub-h">自动化工具 / 爬虫</div><div id="t-tool"></div></div>
  </div></div>
  <div class="grid2">
    ${rankPanel('外部来源域名', 't-ref', 'referer')}
    ${rankPanel('外部来源页面', 't-ref-page', 'referer_page')}
  </div>
  <div class="grid2">
    ${rankPanel('受访域名', 't-host', 'host')}
    ${rankPanel('受访页面', 't-page', 'page')}
  </div>`;
  let trendC = null, statusC = null;
  const paintGeo = () => {
    const el = $('#t-geo');
    if (!el || !geoData) return;
    const arr = geoMode === 'world' ? (geoData.countries || []) : (geoData.provinces || []);
    el.innerHTML = rankList(arr.slice(0, 10), geoMetric === 'block');
  };
  const paint = async first => {
    const s = await api('/api/analytics?hours=' + span);
    geoData = s;
    trafficData = s;
    const t = s.totals || {};
    $('#t-cards').innerHTML = `
      ${card('请求量', fmtN(t.req), '', 'activity', '')}
      ${card('拦截量', fmtN(t.blocked), 'red', 'zap', 'red')}
      ${card('拦截率', (t.block_rate || 0) + '%', 'red', 'shield', 'red')}
      ${card('独立 IP', fmtN(t.uv), 'green', 'globe', 'green')}
      ${card('4xx 占比', (t.rate_4xx || 0) + '%', '', 'report', 'violet')}
      ${card('5xx 占比', (t.rate_5xx || 0) + '%', '', 'layers', 'violet')}`;
    const hrs = s.hours || [];
    const trendOpt = {
      tooltip: {trigger: 'axis', ...tipStyle},
      legend: {data: ['请求', '拦截', '独立IP'], textStyle: {color: '#5d718d'}, icon: 'roundRect', itemWidth: 12, itemHeight: 4},
      grid: {left: 50, right: 20, top: 40, bottom: 30},
      xAxis: {type: 'category', boundaryGap: false, data: hrs.map(p => hourLbl(p.ts, span)), ...axisStyle},
      yAxis: {type: 'value', ...axisStyle},
      series: [
        {name: '请求', type: 'line', smooth: true, showSymbol: false, data: hrs.map(p => p.req), lineStyle: {width: 2, color: '#3b71df'}, itemStyle: {color: '#3b71df'}, areaStyle: {color: areaGrad('59,113,223')}},
        {name: '拦截', type: 'line', smooth: true, showSymbol: false, data: hrs.map(p => p.blocked), lineStyle: {width: 2, color: '#d14c6b'}, itemStyle: {color: '#d14c6b'}, areaStyle: {color: areaGrad('209,76,107')}},
        {name: '独立IP', type: 'line', smooth: true, showSymbol: false, data: hrs.map(p => p.uv), lineStyle: {width: 1.5, color: '#168a70', type: 'dashed'}, itemStyle: {color: '#168a70'}}]
    };
    if (first) trendC = mkChart($('#t-trend'), trendOpt); else trendC.setOption(trendOpt, true);
    const stOpt = donutOpt((s.status || []).slice(0, 9).map(k => ({key: k.key + ' ' + (STATUS_NAME[k.key] || ''), count: k.count})), {num: fmtN(t.req), label: '总请求'});
    if (first) statusC = mkChart($('#t-status'), stOpt); else statusC.setOption(stOpt, true);
    paintGeo();
    $('#t-os').innerHTML = rankList((s.os || []).slice(0, 5));
    $('#t-br').innerHTML = rankList((s.browser || []).slice(0, 5));
    $('#t-tool').innerHTML = rankList((s.tool || []).slice(0, 5));
    $('#t-ref').innerHTML = rankList((s.referer || []).slice(0, 10));
    $('#t-ref-page').innerHTML = rankList((s.referer_page || []).slice(0, 10), false, true);
    $('#t-host').innerHTML = rankList((s.host || []).slice(0, 10));
    $('#t-page').innerHTML = rankList((s.page || []).slice(0, 10), false, true);
  };
  m.addEventListener('click', e => {
    const b = e.target.closest('button[data-rank]'); if (!b || !trafficData) return;
    const key = b.dataset.rank;
    showRankModal(b.dataset.title, trafficData[key] || [], key === 'referer_page' || key === 'page');
  });
  $('#t-span').addEventListener('click', e => {
    const b = e.target.closest('button[data-h]'); if (!b) return;
    span = +b.dataset.h;
    $('#t-span').querySelectorAll('.btn').forEach(x => x.classList.toggle('on', x === b));
    paint(false).catch(err => toast(err.message, true));
  });
  $('#t-geo-mode').addEventListener('click', e => {
    const b = e.target.closest('button[data-v]'); if (!b) return;
    geoMode = b.dataset.v;
    $('#t-geo-mode').querySelectorAll('.btn').forEach(x => x.classList.toggle('on', x === b));
    paintGeo();
  });
  $('#t-geo-metric').addEventListener('click', e => {
    const b = e.target.closest('button[data-v]'); if (!b) return;
    geoMetric = b.dataset.v;
    $('#t-geo-metric').querySelectorAll('.btn').forEach(x => x.classList.toggle('on', x === b));
    paintGeo();
  });
  try {
    await paint(true);
    dashTimer = setInterval(() => {
      if (document.visibilityState === 'visible') paint(false).catch(() => {});
    }, 30000);
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

/* ---------------- 安全态势 ---------------- */
const MOD_ICON = {'攻击防护': 'shield', 'IP 黑名单': 'zap', '信誉封禁': 'report', 'CC 限流': 'activity', 'Bot 防护': 'search', '动态防护': 'layers', '自定义规则': 'report', '地域管控': 'globe', '人机验证': 'pin'};
async function posture() {
  const m = $('#main');
  let span = 24, curMod = '';
  m.innerHTML = pageHead('安全态势', '防护模块命中 · 攻击类型与来源 · 每 30 秒自动刷新', spanSeg('p-span', span)) + `
  <div class="cards" id="p-cards"></div>
  <div class="grid2">
    <div class="panel"><h3>防护模块命中趋势（堆叠）</h3><div id="p-modtrend" class="chart"></div></div>
    <div class="panel"><h3>攻击类型分布</h3><div id="p-cat" class="chart"></div></div>
  </div>
  <div class="grid2">
    <div class="panel"><h3>攻击源 IP Top10</h3><div id="p-ips" class="chart"></div></div>
    <div class="panel"><div class="panel-head"><h3>模块 × 攻击源</h3><select id="p-modsel"></select></div><div id="p-modip" class="chart"></div></div>
  </div>
  <div class="grid2">
    <div class="panel"><h3>Top 被攻击页面</h3><div id="p-path"></div></div>
    <div class="panel"><h3>Top 被攻击站点</h3><div id="p-host"></div></div>
  </div>`;
  let mtC = null, catC = null, ipsC = null, mipC = null, modIPs = {};
  const paint = async first => {
    const s = await api('/api/analytics?hours=' + span);
    const mods = s.modules || [];
    $('#p-cards').innerHTML = mods.length
      ? mods.slice(0, 6).map(mo => card(mo.key, fmtN(mo.count), 'red', MOD_ICON[mo.key] || 'zap', 'red')).join('')
      : card('安全事件', '0', 'green', 'shield', 'green');
    const top5 = mods.slice(0, 5).map(mo => mo.key);
    const hrs = s.hours || [];
    const mtOpt = {
      color: DONUT_COLORS,
      tooltip: {trigger: 'axis', ...tipStyle},
      legend: {data: top5, textStyle: {color: '#5d718d'}, icon: 'roundRect', itemWidth: 12, itemHeight: 4},
      grid: {left: 50, right: 20, top: 40, bottom: 30},
      xAxis: {type: 'category', boundaryGap: false, data: hrs.map(p => hourLbl(p.ts, span)), ...axisStyle},
      yAxis: {type: 'value', ...axisStyle},
      series: top5.map(name => ({name, type: 'line', smooth: true, showSymbol: false, stack: 'mod',
        lineStyle: {width: 1.5}, areaStyle: {opacity: .22},
        data: hrs.map(p => (p.modules || {})[name] || 0)}))
    };
    if (first) mtC = mkChart($('#p-modtrend'), mtOpt); else mtC.setOption(mtOpt, true);
    const cats = s.categories || [];
    const catOpt = donutOpt(cats, {num: fmtN(cats.reduce((a, c) => a + c.count, 0)), label: '安全事件'});
    if (first) catC = mkChart($('#p-cat'), catOpt); else catC.setOption(catOpt, true);
    const ipsOpt = barOpt((s.attack_ips || []).map(k => ({key: k.key, count: k.count})), '#d14c6b');
    if (first) ipsC = mkChart($('#p-ips'), ipsOpt); else ipsC.setOption(ipsOpt, true);
    modIPs = s.module_ips || {};
    const names = Object.keys(modIPs);
    if (!curMod || !names.includes(curMod)) curMod = names[0] || '';
    const sel = $('#p-modsel');
    sel.innerHTML = names.length ? names.map(k => `<option value="${esc(k)}"${k === curMod ? ' selected' : ''}>${esc(k)}</option>`).join('') : '<option value="">暂无数据</option>';
    const mipOpt = curMod ? barOpt(modIPs[curMod] || [], '#bc771e') : {title: {text: '暂无数据', left: 'center', top: 'center', textStyle: {color: '#5a6b8c', fontSize: 13, fontWeight: 400}}};
    if (first) mipC = mkChart($('#p-modip'), mipOpt); else mipC.setOption(mipOpt, true);
    $('#p-path').innerHTML = rankList((s.attack_paths || []).slice(0, 10));
    $('#p-host').innerHTML = rankList((s.attack_hosts || []).slice(0, 10));
  };
  $('#p-modsel').addEventListener('change', () => {
    curMod = $('#p-modsel').value;
    if (mipC) mipC.setOption(barOpt(modIPs[curMod] || [], '#bc771e'), true);
  });
  $('#p-span').addEventListener('click', e => {
    const b = e.target.closest('button[data-h]'); if (!b) return;
    span = +b.dataset.h;
    $('#p-span').querySelectorAll('.btn').forEach(x => x.classList.toggle('on', x === b));
    paint(false).catch(err => toast(err.message, true));
  });
  try {
    await paint(true);
    dashTimer = setInterval(() => {
      if (document.visibilityState === 'visible') paint(false).catch(() => {});
    }, 30000);
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

/* ---------------- 防护站点 ---------------- */
async function sites() {
  const m = $('#main');
  const admin = currentAccount.role === 'admin';
  const canEditAPI = currentAccount.role !== 'viewer';
  m.innerHTML = pageHead('防护站点', '配置站点后，从用户访问的入口验证流量、拦截和回源',
    `${admin ? `<button class="btn" onclick="siteForm()">${ico('plus')}添加站点</button>` : ''}
     <button class="btn ghost" onclick="sites()">${ico('refresh')}刷新状态</button>`) + `
  <div class="panel table-panel"><table>
  <thead><tr><th>名称</th><th>域名</th><th>上游地址</th><th>模式</th><th>CC防护</th><th>身份认证</th><th>状态</th><th>操作</th></tr></thead>
  <tbody id="site-body"></tbody></table></div>`;
  try {
    const [list, health] = await Promise.all([api('/api/sites'), api('/api/upstreams')]);
    const hmap = {};
    health.forEach(h => { hmap[h.domain] = h.targets; });
    const upCell = s => (hmap[s.domain] || []).map(t =>
      `<div><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${t.up ? '#168a70' : '#d14c6b'};margin-right:6px;box-shadow:0 0 6px ${t.up ? 'rgba(22,138,112,.6)' : 'rgba(209,76,107,.6)'}"></span>${esc(t.url)}</div>`).join('') || esc(s.upstream);
    const siteBody = $('#site-body');
    siteBody.innerHTML = list.length ? list.map(s => `<tr>
      <td>${esc(s.name)}</td><td class="mono">${esc(s.domain)}</td><td class="mono">${upCell(s)}</td>
      <td>${s.waf_mode === 'strict' ? '<span class="tag orange">严格</span>' : '<span class="tag blue">平衡</span>'}${s.dynamic_mode === 'block' ? ' <span class="tag cyan">动态拦截</span>' : s.dynamic_mode === 'observe' ? ' <span class="tag cyan">动态观察</span>' : ''}${s.bot_mode && s.bot_mode !== 'off' ? ' <span class="tag violet">反爬' + ({block: '拦截', captcha: '验证', log: '观察'}[s.bot_mode] || '') + '</span>' : ''}</td>
      <td>${s.cc_rate > 0 ? s.cc_rate + ' req/s' + (s.captcha ? ' +人机验证' : '') : '<span class="hint">关闭</span>'}</td>
      <td>${s.auth_user ? '<span class="tag on">开启</span>' : '<span class="hint">关闭</span>'}</td>
      <td data-ingress-site="${esc(s.id)}">${ingressBadge(s, s.ingress)}</td>
      <td>
        <button class="btn ghost sm" data-site-action="ingress" data-id="${esc(s.id)}">接入验收</button>
        ${canEditAPI ? `<button class="btn ghost sm" data-site-action="api" data-id="${esc(s.id)}">API 契约</button>` : ''}
        ${admin ? `<button class="btn ghost sm" data-site-action="upload" data-id="${esc(s.id)}">上传策略</button>` : ''}
        ${admin ? `<button class="btn ghost sm" data-site-action="edit" data-id="${esc(s.id)}">编辑</button>
          <button class="btn danger sm" data-site-action="delete" data-id="${esc(s.id)}">删除</button>` : ''}
      </td>
    </tr>`).join('') : emptyHTML(8, '还没有防护站点，点击右上角添加');
    siteBody.addEventListener('click', e => {
      const btn = e.target.closest('button[data-site-action]');
      if (!btn) return;
      const s = list.find(item => String(item.id) === btn.dataset.id);
      if (!s) return;
      if (btn.dataset.siteAction === 'edit') siteForm(s);
      else if (btn.dataset.siteAction === 'delete') delSite(s.id, s.domain);
      else if (btn.dataset.siteAction === 'api') openAPIPolicy(s);
      else if (btn.dataset.siteAction === 'upload') openUploadPolicy(s);
      else if (btn.dataset.siteAction === 'ingress') openIngressVerification(s);
    });
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

function ingressBadge(site, status) {
  if (!site.enabled) return '<span class="tag off">已停用</span>';
  if (status?.verified) {
    const label = status.source === 'external' ? '外部入口已验收' : '本地入口已验收';
    const verifiedAt = [status.pass?.observed_at, status.block?.observed_at]
      .filter(Boolean).sort().at(-1);
    return `<span class="tag on">${label}</span><div class="hint">${esc(status.entry_url)}</div>
      ${verifiedAt ? `<div class="hint">${esc(inspectionTime(verifiedAt))}</div>` : ''}`;
  }
  if (status?.pass?.observed_at || status?.block?.observed_at || site.traffic_observed_at) {
    const observedAt = status?.pass?.observed_at || status?.block?.observed_at || site.traffic_observed_at;
    return `<span class="tag blue">已收到流量</span><div class="hint">${esc(inspectionTime(observedAt))}</div>`;
  }
  return '<span class="tag orange">已配置</span><div class="hint">待验收</div>';
}

async function openIngressVerification(site) {
  const endpoint = '/api/sites/' + encodeURIComponent(site.id) + '/ingress-verification';
  const canStart = currentAccount.role === 'admin' && site.enabled;
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()">
    <section class="modal" role="dialog" aria-modal="true" aria-labelledby="ingress-title">
      <h3 id="ingress-title">接入验收 · ${esc(site.domain)}</h3>
      ${canStart ? `<form id="ingress-form">
        <div class="form-grid">
          <label class="form-row"><span>协议</span><select name="scheme"><option value="https">HTTPS</option><option value="http">HTTP</option></select></label>
          <label class="form-row"><span>用户访问的端口</span><input name="port" type="number" required min="1" max="65535" value="443"></label>
          <label class="form-row"><span>GET 路径</span><input name="path" required maxlength="256" value="/" autocomplete="off" spellcheck="false"></label>
          <label class="form-row"><span>执行位置</span><select name="source"><option value="external">外部网络</option><option value="local">内网或本机</option></select></label>
        </div>
        <p class="hint">选一个可正常访问的只读路径。外部网络验收请在站点所在局域网之外执行。</p>
        <div class="verify-actions"><button class="btn" type="submit">生成验收命令</button></div>
      </form>` : `<p class="hint">${site.enabled ? '管理员可以生成验收命令。' : '启用站点后可生成验收命令。'}</p>`}
      <div id="ingress-commands" hidden></div>
      <div id="ingress-result" class="verify-result" role="status" aria-live="polite"></div>
      <div class="modal-actions"><button id="ingress-refresh" class="btn ghost" type="button">刷新结果</button><button class="btn ghost" onclick="closeModal()">关闭</button></div>
    </section></div>`;
  const result = $('#ingress-result');
  const commands = $('#ingress-commands');
  const refresh = $('#ingress-refresh');
  const form = $('#ingress-form');
  let resultRevision = 0;
  let commandCreatedAt;
  function render(status) {
    if (!result.isConnected) return;
    const expired = status?.expires_at && Date.parse(status.expires_at) <= Date.now();
    if (status?.created_at !== commandCreatedAt || expired) commands.hidden = true;
    const cell = document.querySelector(`[data-ingress-site="${Number(site.id)}"]`);
    if (cell) cell.innerHTML = ingressBadge(site, status);
    if (!status?.entry_url) {
      result.textContent = '还没有接入验收记录。';
      return;
    }
    const verificationRow = (label, item) => {
      if (!item?.observed_at) return `<dt>${label}</dt><dd>${expired ? '验收命令已过期' : '等待请求到达'}</dd>`;
      const detail = item.origin_status ? ` · 上游 HTTP ${item.origin_status}` : '';
      const reasons = {origin_reached: '源站已响应', origin_error_status: '源站返回非成功状态', response_status_changed: 'WAF 返回的状态与源站不同',
        request_interrupted: '请求处理未完成', no_origin_response: '没有收到源站响应', verification_blocked: 'WAF 返回预期的验证拦截'};
      return `<dt>${label}</dt><dd><span class="tag ${item.matched ? 'on' : 'orange'}">${item.matched ? '通过' : '未通过'}</span>
        HTTP ${esc(item.status)}${esc(detail)}<div class="hint">${esc(inspectionTime(item.observed_at))} · ${esc(item.request_id || '—')}</div>
        ${reasons[item.reason] ? `<div class="hint">${reasons[item.reason]}</div>` : ''}</dd>`;
    };
    result.innerHTML = `<dl class="verify-details">
      <dt>验证入口</dt><dd class="mono">${esc(status.entry_url)}</dd>
      <dt>执行位置</dt><dd>${status.source === 'external' ? '外部网络（由操作者选择）' : '内网或本机'}</dd>
      ${verificationRow('正常回源', status.pass)}${verificationRow('WAF 验证拦截', status.block)}
      ${status.expires_at ? `<dt>命令有效期</dt><dd>${esc(inspectionTime(status.expires_at))}</dd>` : ''}
    </dl><p class="hint">验收结果反映本 WAF 节点观测到的请求。</p>`;
  }
  async function loadResult() {
    const revision = ++resultRevision;
    refresh.disabled = true;
    try {
      const status = await api(endpoint);
      if (revision === resultRevision) render(status);
    } catch (e) {
      if (result.isConnected && revision === resultRevision) result.textContent = e.message;
    } finally {
      if (revision === resultRevision) refresh.disabled = false;
    }
  }
  refresh.onclick = loadResult;
  if (form) {
    const {scheme, port, path, source} = form.elements;
    const submit = form.querySelector('button[type="submit"]');
    scheme.onchange = () => { port.value = scheme.value === 'https' ? '443' : '80'; };
    form.onsubmit = async event => {
      event.preventDefault();
      const probePath = path.value.trim();
      if (!/^\/[a-zA-Z0-9._~/-]*$/.test(probePath) || probePath.startsWith('//')) {
        toast('请输入简单的站内路径，例如 / 或 /health，省略查询参数。', true);
        return;
      }
      ++resultRevision;
      submit.disabled = refresh.disabled = true;
      try {
        const data = await api(endpoint, {method: 'POST', body: {scheme: scheme.value, port: Number(port.value), path: probePath, source: source.value}});
        if (!form.isConnected) return;
        const target = data.status.entry_url;
        if (!/^https?:\/\/[a-zA-Z0-9.-]+(?::[0-9]+)?\/[a-zA-Z0-9._~/-]*$/.test(target) ||
            !/^[a-zA-Z0-9-]+$/.test(data.header) || !/^[a-zA-Z0-9_-]+$/.test(data.pass_token) || !/^[a-zA-Z0-9_-]+$/.test(data.block_token)) {
          throw new Error('验收命令包含无效字符，请检查站点域名和路径。');
        }
        const cmd = token => `curl -i --max-time 20 -H "${data.header}: ${token}" "${target}"`;
        commands.innerHTML = `<p class="hint">在所选网络执行两条命令，然后刷新结果。Windows PowerShell 中请使用 curl.exe。</p>
          <label class="form-row"><span>验证正常回源</span><input class="mono" readonly value="${esc(cmd(data.pass_token))}" onclick="this.select()"></label>
          <label class="form-row"><span>验证 WAF 拦截</span><input class="mono" readonly value="${esc(cmd(data.block_token))}" onclick="this.select()"></label>`;
        commandCreatedAt = data.status.created_at;
        commands.hidden = false;
        render(data.status);
      } catch (e) { if (form.isConnected) toast(e.message, true); }
      finally { submit.disabled = refresh.disabled = false; }
    };
  }
  await loadResult();
}

async function openAPIPolicy(site) {
  try {
    const endpoint = '/api/sites/' + encodeURIComponent(site.id) + '/api-policy';
    const config = await api(endpoint);
    $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()">
    <div class="modal modal-wide" role="dialog" aria-modal="true" aria-label="API 契约">
      <h3>API 契约 · ${esc(site.domain)}</h3>
      <div class="form-grid">
        <div class="form-row"><label for="api-mode">校验模式</label><select id="api-mode">
          <option value="off">关闭</option><option value="observe">仅记录</option><option value="block">拒绝不符合契约的请求</option>
        </select></div>
        <div class="form-row"><label for="api-prefix">校验路径范围</label><input id="api-prefix" placeholder="/api"></div>
      </div>
      <div class="form-row"><label for="api-file">选取 OpenAPI 文档（JSON 或 YAML，最大 512 KiB）</label><input id="api-file" type="file" accept=".json,.yaml,.yml"></div>
      <div class="form-row"><label for="api-document">OpenAPI 3.0 / 3.1</label><textarea id="api-document" spellcheck="false"></textarea></div>
      <p class="hint">文档中的路径应与 WAF 收到的路径一致。仅记录模式会在攻击日志中显示校验失败。</p>
      <details><summary>接口清单（${config.endpoints.length}）</summary>
        <div class="table-scroll"><table><thead><tr><th>方法</th><th>路径</th><th>操作标识</th></tr></thead>
        <tbody>${config.endpoints.map(e => `<tr><td>${esc(e.method)}</td><td class="mono">${esc(e.path)}</td><td>${esc(e.name || '—')}</td></tr>`).join('') || emptyHTML(3, '保存契约后显示接口')}</tbody></table></div>
      </details>
      <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">关闭</button><button class="btn" id="api-policy-save">保存</button></div>
    </div></div>`;
    $('#api-mode').value = config.mode;
    $('#api-prefix').value = config.prefix;
    const documentField = $('#api-document');
    documentField.value = config.document;
    $('#api-file').addEventListener('change', async e => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 512 * 1024) { toast('文档不能超过 512 KiB', true); return; }
      documentField.value = await file.text();
    });
    const save = $('#api-policy-save');
    save.addEventListener('click', async () => {
      save.disabled = true;
      try {
        await api(endpoint, {method: 'PUT', body: {mode: $('#api-mode').value, prefix: $('#api-prefix').value, document: documentField.value}});
        toast('API 契约已保存');
        await openAPIPolicy(site);
      } catch (e) { toast(e.message, true); }
      finally { save.disabled = false; }
    });
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

async function openUploadPolicy(site) {
  try {
    const endpoint = '/api/sites/' + encodeURIComponent(site.id) + '/upload-policy';
    const config = await api(endpoint);
    $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()">
    <section class="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="upload-title">
      <h3 id="upload-title">上传策略 · ${esc(site.domain)}</h3>
      <p class="hint">配置上传请求的方法和精确路径。每条策略可设置请求体上限与大文件上传并发数，命中时仍执行 WAF 检测。</p>
      <form id="upload-policy-form">
        <div id="upload-policy-rows"></div>
        <div class="modal-actions">
          <button id="upload-policy-add" type="button" class="btn ghost">添加接口</button>
          <button type="button" class="btn ghost" onclick="closeModal()">关闭</button>
          <button id="upload-policy-save" type="submit" class="btn">保存策略</button>
        </div>
      </form>
    </section></div>`;
    const form = $('#upload-policy-form');
    const rows = $('#upload-policy-rows');
    const add = $('#upload-policy-add');
    const save = $('#upload-policy-save');
    function appendPolicy(policy) {
      rows.insertAdjacentHTML('beforeend', `<div class="upload-policy-row">
        <label class="form-row"><span>方法</span><select data-field="method">
          ${['POST', 'PUT', 'PATCH'].map(m => `<option ${policy.method === m ? 'selected' : ''}>${m}</option>`).join('')}
        </select></label>
        <label class="form-row"><span>路径</span><input data-field="path" required maxlength="512" placeholder="/api/upload" value="${esc(policy.path)}"></label>
        <label class="form-row"><span>请求体上限（MiB）</span><input data-field="max_body_mib" required type="number" min="1" max="${esc(config.max_body_mib)}" value="${esc(policy.max_body_mib)}"></label>
        <label class="form-row"><span>大上传并发数</span><input data-field="max_concurrent" required type="number" min="1" max="${esc(config.max_concurrent)}" value="${esc(policy.max_concurrent)}"></label>
        <button type="button" class="btn danger sm" data-remove>移除</button>
      </div>`);
      add.disabled = rows.children.length >= config.max_policies;
    }
    config.policies.forEach(appendPolicy);
    add.onclick = () => {
      appendPolicy({method: 'POST', path: '', max_body_mib: config.max_body_mib, max_concurrent: 2});
      rows.lastElementChild.querySelector('[data-field="path"]').focus();
    };
    rows.addEventListener('click', event => {
      const remove = event.target.closest('[data-remove]');
      if (remove) {
        remove.closest('.upload-policy-row').remove();
        add.disabled = false;
      }
    });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      save.disabled = true;
      const policies = Array.from(rows.children, row => {
        const value = field => row.querySelector(`[data-field="${field}"]`).value;
        return {method: value('method'), path: value('path').trim(),
          max_body_mib: Number(value('max_body_mib')), max_concurrent: Number(value('max_concurrent'))};
      });
      try {
        await api(endpoint, {method: 'PUT', body: {policies}});
        if (form.isConnected) closeModal();
        toast('上传策略已生效');
      } catch (e) { toast(e.message, true); }
      finally { save.disabled = false; }
    });
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

function siteForm(s) {
  s = s || {name: '', domain: '', upstream: 'http://', enabled: true, waf_mode: 'balanced', cc_rate: 0, cc_burst: 0, captcha: false, auth_user: '', resp_detect: false, dynamic_mode: 'off', bot_mode: 'off', bot_strict: false, http_redirect: false};
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()"><div class="modal">
  <h3>${s.id ? '编辑站点' : '添加防护站点'}</h3>
  <div class="form-grid">
    <div class="form-row"><label>站点名称</label><input id="f-name" value="${esc(s.name)}"></div>
    <div class="form-row"><label>防护域名</label><input id="f-domain" placeholder="www.example.com" value="${esc(s.domain)}"></div>
  </div>
  <div class="form-row"><label>上游地址（真实服务器，多个用逗号分隔，自动负载均衡与健康检查）</label><input id="f-upstream" placeholder="http://192.168.1.10:80, http://192.168.1.11:80" value="${esc(s.upstream)}"></div>
  ${s.upstream_redacted ? '<label class="check"><input id="f-replace-upstream" type="checkbox"> 用当前输入值替换上游（旧地址的凭据或查询参数已隐藏，地址不变时默认保留旧配置）</label>' : ''}
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
  <label class="check"><input id="f-captcha" type="checkbox" ${s.captcha ? 'checked' : ''}> CC 超限时显示人机验证（验证后仍执行限流）</label>
  <label class="check"><input id="f-resp" type="checkbox" ${s.resp_detect ? 'checked' : ''}> 响应内容检测</label>
  <p class="hint">检查响应头及支持类型的正文。部分响应只检查响应头，覆盖结果见「运行维护」。</p>
  <div class="form-row"><label>动态防护（向页面植入混淆令牌，拦截无令牌的自动化写操作 / 重放 / CSRF）</label><select id="f-dyn">
    <option value="off" ${s.dynamic_mode !== 'observe' && s.dynamic_mode !== 'block' ? 'selected' : ''}>关闭</option>
    <option value="observe" ${s.dynamic_mode === 'observe' ? 'selected' : ''}>观察（仅记录，不拦截）</option>
    <option value="block" ${s.dynamic_mode === 'block' ? 'selected' : ''}>拦截（缺失令牌即 403）</option></select></div>
  <div class="form-row"><label>反爬 Bot 防护（内置爬虫 UA 特征库：脚本库 / 采集框架 / 下载器 / 扫描攻击工具 / SEO 外链爬虫）</label><select id="f-bot">
    <option value="off" ${s.bot_mode !== 'block' && s.bot_mode !== 'captcha' && s.bot_mode !== 'log' ? 'selected' : ''}>关闭</option>
    <option value="log" ${s.bot_mode === 'log' ? 'selected' : ''}>观察（仅记录，不拦截）</option>
    <option value="captcha" ${s.bot_mode === 'captcha' ? 'selected' : ''}>人机验证（需要配置 Turnstile）</option>
    <option value="block" ${s.bot_mode === 'block' ? 'selected' : ''}>拦截（命中即 403）</option></select></div>
  <label class="check"><input id="f-botstrict" type="checkbox" ${s.bot_strict ? 'checked' : ''}> 严格模式：连同搜索引擎爬虫（Googlebot / Baiduspider 等）一并处置，默认放行以免误伤 SEO 收录</label>
  <details class="https-box" ${s.tls_configured ? 'open' : ''}>
    <summary>HTTPS 证书配置（TLS 监听默认 :8443，按域名 SNI 匹配）</summary>
    <p class="hint">${s.tls_configured ? '已配置手动证书。留空保留，替换时请同时填写证书和私钥。' : '配置手动证书时，请同时填写证书和私钥。'}</p>
    <div class="form-row"><label for="f-cert">证书（PEM 格式，含证书链）</label><textarea id="f-cert" rows="4" placeholder="-----BEGIN CERTIFICATE-----" spellcheck="false"></textarea></div>
    <div class="form-row"><label for="f-key">私钥（PEM 格式）</label><textarea id="f-key" rows="4" placeholder="-----BEGIN PRIVATE KEY-----" spellcheck="false" autocomplete="off"></textarea></div>
    ${s.tls_configured ? '<label class="check"><input id="f-clear-tls" type="checkbox"> 移除站点手动证书</label>' : ''}
    <label class="check"><input id="f-redirect" type="checkbox" ${s.http_redirect ? 'checked' : ''}> HTTP 自动跳转 HTTPS（301）</label>
  </details>
  <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">取消</button>
  <button class="btn" id="site-save">保存</button></div>
  </div></div>`;
  $('#site-save').addEventListener('click', () => saveSite(s.id || 0));
}
function closeModal() { $('#modal-root').innerHTML = ''; }
async function saveSite(id) {
  const body = {
    name: $('#f-name').value.trim(), domain: $('#f-domain').value.trim(),
    upstream: $('#f-upstream').value.trim(), replace_upstream: $('#f-replace-upstream')?.checked || false, waf_mode: $('#f-mode').value,
    cc_rate: +$('#f-cc').value || 0, cc_burst: +$('#f-burst').value || 0,
    auth_user: $('#f-authu').value.trim(), auth_pass: $('#f-authp').value,
    enabled: $('#f-enabled').checked, captcha: $('#f-captcha').checked, resp_detect: $('#f-resp').checked,
    dynamic_mode: $('#f-dyn').value,
    bot_mode: $('#f-bot').value, bot_strict: $('#f-botstrict').checked,
    cert_pem: $('#f-cert').value.trim(), key_pem: $('#f-key').value.trim(),
    clear_tls: $('#f-clear-tls')?.checked || false, http_redirect: $('#f-redirect').checked,
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
  m.innerHTML = pageHead('攻击日志', '检索防护事件，按请求 ID 定位拦截与回源结果',
    `<button class="btn ghost" onclick="openRequestDiagnostic()">${ico('search')}请求诊断</button>`) + `
  <div class="toolbar">
    <input id="q-ip" placeholder="客户端 IP">
    <input id="q-domain" placeholder="站点域名">
    <select id="q-action"><option value="">全部动作</option><option value="waf">WAF拦截</option><option value="semantic">语义检测</option><option value="reputation">信誉封禁</option><option value="cc">CC限频</option><option value="blacklist">黑名单</option><option value="geo">地区限制</option><option value="resp">响应拦截</option><option value="custom">自定义规则</option><option value="dynamic">动态防护</option><option value="bot">Bot防护</option><option value="api_schema">API 契约</option></select>
    <button class="btn" onclick="logPage=1;loadLogs()">${ico('search')}查询</button>
    <button class="btn ghost" onclick="exportCSV()">${ico('download')}导出 CSV</button>
    ${currentAccount.role === 'admin' ? `<details class="toolbar-more">
      <summary class="btn ghost">更多操作</summary>
      <div class="panel menu-items">
        <a class="btn ghost sm" href="/api/report" target="_blank" rel="noopener">${ico('report')}导出防护报告</a>
        <button class="btn danger sm" onclick="clearAttackLogs()">清空日志</button>
      </div>
    </details>` : ''}
  </div>
  <div class="panel table-panel"><table>
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
      <td>${l.req_id ? `<button class="btn ghost sm" onclick="openRequestDiagnostic(logRows[${i}].req_id)">诊断</button>` : ''}
        ${l.rule_id > 0 && (l.action === 'waf' || l.action === 'resp' || l.action === 'semantic') ? `<button class="btn ghost sm" onclick="exclFromLog(${i})">豁免</button>` : ''}</td></tr>`).join('')
      : emptyHTML(11, '暂无记录');
    const pages = Math.max(1, Math.ceil(d.total / d.size));
    $('#log-pager').innerHTML = `共 ${d.total} 条 · ${logPage}/${pages} 页
      <button class="btn ghost sm" ${logPage <= 1 ? 'disabled' : ''} onclick="logPage--;loadLogs()">上一页</button>
      <button class="btn ghost sm" ${logPage >= pages ? 'disabled' : ''} onclick="logPage++;loadLogs()">下一页</button>`;
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

function openRequestDiagnostic(reqID = '') {
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()">
    <section class="modal" role="dialog" aria-modal="true" aria-labelledby="diag-title">
      <h3 id="diag-title">请求诊断</h3>
      <form id="diagnostic-form" class="toolbar">
        <input class="mono" name="requestID" aria-label="请求 ID" placeholder="输入请求 ID" value="${esc(reqID)}" required pattern="[a-fA-F0-9]{12}" maxlength="12" autocomplete="off" spellcheck="false">
        <button class="btn" type="submit">查询</button>
      </form>
      <p class="hint">请求 ID 可在拦截页或响应头 X-NiuB-WAF-Req-ID 中找到。</p>
      <div id="diagnostic-result" class="verify-result" role="status" aria-live="polite"></div>
      <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">关闭</button></div>
    </section></div>`;
  const form = $('#diagnostic-form');
  const input = form.elements.requestID;
  const result = $('#diagnostic-result');
  const button = form.querySelector('button');
  async function lookup() {
    const id = input.value.trim();
    if (!/^[a-fA-F0-9]{12}$/.test(id)) return;
    button.disabled = true;
    result.textContent = '正在查询…';
    try {
      const item = await api('/api/request-diagnostics?id=' + encodeURIComponent(id));
      if (!result.isConnected) return;
      const sources = {waf: 'WAF', origin: '源站', upstream: 'WAF 回源过程', unknown: '未记录'};
      const outcomes = {allowed: '放行', observed: '观察', blocked: '拦截', challenged: '人机验证', redirected: '重定向',
        rejected: '拒绝', origin_error: '源站错误', upstream_error: '回源失败', unknown: '未记录'};
      const sizes = {declared: '客户端声明', read: '实际读取', at_least: '至少已读取'};
      const limits = {upload_policy: '站点上传策略', inspection: '通用完整检测设置', declared_upload: '上传声明长度'};
      const detail = (label, value) => value == null || value === '' ? '' : `<dt>${label}</dt><dd>${esc(value)}</dd>`;
      const bytes = value => `${fmtN(value)} 字节`;
      result.innerHTML = `<dl class="verify-details">
        ${detail('请求 ID', item.req_id)}${detail('时间', inspectionTime(item.ts))}${detail('站点', item.domain)}
        ${detail('请求方法', item.method)}${detail('处置结果', outcomes[item.outcome] || '未记录')}
        ${detail('响应来源', sources[item.source] || '未记录')}${detail('客户端状态码', item.status || '')}
        ${detail('已发起回源', item.upstream_attempted === true ? '是' : item.historical ? '未记录' : '否')}
        ${detail('上游状态码', item.upstream_status || '')}${detail('模块', item.module)}${detail('规则 ID', item.rule_id || '')}
        ${detail('原因', item.reason)}
        ${detail('请求体大小', item.body_bytes == null ? '' : `${bytes(item.body_bytes)}（${sizes[item.body_bytes_kind] || '已记录'}）`)}
        ${detail('生效的请求体上限', item.body_limit_bytes ? bytes(item.body_limit_bytes) : '')}
        ${detail('上限来源', limits[item.body_limit_kind])}
      </dl>${item.observations?.length ? `<p class="hint">观察命中 ${item.observations.map(o => esc(o.module) + (o.rule_id ? ' #' + esc(o.rule_id) : '')).join(' · ')}</p>` : ''}
      ${item.historical ? '<p class="hint">结果来自留存的防护日志，部分过程字段可能未记录。</p>' : ''}`;
    } catch (e) { if (result.isConnected) result.textContent = e.message; }
    finally { button.disabled = false; }
  }
  form.onsubmit = event => { event.preventDefault(); lookup(); };
  if (reqID) lookup(); else input.focus();
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
  <div class="panel table-panel"><table>
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
    <input id="ip-exp" placeholder="过期时间 2026-12-31 00:00:00（可空）" style="min-width:min(100%,230px)">
    <button class="btn" onclick="addIP()">${ico('plus')}添加</button>
  </div>
  <div class="panel table-panel"><table>
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
let shadowCache = [];
const FIELD_LABEL = {ip: 'IP', path: '路径', url: 'URL', method: '方法', header: '请求头', param: '参数', country: '地域'};
const OP_LABEL = {eq: '等于', ne: '不等于', contains: '包含', prefix: '前缀', suffix: '后缀', regex: '正则', cidr: '网段', in: '属于'};
const ruleActionTag = a => ({allow: '<span class="tag green">放行</span>', block: '<span class="tag red">拦截</span>', captcha: '<span class="tag orange">人机验证</span>', log: '<span class="tag blue">观察</span>', redirect: '<span class="tag violet">重定向</span>', rate_limit: '<span class="tag orange">接口限流</span>'}[a] || esc(a));
function condSummary(r) {
  let cs = []; try { cs = JSON.parse(r.conditions || '[]'); } catch {}
  const joiner = r.logic === 'or' ? ' 或 ' : ' 且 ';
  return cs.map(c => `${FIELD_LABEL[c.field] || c.field}${c.name ? '[' + c.name + ']' : ''} ${OP_LABEL[c.op] || c.op} ${c.value}`).join(joiner) || '无条件';
}
async function rules() {
  const m = $('#main');
  m.innerHTML = pageHead('自定义规则', '按 IP/路径/URL/方法/请求头/参数/地域精细匹配 · 支持影子评估与历史回放',
    `<button class="btn ghost" onclick="openRuleReplay()">历史回放</button>
     <button class="btn ghost" id="shadow-refresh" onclick="refreshShadowStats()">${ico('refresh')}刷新影子统计</button>
     <button class="btn" onclick="ruleForm()">${ico('plus')}添加规则</button>`) + `
  <div class="panel table-panel"><table>
  <thead><tr><th>名称</th><th>作用站点</th><th>优先级</th><th>匹配条件</th><th>动作</th><th>状态</th><th>影子统计（命中 / 评估 / 最近命中）</th><th>操作</th></tr></thead>
  <tbody id="rule-body"></tbody></table></div>
  <p class="hint" style="margin-top:10px">优先级数值越小越先匹配。接口限流在访问规则之后评估，命中时使用独立的客户端额度，其他请求使用站点 CC 设置。影子模式和历史回放统计条件命中。放行规则仍需通过已启用的站点认证。</p>`;
  try {
    const [list, sites, shadows] = await Promise.all([api('/api/rules'), api('/api/sites'), api('/api/rules/shadow')]);
    if (!$('#rule-body')) return;
    ruleSites = sites; ruleCache = list; shadowCache = shadows || [];
    renderRuleRows();
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}
function renderRuleRows() {
  const body = $('#rule-body');
  if (!body) return;
  const nameOf = id => id === 0 ? '<span class="tag orange">全局</span>' : esc((ruleSites.find(s => s.id === id) || {}).domain || ('站点#' + id));
  body.innerHTML = ruleCache.length ? ruleCache.map(r => {
    const stats = shadowCache.filter(s => s.rule_id === r.id);
    const matched = stats.reduce((n, s) => n + (+s.matched || 0), 0);
    const evaluated = stats.reduce((n, s) => n + (+s.evaluated || 0), 0);
    const lastHit = stats.reduce((last, s) => s.last_hit && s.last_hit > last ? s.last_hit : last, '');
    const state = !r.enabled ? '<span class="tag off">停用</span>' : r.shadow ? '<span class="tag orange">影子</span>' : '<span class="tag on">生效</span>';
    const shadowText = r.shadow ? `<span class="mono">${fmtN(matched)} / ${fmtN(evaluated)}</span><div class="hint">最近命中：${esc(lastHit || '-')}</div>` : '<span class="hint">—</span>';
    return `<tr>
      <td>${esc(r.name)}</td><td>${nameOf(r.site_id)}</td><td class="mono">${r.priority}</td>
      <td class="url-cell" title="${esc(condSummary(r))}">${esc(condSummary(r))}</td>
      <td>${ruleActionTag(r.action)}${r.action === 'rate_limit' ? `<div class="hint">${esc(r.action_param.split(',')[0].trim())} 请求/秒</div>` : ''}</td><td>${state}</td><td>${shadowText}</td>
      <td><button class="btn ghost sm" onclick="editRule(${r.id})">编辑</button>
          <button class="btn ghost sm" onclick="openRuleReplay(${r.id})">回放</button>
          <button class="btn danger sm" onclick="delRule(${r.id})">删除</button></td></tr>`;
  }).join('') : emptyHTML(8, '暂无自定义规则');
}
async function refreshShadowStats() {
  const btn = $('#shadow-refresh');
  if (btn) btn.disabled = true;
  try {
    const stats = await api('/api/rules/shadow');
    shadowCache = stats || [];
    renderRuleRows();
    toast('影子统计已刷新');
  } catch (e) { toast(e.message, true); }
  finally { if (btn) btn.disabled = false; }
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
  $('#r-rate-row').classList.toggle('hidden', a !== 'rate_limit');
  if (a === 'redirect') { row.style.display = ''; label.textContent = '重定向目标（/ 站内路径或 http(s) 地址）'; }
  else if (a === 'block') { row.style.display = ''; label.textContent = '拦截原因（可选）'; }
  else { row.style.display = 'none'; }
}
function ruleForm(r) {
  r = r || {name: '', site_id: 0, priority: 100, logic: 'and', conditions: '[]', action: 'block', action_param: '', enabled: true, shadow: true, note: ''};
  const [rate, burst] = r.action === 'rate_limit' ? r.action_param.split(',').map(s => s.trim()) : [];
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
      <option value="rate_limit" ${r.action === 'rate_limit' ? 'selected' : ''}>接口限流（429）</option>
      <option value="redirect" ${r.action === 'redirect' ? 'selected' : ''}>重定向（302）</option></select></div>
    <div class="form-row" id="r-param-row"><label id="r-param-label">拦截原因（可选）</label><input id="r-param" value="${esc(r.action === 'rate_limit' ? '' : r.action_param || '')}"></div>
  </div>
  <div class="form-grid hidden" id="r-rate-row">
    <div class="form-row"><label for="r-rate">每个客户端每秒请求数</label><input id="r-rate" type="number" min="1" max="1000000" step="1" value="${esc(rate ?? 10)}"></div>
    <div class="form-row"><label for="r-burst">突发容量（留空时同速率）</label><input id="r-burst" type="number" min="0" max="1000000" step="1" value="${esc(burst ?? '')}"></div>
  </div>
  <label class="check"><input id="r-enabled" type="checkbox" ${r.enabled ? 'checked' : ''}> 启用规则</label>
  <label class="check"><input id="r-shadow" type="checkbox" ${r.shadow ? 'checked' : ''}> 影子模式（仅匹配统计，不执行动作；新建规则默认启用）</label>
  <div class="form-row"><label>备注</label><input id="r-note" value="${esc(r.note || '')}"></div>
  <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">取消</button>
  <button class="btn ghost" onclick="replayDraftFromForm(${r.id || 0})">用当前草稿回放</button>
  <button class="btn" onclick="saveRule(${r.id || 0})">保存</button></div>
  </div></div>`;
  toggleActionParam();
}
function readRuleForm(id = 0) {
  const conds = [...document.querySelectorAll('#r-conds .cond-row')].map(row => ({
    field: row.querySelector('.c-field').value, op: row.querySelector('.c-op').value,
    name: row.querySelector('.c-name').value.trim(), value: row.querySelector('.c-value').value,
  })).filter(c => c.value !== '' || c.op === 'eq' || c.op === 'ne');
  if (!conds.length) { toast('请至少填写一个有效匹配条件', true); return null; }
  const action = $('#r-action').value;
  let actionParam = $('#r-param').value.trim();
  if (action === 'rate_limit') {
    const rate = $('#r-rate'), burst = $('#r-burst');
    if (!rate.value || !rate.checkValidity() || !burst.checkValidity()) {
      toast('请输入有效的每秒速率和突发容量', true);
      return null;
    }
    actionParam = burst.value ? rate.valueAsNumber + ',' + burst.valueAsNumber : String(rate.valueAsNumber);
  }
  const body = {
    id, name: $('#r-name').value.trim(), site_id: +$('#r-site').value || 0,
    priority: +$('#r-priority').value || 0, logic: $('#r-logic').value,
    conditions: JSON.stringify(conds), action,
    action_param: actionParam, enabled: $('#r-enabled').checked,
    shadow: $('#r-shadow').checked, note: $('#r-note').value.trim(),
  };
  if (!body.name) { toast('请填写规则名称', true); return null; }
  return body;
}
async function saveRule(id) {
  const body = readRuleForm(id);
  if (!body) return;
  const previous = ruleCache.find(r => r.id === id);
  if (previous && previous.shadow && !body.shadow && !confirm('确认将影子规则切换为真实执行？启用后，匹配请求将执行该规则动作。')) return;
  try {
    await api('/api/rules' + (id ? '/' + id : ''), {method: id ? 'PUT' : 'POST', body});
    closeModal(); toast(body.shadow ? '影子规则已保存，仅进行评估统计' : '规则已保存，即时生效'); rules();
  } catch (e) { toast(e.message, true); }
}
async function delRule(id) {
  if (!confirm('确认删除该自定义规则？')) return;
  try { await api('/api/rules/' + id, {method: 'DELETE'}); toast('已删除'); rules(); }
  catch (e) { toast(e.message, true); }
}

let replayChoices = [];
let replayReturnRule = null;
const replayLocalTime = d => {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
};
function openRuleReplay(id) {
  if (!ruleCache.length) return toast('请先创建自定义规则，或在规则编辑表单中使用当前草稿回放', true);
  replayReturnRule = null;
  showRuleReplay(false, id);
}
function replayDraftFromForm(id) {
  const draft = readRuleForm(id);
  if (!draft) return;
  replayReturnRule = {...draft};
  showRuleReplay(true, id);
}
function showRuleReplay(isDraft, selectedID) {
  replayChoices = isDraft ? [replayReturnRule] : ruleCache;
  let selected = Math.max(0, replayChoices.findIndex(r => r.id === selectedID));
  if (isDraft) selected = 0;
  const now = new Date(), from = new Date(now.getTime() - 24 * 3600 * 1000);
  const chooser = isDraft
    ? `<input value="${esc(replayChoices[0].name)}（未保存草稿）" readonly>`
    : `<select id="replay-rule" onchange="clearReplayResult()">${replayChoices.map((r, i) => `<option value="${i}" ${i === selected ? 'selected' : ''}>${esc(r.name)} · ${r.site_id === 0 ? '全局' : '站点#' + r.site_id}</option>`).join('')}</select>`;
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeRuleReplay()"><div class="modal modal-wide" role="dialog" aria-modal="true" aria-label="历史回放">
  <h3>历史回放${isDraft ? ' · 当前规则草稿' : ''}</h3>
  <p class="hint">仅回放攻击日志中已记录的安全事件，不含请求 header/body，也不是全量正常流量；回放不会保存草稿或执行规则动作。</p>
  <div class="form-row"><label>回放规则</label>${chooser}</div>
  <div class="form-grid">
    <div class="form-row"><label>开始时间</label><input id="replay-from" type="datetime-local" value="${replayLocalTime(from)}"></div>
    <div class="form-row"><label>结束时间</label><input id="replay-to" type="datetime-local" value="${replayLocalTime(now)}"></div>
  </div>
  <div class="form-grid">
    <div class="form-row"><label>扫描上限 limit（1–10000）</label><input id="replay-limit" type="number" min="1" max="10000" value="1000"></div>
    <div class="form-row"><label>样本上限 sample_limit（1–100）</label><input id="replay-sample-limit" type="number" min="1" max="100" value="20"></div>
  </div>
  <div class="form-grid">
    <div class="form-row"><label>域名（可选）</label><input id="replay-domain" placeholder="example.com"></div>
    <div class="form-row"><label>客户端 IP（可选）</label><input id="replay-ip" placeholder="192.0.2.1"></div>
  </div>
  <div class="form-row"><label>原攻击动作（可选）</label><input id="replay-action" placeholder="如 waf、cc、custom"></div>
  <div class="modal-actions"><button class="btn ghost" onclick="closeRuleReplay()">${isDraft ? '返回规则草稿' : '关闭'}</button>
  <button class="btn" id="replay-run" onclick="runRuleReplay()">开始回放</button></div>
  <div id="replay-result" style="margin-top:14px"></div>
  </div></div>`;
}
function clearReplayResult() { const el = $('#replay-result'); if (el) el.textContent = ''; }
function closeRuleReplay() {
  if (replayReturnRule) {
    const draft = replayReturnRule;
    replayReturnRule = null;
    ruleForm(draft);
  } else closeModal();
}
async function runRuleReplay() {
  const select = $('#replay-rule');
  const rule = replayChoices[select ? +select.value : 0];
  if (!rule) return toast('请选择回放规则', true);
  const timeValue = id => {
    const raw = $(id).value;
    return raw && raw.length === 16 ? raw + ':00' : raw;
  };
  const body = {
    rule, from: timeValue('#replay-from'), to: timeValue('#replay-to'),
    limit: +$('#replay-limit').value || 1000, sample_limit: +$('#replay-sample-limit').value || 20,
    domain: $('#replay-domain').value.trim(), ip: $('#replay-ip').value.trim(), action: $('#replay-action').value.trim(),
  };
  const btn = $('#replay-run'), result = $('#replay-result');
  if (btn) { btn.disabled = true; btn.textContent = '回放中…'; }
  if (result) result.textContent = '正在扫描攻击日志…';
  try {
    const d = await api('/api/rules/replay', {method: 'POST', body});
    renderReplayResult(d);
  } catch (e) {
    if (result) result.textContent = '回放失败：' + e.message;
    toast(e.message, true);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '开始回放'; }
  }
}
function renderReplayResult(d) {
  const box = $('#replay-result');
  if (!box) return;
  const resultTag = value => {
    const item = {
      matched: ['red', 'matched 命中'], not_matched: ['green', 'not_matched 未命中'],
      indeterminate: ['orange', 'indeterminate 无法确定'], invalid: ['off', 'invalid 无效'],
    }[value];
    return item ? `<span class="tag ${item[0]}">${item[1]}</span>` : `<span class="tag">${esc(value)}</span>`;
  };
  const samples = Array.isArray(d.samples) ? d.samples : [];
  box.innerHTML = `<div class="panel" style="padding:12px;overflow:auto">
    <div class="toolbar" style="margin-bottom:10px">
      <span class="tag red">matched ${fmtN(d.matched)}</span><span class="tag green">not_matched ${fmtN(d.not_matched)}</span>
      <span class="tag orange">indeterminate ${fmtN(d.indeterminate)}</span><span class="tag off">invalid ${fmtN(d.invalid)}</span>
      <span class="tag ${d.truncated ? 'orange' : 'blue'}">truncated ${d.truncated ? 'true' : 'false'}</span>
      <span class="hint">扫描 ${fmtN(d.scanned)} 条</span></div>
    <p class="hint">时间 ${esc(d.from || '-')} 至 ${esc(d.to || '-')} · 域名 ${esc(d.domain || '全部')} · IP ${esc(d.ip || '全部')} · 动作 ${esc(d.action || '全部')}</p>
    <p class="hint">仅攻击日志，不含 header/body，不是全量正常流量。${d.truncated ? '结果已达到扫描上限，可缩小范围后重试。' : ''}</p>
    <table><thead><tr><th>回放结果</th><th>时间</th><th>站点 / IP</th><th>方法 / URI</th><th>原动作 / 描述</th></tr></thead><tbody>
    ${samples.length ? samples.map(s => {
      const l = s.log || {};
      return `<tr><td>${resultTag(s.result)}</td><td class="mono">${esc(l.ts)}</td>
        <td>${esc(l.domain)}<div class="hint mono">${esc(l.client_ip)}</div></td>
        <td>${esc(l.method)}<div class="url-cell mono" title="${esc(l.url)}">${esc(l.url)}</div></td>
        <td>${actionTag(l.action)}<div class="hint">${esc(l.msg)}</div></td></tr>`;
    }).join('') : emptyHTML(5, '暂无回放样本')}
    </tbody></table></div>`;
}

/* ---------------- IP 信誉（本地攻击历史自动封禁） ---------------- */
const INTEL_SECRET_KEYS = ['intel_api_key', 'intel_api_url'];
const ALERT_SECRET_KEYS = ['alert_webhook', 'alert_dingtalk', 'alert_wecom'];

function secretField(key, label) {
  return `<div class="form-row">
    <label for="secret-${key}">${label}</label>
    <input id="secret-${key}" type="password" autocomplete="new-password" spellcheck="false" placeholder="输入新值">
    <label class="check"><input id="clear-${key}" type="checkbox" disabled> 清除已保存的值</label>
  </div>`;
}

function setSecretField(key, configured) {
  const field = $('#secret-' + key);
  const clear = $('#clear-' + key);
  field.value = '';
  field.dataset.configured = String(configured);
  field.placeholder = configured ? '已配置，留空保留' : '未配置';
  clear.checked = false;
  clear.disabled = !configured;
}

function readSecretFields(keys) {
  const values = {};
  for (const key of keys) {
    const value = $('#secret-' + key).value.trim();
    if ($('#clear-' + key).checked) values[key] = '';
    else if (value) values[key] = value;
  }
  return values;
}

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
  <details class="panel"><summary>IP 情报源 <span id="intel-threat" class="hint"></span></summary>
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
      <button class="btn" onclick="saveIntel()">保存</button>
      <button class="btn ghost" onclick="testIntel()">测试连通</button>
    </div>
    <div class="form-grid">
      ${secretField('intel_api_key', 'API Key（Bearer）')}
      ${secretField('intel_api_url', '接口地址（含 {ip}）')}
    </div>
    <p class="hint">可选接入第三方威胁情报（代理/VPN/Tor/僵尸网络/扫描器等标签）。通用接口需返回 JSON，URL 用 <code>{ip}</code> 占位待查 IP，密钥以 Bearer 头发送；识别 proxy/vpn/tor/botnet/malicious/scanner/hosting 等布尔字段与 tags 数组、threat_score/risk_score 评分。默认关闭，零密钥可运行；结果按 IP 缓存 24 小时。仅作展示标签，不参与自动封禁。</p>
    <div id="intel-test-result"></div>
  </details>
  <div class="panel"><h3>IP 裁决查询</h3>
    <div class="toolbar">
      <input id="rep-lookup-ip" placeholder="输入 IP，如 1.2.3.4" style="min-width:min(100%,220px)">
      <button class="btn" onclick="repLookup()">${ico('search')}查询</button>
    </div>
    <div id="rep-lookup-result"></div>
  </div>
  <div class="panel table-panel"><table>
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
    for (const key of INTEL_SECRET_KEYS) setSecretField(key, s[key + '_configured'] === 'true');
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
  const secrets = readSecretFields(INTEL_SECRET_KEYS);
  try {
    await api('/api/settings', {method: 'PUT', body: {
      intel_provider: $('#intel-provider').value,
      ...secrets,
    }});
    for (const [key, value] of Object.entries(secrets)) setSecretField(key, !!value);
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
      <input id="geo-countries" placeholder="国家代码，逗号分隔，如 CN,US,JP" style="min-width:min(100%,280px)">
      <button class="btn" onclick="saveGeo()">保存</button>
      <span id="geo-status" class="hint"></span>
    </div>
    <p class="hint">需要将 mmdb 格式的 GeoIP 数据库文件放置于 data/geoip.mmdb 后重启。ip2region.xdb 仅补充城市展示，地域限制策略仍以 mmdb 国家库（ISO 码）为准。</p>
  </div>
  <div class="panel"><h3>可信代理（真实客户端 IP 解析）</h3>
    <div class="toolbar">
      <input id="trusted-proxies" placeholder="可信代理 IP/CIDR，逗号分隔，如 10.0.0.0/8,192.168.1.5" style="min-width:min(100%,320px)">
      <button class="btn" onclick="saveTrusted()">保存</button>
    </div>
    <p class="hint">仅填写实际前置代理的 IP 或 CIDR。公网入口须清理客户端自带的 X-Forwarded-For 和 X-Real-IP，并用连接来源重建转发头。WAF 从右向左检查完整的 X-Forwarded-For 链，无法识别客户端时使用直连 IP。没有 X-Forwarded-For 时才接受可信代理提供的单个 X-Real-IP。留空则始终使用直连 IP。</p>
  </div>
  <div class="panel"><h3>告警通知（攻击激增推送）</h3>
    <div class="toolbar">
      <select id="alert-enabled"><option value="off">关闭</option><option value="on">启用</option></select>
      <label class="hint">阈值</label><input id="alert-threshold" type="number" min="1" style="width:80px"> 次
      <label class="hint">窗口</label><input id="alert-window" type="number" min="10" style="width:70px"> 秒
      <label class="hint">冷却</label><input id="alert-cooldown" type="number" min="10" style="width:80px"> 秒
    </div>
    <div class="form-grid">
      ${secretField('alert_webhook', '通用 Webhook（POST JSON）')}
      ${secretField('alert_dingtalk', '钉钉机器人 Webhook')}
      ${secretField('alert_wecom', '企业微信机器人 Webhook')}
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
  <div class="panel"><h3>自定义拦截页面</h3>
    <p class="hint" style="margin-bottom:10px">支持占位符：{{REQ_ID}} {{REASON}} {{CLIENT_IP}} {{DOMAIN}} {{TIME}} {{RULE_ID}}，留空使用默认页面。</p>
    <textarea id="block-page" style="width:100%;min-height:180px;font-family:var(--mono);font-size:12px"></textarea>
    <div style="margin-top:12px;display:flex;gap:10px"><button class="btn" onclick="saveBlockPage()">保存</button>
    <button class="btn ghost" onclick="previewBlock()">预览</button></div>
  </div>
  <div class="panel"><h3>Bot 来源和行为</h3>
    <label class="check"><input id="bot-verify-crawlers" type="checkbox">使用官方网段验证 Googlebot 和 Bingbot</label>
    <div class="toolbar">
      <label class="hint" for="bot-path-limit">每个客户端 10 秒内的新路径数</label>
      <input id="bot-path-limit" type="number" min="0" max="128" step="1">
      <button class="btn" id="bot-policy-save">保存</button>
    </div>
    <p class="hint">适用于启用了 Bot 防护的站点。路径数设为 0 时关闭行为判定。已验证的爬虫免于新路径限额。</p>
    <p class="hint" id="bot-crawler-sources"></p>
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
  <div class="panel"><h3>请求体缓冲上限</h3>
    <div class="toolbar">
      <label class="hint">上限</label><input id="body-inspect-kb" type="number" min="64" max="102400" style="width:120px"> KB
      <button class="btn" onclick="saveBodyInspect()">保存</button>
    </div>
    <p class="hint">默认 2048 KB，范围 64–102400 KB。通用请求体大小还受完整送检上限约束。</p>
  </div>
  <div class="panel"><h3>请求体完整送检上限</h3>
    <div class="toolbar">
      <label class="hint">送检</label><input id="body-scan-kb" type="number" min="16" max="1024" style="width:120px"> KB
      <button class="btn" onclick="saveBodyScan()">保存</button>
    </div>
    <p class="hint">默认 16 KB，范围 16–1024 KB。通用上限取两项上限的较小值。大文件接口可在「防护站点 → 上传策略」配置。超限返回 413，压缩请求体返回 415。</p>
  </div>
  <div class="panel"><h3>允许的请求体 Content-Type</h3>
    <div class="toolbar">
      <input id="allowed-ct" type="text" placeholder="例如 text/plain,application/octet-stream" style="flex:1">
      <button class="btn" onclick="saveAllowedCT()">保存</button>
    </div>
    <p class="hint">默认已允许：x-www-form-urlencoded、multipart/form-data、multipart/related、text/xml、application/xml、application/soap+xml、application/json、application/cloudevents+json、application/cloudevents-batch+json。若业务提交 text/plain 等类型请求体被拦截（规则 920420 请求体类型不受支持），在此追加即可放行该类型。逗号分隔，最多 32 项；保存会重建检测引擎（约 1 秒）并即时生效，追加的类型越多、可绕过的协议面越宽，按需最小化。</p>
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
    for (const key of ALERT_SECRET_KEYS) setSecretField(key, s[key + '_configured'] === 'true');
    $('#acme-enabled').value = s.acme_enabled || 'off';
    $('#acme-staging').value = s.acme_staging || 'on';
    $('#acme-domains').value = s.acme_domains || '';
    $('#acme-email').value = s.acme_email || '';
    $('#body-inspect-kb').value = s.body_inspect_kb || 2048;
    $('#body-scan-kb').value = s.body_scan_kb || 16;
    $('#allowed-ct').value = s.allowed_content_types || '';
    $('#bot-verify-crawlers').checked = s.bot_verify_crawlers === 'on';
    $('#bot-path-limit').value = s.bot_path_limit || '0';
    renderCrawlerSources(s);
    $('#bot-policy-save').onclick = saveBotPolicy;
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

async function saveBotPolicy() {
  try {
    await api('/api/settings', {method: 'PUT', body: {
      bot_verify_crawlers: $('#bot-verify-crawlers').checked ? 'on' : 'off',
      bot_path_limit: $('#bot-path-limit').value,
    }});
    toast('Bot 策略已保存');
    renderCrawlerSources(await api('/api/settings'));
  } catch (e) { toast(e.message, true); }
}

function renderCrawlerSources(config) {
  const target = $('#bot-crawler-sources');
  if (!target) return;
  target.textContent = config.bot_verify_crawlers === 'on' ?
    (config.bot_crawler_sources ? '已加载官方网段：' + config.bot_crawler_sources : '官方网段未就绪，暂按 UA 识别') : '来源验证已关闭';
}

async function operations() {
  $('#main').innerHTML = pageHead('运行维护', '引擎版本、运行巡检、配置迁移与备份') + `
  <div class="panel">
    <h3>运行信息</h3>
    <dl id="ops-runtime" class="runtime-info">
      <div><dt>OWASP CRS</dt><dd id="ops-crs">—</dd></div>
      <div><dt>GeoIP 国家库</dt><dd id="ops-geo">—</dd></div>
    </dl>
  </div>
  <div class="panel"><h3>运行巡检</h3>
    <p class="hint">检查证书、上游健康状态、磁盘、备份和地域库。巡检通知使用<a href="#/settings">安全设置</a>中的告警配置。</p>
    <div class="form-grid">${inspectionFieldsHTML()}</div>
    <div class="toolbar" style="margin-top:12px">
      <button class="btn" onclick="saveInspectionSettings()">保存巡检设置</button>
      <button class="btn" id="inspection-run" onclick="runInspection()">立即巡检</button>
      <button class="btn ghost" onclick="loadInspections()">${ico('refresh')}刷新结果</button>
      <span class="tag" id="inspection-running">running：否</span><span class="hint" id="inspection-last">last：尚未加载</span>
    </div>
    <div id="inspection-results" style="margin-top:12px"></div>
  </div>
  <div class="panel"><h3>Prometheus 指标</h3>
    ${secretField('metrics_token', '抓取令牌')}
    <div class="toolbar">
      <button class="btn" onclick="saveMetrics()">保存</button>
      <button class="btn ghost" onclick="copyScrape()">复制抓取配置</button>
    </div>
    <p class="hint">抓取端点 <code>/metrics</code>（管理端口，默认 9443）。已配置令牌时，请将令牌填入 Prometheus 抓取配置。清除令牌后仅允许环回地址访问。指标含请求量与时延直方图、攻击计数、上游健康与排队、超时和拒绝数、信誉封禁数、响应字节与 Go 运行时。</p>
  </div>
  <div class="panel"><h3>响应检测覆盖</h3>
    <p class="hint">统计当前节点自启动以来已启用响应检测的站点。流式和部分下载响应保留原转发方式。</p>
    <dl id="ops-response" class="runtime-info" style="margin-top:12px" aria-live="polite"></dl>
  </div>
  <div class="panel"><h3>审计日志采集</h3>
    <p class="hint">采集器通过 Bearer 令牌读取 <code>/audit/events?after_id=0</code>，使用返回的 <code>X-NiuB-Audit-Next-ID</code> 继续采集。</p>
    <div class="toolbar">
      <input id="audit-token" type="password" autocomplete="new-password" placeholder="新采集令牌">
      <button class="btn" id="audit-feed-enable">保存令牌</button>
      <button class="btn ghost" id="audit-feed-disable">停用</button>
      <span class="hint" id="audit-feed-state"></span>
    </div>
  </div>
  <div class="panel"><h3>配置导入与导出</h3>
    <p class="hint">配置包已脱敏但不加密，请按敏感文件保护下载与传输过程；证书、证书私钥和站点认证口令不随包同步，节点本地认证与管理密钥也不会同步。</p>
    <div class="toolbar">
      <input id="config-source" placeholder="来源标签，如 node-a" value="" style="min-width:min(100%,220px)">
      <button class="btn" id="config-export" onclick="exportConfigPackage()">${ico('download')}导出并下载 JSON</button>
    </div>
    <div class="form-grid" style="margin-top:14px">
      <div class="form-row"><label>选择本地 JSON 配置包（最大 4 MiB）</label><input id="config-file" type="file" accept=".json,application/json" onchange="loadConfigPackage(this)"></div>
      <div class="form-row"><label>导入模式</label><select id="config-mode" onchange="resetConfigImportPreview()"><option value="merge">merge（合并，不删除目标独有项）</option><option value="replace">replace（替换，删除目标独有项）</option></select></div>
    </div>
    <div id="config-package-meta" class="hint" style="margin-top:8px">尚未载入配置包；包和预览仅保存在当前页面内存中。</div>
    <div class="toolbar" style="margin-top:10px"><button class="btn" id="config-preview-btn" onclick="previewConfigImport()">预览导入</button><span class="hint">必须先预览，应用时会校验包、目标和预览摘要。</span></div>
    <div id="config-preview" style="margin-top:12px"></div>
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
  const runtime = $('#ops-runtime');
  restoreConfigImportUI();
  try {
    const [stats, settings, auditFeed] = await Promise.all([api('/api/stats'), api('/api/settings'), api('/api/audit/feed')]);
    if (!runtime.isConnected) return;
    $('#ops-crs').textContent = stats.crs_version || '—';
    $('#ops-geo').textContent = stats.geoip_available ? '已加载' : '未加载';
    const responseCounts = stats.response_inspection || {};
    const responseLabels = {complete:'完整检查',partial:'正文前缀',blocked:'检测拦截',no_body:'无正文',stream:'流式或升级（仅响应头）',
      range:'分段下载（仅响应头）',media_type:'其他类型（仅响应头）',encoding:'其他编码（仅响应头）',decode_error:'解码失败',read_error:'读取失败',engine_error:'检测未完成'};
    $('#ops-response').innerHTML = Object.entries(responseLabels).filter(([key]) => responseCounts[key] > 0)
      .map(([key, label]) => `<div><dt>${label}</dt><dd>${fmtN(responseCounts[key])}</dd></div>`).join('') || '<div class="hint">暂无检测记录</div>';
    setSecretField('metrics_token', settings.metrics_token_configured === 'true');
    $('#audit-feed-state').textContent = auditFeed.enabled ? '采集已开启' : '采集已关闭';
    $('#audit-feed-enable').onclick = () => configureAuditFeed($('#audit-token').value.trim(), true);
    $('#audit-feed-disable').onclick = () => configureAuditFeed('', false);
    INSPECT_FIELDS.forEach(([key, , fallback]) => { $('#' + key).value = settings[key] ?? fallback; });
    await Promise.all([loadBackups(), loadInspections()]);
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

async function configureAuditFeed(token, enable) {
  if (enable && !token) { toast('请输入采集令牌', true); return; }
  try {
    const result = await api('/api/audit/feed', {method: 'PUT', body: {token}});
    $('#audit-token').value = '';
    $('#audit-feed-state').textContent = result.enabled ? '采集已开启' : '采集已关闭';
    toast('采集设置已保存');
  } catch (e) { toast(e.message, true); }
}

/* ---------------- 配置同步（包与预览仅存于内存） ---------------- */
let configImportPackage = null;
let configImportPreview = null;
let configImportPreviewMode = '';
let configImportMode = 'merge';
let configImportFileName = '';
let configImportRevision = 0;
function configPackageSummary(pkg) {
  if (!pkg) return '尚未载入配置包；包和预览仅保存在当前页面内存中。';
  return `已载入 ${configImportFileName || '内存配置包'} · 来源 ${pkg.source_label || '-'} · 格式 ${pkg.kind || '-'} v${pkg.format_version ?? '-'} · 导出时间 ${pkg.created_at || '-'}`;
}
function restoreConfigImportUI() {
  const mode = $('#config-mode'), meta = $('#config-package-meta');
  if (mode) mode.value = configImportMode;
  if (meta) meta.textContent = configPackageSummary(configImportPackage);
  if (configImportPreview) renderConfigImportPreview(configImportPreview);
}
function resetConfigImportPreview() {
  const mode = $('#config-mode');
  if (mode) configImportMode = mode.value;
  configImportRevision++;
  configImportPreview = null;
  configImportPreviewMode = '';
  const box = $('#config-preview');
  if (box) box.textContent = '';
}
async function loadConfigPackage(input) {
  resetConfigImportPreview();
  configImportPackage = null;
  configImportFileName = '';
  const file = input.files && input.files[0];
  const meta = $('#config-package-meta');
  if (!file) { if (meta) meta.textContent = configPackageSummary(null); return; }
  try {
    if (file.size > 4 * 1024 * 1024) throw new Error('配置包超过 4 MiB 上限');
    const pkg = JSON.parse(await file.text());
    if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) throw new Error('JSON 顶层必须是配置包对象');
    configImportPackage = pkg;
    configImportFileName = file.name;
    if (meta) meta.textContent = configPackageSummary(pkg);
  } catch (e) {
    input.value = '';
    if (meta) meta.textContent = '配置包读取失败：' + e.message;
    toast('配置包读取失败：' + e.message, true);
  }
}
async function exportConfigPackage() {
  const btn = $('#config-export');
  if (btn) btn.disabled = true;
  try {
    const pkg = await api('/api/config/export', {method: 'POST', body: {source_label: $('#config-source').value.trim()}});
    const url = URL.createObjectURL(new Blob([JSON.stringify(pkg, null, 2)], {type: 'application/json'}));
    const a = document.createElement('a');
    a.href = url; a.download = 'niubwaf-config.json';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    toast('配置包已导出；已脱敏但不加密，请妥善保管');
  } catch (e) { toast(e.message, true); }
  finally { if (btn) btn.disabled = false; }
}
async function previewConfigImport() {
  if (!configImportPackage) return toast('请先选择本地 JSON 配置包', true);
  const pkg = configImportPackage;
  const mode = $('#config-mode').value;
  configImportMode = mode;
  const revision = ++configImportRevision;
  configImportPreview = null;
  configImportPreviewMode = '';
  const btn = $('#config-preview-btn'), box = $('#config-preview');
  if (btn) btn.disabled = true;
  if (box) box.textContent = '正在生成导入预览…';
  try {
    const preview = await api('/api/config/import/preview', {method: 'POST', body: {package: pkg, mode}});
    if (revision !== configImportRevision || pkg !== configImportPackage) return;
    configImportPreview = preview;
    configImportPreviewMode = mode;
    renderConfigImportPreview(preview);
  } catch (e) {
    if (revision === configImportRevision && box) box.textContent = '预览失败：' + e.message;
    toast(e.message, true);
  } finally { if (btn) btn.disabled = false; }
}
function configDeleteTotal(preview) {
  return Object.values(preview.stats || {}).reduce((total, stat) => total + (+stat.delete || 0), 0);
}
function renderConfigImportPreview(preview) {
  const box = $('#config-preview');
  if (!box) return;
  const stats = Object.entries(preview.stats || {});
  const warnings = Array.isArray(preview.warnings) ? preview.warnings : [];
  const diff = Array.isArray(preview.diff) ? preview.diff : [];
  const deletions = Array.isArray(preview.deletions) ? preview.deletions : [];
  const deleteTotal = configDeleteTotal(preview);
  const resourceName = {sites: '站点', settings: '设置', custom_rules: '自定义规则', exclusions: '规则豁免', ip_lists: 'IP 名单'};
  const boundedNote = (shown, total) => total > shown ? `仅展示前 ${shown} 条，共 ${total} 条。` : '';
  box.innerHTML = `<div class="panel" style="padding:12px;overflow:auto">
    <h3>导入预览 · ${esc(preview.mode || configImportPreviewMode)}</h3>
    <p class="hint">diff 与 deletions 各最多展示 100 条；删除确认数以完整统计为准，不受展示上限影响。</p>
    <table><thead><tr><th>资源</th><th>新增</th><th>更新</th><th>跳过</th><th>删除</th><th>不变</th></tr></thead><tbody>
      ${stats.map(([key, stat]) => `<tr><td>${esc(resourceName[key] || key)}</td><td>${fmtN(stat.create)}</td><td>${fmtN(stat.update)}</td><td>${fmtN(stat.skip)}</td><td>${fmtN(stat.delete)}</td><td>${fmtN(stat.unchanged)}</td></tr>`).join('') || emptyHTML(6, '暂无统计')}
    </tbody></table>
    <div class="sub-h" style="margin-top:12px">Warnings</div>
    ${warnings.length ? `<ul class="hint">${warnings.slice(0, 50).map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : '<p class="hint">无</p>'}
    <div class="sub-h" style="margin-top:12px">Diff（${diff.length}）</div>
    <p class="hint">${preview.diff_truncated ? '服务端 diff 已截断；统计与 deletions 仍完整。' : ''}${boundedNote(Math.min(diff.length, 100), diff.length)}</p>
    <table><thead><tr><th>资源</th><th>动作</th><th>自然键</th><th>变化字段</th></tr></thead><tbody>
      ${diff.slice(0, 100).map(d => `<tr><td>${esc(resourceName[d.resource] || d.resource)}</td><td>${esc(d.action)}</td><td class="mono">${esc(d.key)}</td><td>${(d.fields || []).map(f => esc(f)).join(', ') || '-'}</td></tr>`).join('') || emptyHTML(4, '无配置差异')}
    </tbody></table>
    <div class="sub-h" style="margin-top:12px">Deletions（${deletions.length}）· 删除总数 ${deleteTotal}</div>
    <p class="hint">${boundedNote(Math.min(deletions.length, 100), deletions.length)}</p>
    <table><thead><tr><th>资源</th><th>将删除的自然键</th></tr></thead><tbody>
      ${deletions.slice(0, 100).map(d => `<tr><td>${esc(resourceName[d.resource] || d.resource)}</td><td class="mono">${esc(d.key)}</td></tr>`).join('') || emptyHTML(2, '无删除项')}
    </tbody></table>
    ${preview.mode === 'replace' ? `<div class="panel" style="padding:12px;margin-top:12px">
      <label class="check"><input id="config-replace-confirm" type="checkbox"> 我明确确认使用 replace，并同意删除预览列出的 ${deleteTotal} 条目标配置</label>
      <div class="form-row" style="margin-top:10px"><label>输入准确删除总数以确认（${deleteTotal}）</label><input id="config-delete-count" type="number" min="0" step="1" placeholder="请输入 ${deleteTotal}"></div>
    </div>` : ''}
    <div class="modal-actions"><button class="btn danger" id="config-apply" onclick="applyConfigImport()">确认应用导入</button></div>
  </div>`;
}
async function applyConfigImport() {
  const preview = configImportPreview, pkg = configImportPackage, mode = configImportPreviewMode;
  if (!preview || !pkg || !mode) return toast('预览已失效，请重新预览', true);
  if ($('#config-mode').value !== mode) return toast('导入模式已变化，请重新预览', true);
  const deletes = configDeleteTotal(preview);
  let confirmDeletes = 0;
  if (mode === 'replace') {
    if (!$('#config-replace-confirm').checked) return toast('请明确勾选 replace 删除确认', true);
    const raw = $('#config-delete-count').value.trim();
    if (!raw || !Number.isInteger(+raw) || +raw !== deletes) return toast(`请输入准确删除总数 ${deletes}`, true);
    confirmDeletes = +raw;
  }
  const revision = configImportRevision;
  const btn = $('#config-apply'), box = $('#config-preview');
  if (btn) btn.disabled = true;
  try {
    await api('/api/config/import/apply', {method: 'POST', body: {
      package: pkg, mode, package_sha256: preview.package_sha256,
      target_sha256: preview.target_sha256, preview_sha256: preview.preview_sha256,
      confirm_deletes: confirmDeletes,
    }});
    if (revision === configImportRevision) {
      configImportRevision++;
      configImportPreview = null;
      configImportPreviewMode = '';
      if (box) box.textContent = '配置已成功应用。原预览已失效；如需再次导入，请重新预览。';
    }
    toast('配置导入已应用');
  } catch (e) {
    if (e.status === 409 && revision === configImportRevision) {
      configImportRevision++;
      configImportPreview = null;
      configImportPreviewMode = '';
      if (box) box.textContent = '目标配置已在预览后变化（409），原预览已失效，请重新预览后再应用。';
      toast('目标配置已变化，请重新预览', true);
    } else toast(e.message, true);
  } finally { if (btn) btn.disabled = false; }
}

/* ---------------- 运行巡检 ---------------- */
const INSPECT_FIELDS = [
  ['inspect_interval_sec', '巡检间隔', 60, 30, 3600, '秒'],
  ['inspect_cert_warn_days', '证书到期预警', 14, 1, 90, '天'],
  ['inspect_upstream_failures', '上游异常确认次数', 3, 1, 20, '次'],
  ['inspect_disk_free_percent', '磁盘最小可用比例', 10, 1, 90, '%'],
  ['inspect_disk_free_mb', '磁盘最小可用空间', 1024, 0, 1048576, 'MB'],
  ['inspect_backup_max_age_hours', '备份最大年龄', 26, 7, 8760, '小时'],
  ['inspect_geoip_max_age_days', 'GeoIP 库最大年龄', 30, 1, 3650, '天'],
  ['inspect_ip2region_max_age_days', 'IP2Region 库最大年龄', 90, 1, 3650, '天'],
  ['inspect_cooldown_sec', '同一发现通知冷却', 21600, 300, 604800, '秒'],
];
function inspectionFieldsHTML() {
  return INSPECT_FIELDS.map(([key, label, , min, max, unit]) => `<div class="form-row"><label>${label}</label><div class="toolbar"><input id="${key}" type="number" min="${min}" max="${max}" step="1" style="width:120px"><span class="hint">${unit}（${min}–${max}）</span></div></div>`).join('');
}
async function saveInspectionSettings() {
  const body = {};
  INSPECT_FIELDS.forEach(([key]) => { body[key] = $('#' + key).value; });
  try {
    await api('/api/settings', {method: 'PUT', body});
    toast('九项巡检设置已保存');
  } catch (e) { toast(e.message, true); }
}
let inspectionRunning = false;
let inspectionSnapshot = null;
function inspectionTime(value) {
  if (!value || String(value).startsWith('0001-')) return '尚未运行';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}
function updateInspectionStatus() {
  const running = $('#inspection-running'), last = $('#inspection-last'), btn = $('#inspection-run');
  if (running) { running.textContent = inspectionRunning ? 'running：是（巡检中）' : 'running：否'; running.className = 'tag ' + (inspectionRunning ? 'orange' : 'on'); }
  if (last) last.textContent = 'last：' + inspectionTime(inspectionSnapshot && inspectionSnapshot.last_run);
  if (btn) { btn.disabled = inspectionRunning; btn.textContent = inspectionRunning ? '巡检中…' : '立即巡检'; }
}
function renderInspectionSnapshot(snapshot) {
  inspectionSnapshot = snapshot || {last_run: '', findings: [], errors: []};
  updateInspectionStatus();
  const box = $('#inspection-results');
  if (!box) return;
  const findings = Array.isArray(inspectionSnapshot.findings) ? inspectionSnapshot.findings : [];
  const errors = Array.isArray(inspectionSnapshot.errors) ? inspectionSnapshot.errors : [];
  box.innerHTML = `<div class="sub-h">Findings（${findings.length}）</div>
    <div class="table-scroll"><table><thead><tr><th>级别</th><th>类型 / Key</th><th>资源</th><th>发现</th><th>首次 / 最近</th></tr></thead><tbody>
    ${findings.length ? findings.map(f => {
      const cls = f.severity === 'critical' ? 'red' : f.severity === 'warning' ? 'orange' : 'blue';
      return `<tr><td><span class="tag ${cls}">${esc(f.severity)}</span></td><td>${esc(f.kind)}<div class="hint mono">${esc(f.key)}</div></td><td>${esc(f.resource)}</td><td>${esc(f.message)}</td><td class="mono">${esc(inspectionTime(f.first))}<br>${esc(inspectionTime(f.last))}</td></tr>`;
    }).join('') : emptyHTML(5, '暂无活动发现')}
    </tbody></table></div>
    <div class="sub-h" style="margin-top:12px">Errors（${errors.length}）</div>
    <div class="table-scroll"><table><thead><tr><th>来源</th><th>资源</th><th>错误</th><th>时间</th></tr></thead><tbody>
    ${errors.length ? errors.map(e => `<tr><td>${esc(e.source)}</td><td>${esc(e.resource || '-')}</td><td>${esc(e.message)}</td><td class="mono">${esc(inspectionTime(e.time))}</td></tr>`).join('') : emptyHTML(4, '暂无巡检错误')}
    </tbody></table></div>`;
}
async function loadInspections() {
  updateInspectionStatus();
  try {
    const snapshot = await api('/api/inspections');
    renderInspectionSnapshot(snapshot);
  } catch (e) {
    if (!$('#inspection-results') && e.message === '未登录') return;
    toast(e.message, true);
  }
}
async function runInspection() {
  if (inspectionRunning) return toast('已有巡检正在运行');
  inspectionRunning = true;
  updateInspectionStatus();
  try {
    const snapshot = await api('/api/inspections/run', {method: 'POST'});
    renderInspectionSnapshot(snapshot);
    toast('巡检已完成');
  } catch (e) { toast(e.message, true); }
  finally { inspectionRunning = false; updateInspectionStatus(); }
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
  const secrets = readSecretFields(ALERT_SECRET_KEYS);
  try {
    await api('/api/settings', {method: 'PUT', body: {
      alert_enabled: $('#alert-enabled').value, alert_threshold: $('#alert-threshold').value,
      alert_window: $('#alert-window').value, alert_cooldown: $('#alert-cooldown').value,
      ...secrets,
    }});
    for (const [key, value] of Object.entries(secrets)) setSecretField(key, !!value);
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
  const body = readSecretFields(['metrics_token']);
  if (!Object.hasOwn(body, 'metrics_token')) return;
  try {
    await api('/api/settings', {method: 'PUT', body});
    setSecretField('metrics_token', !!body.metrics_token);
    toast(body.metrics_token ? '指标令牌已保存，即时生效' : '指标令牌已清除，仅允许本机抓取');
  } catch (e) { toast(e.message, true); }
}
function copyScrape() {
  const configured = $('#secret-metrics_token').dataset.configured;
  if (configured === undefined) { toast('指标设置尚未加载', true); return; }
  let cfg = `scrape_configs:\n  - job_name: niubwaf\n    scheme: https\n    scrape_interval: 15s\n    static_configs:\n      - targets: [${JSON.stringify(location.host)}]\n`;
  if (configured === 'true') cfg += '    authorization:\n      type: Bearer\n      credentials: "<填写抓取令牌>"\n';
  navigator.clipboard.writeText(cfg).then(() => toast('抓取配置已复制到剪贴板')).catch(() => toast('复制失败，请手动选择', true));
}
async function previewBlock() {
  const editor = $('#block-page');
  const tpl = editor.value;
  if (!tpl.trim()) {
    window.open('/api/block-page/preview', '_blank', 'noopener');
    return;
  }
  try {
    const {html} = await api('/api/block-page/preview', {method: 'POST', body: {template: tpl}});
    if (!editor.isConnected || editor.value !== tpl) return;
    $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()">
      <section class="modal modal-wide" role="dialog" aria-modal="true" aria-label="拦截页预览">
        <div class="panel-head"><h3>拦截页预览</h3><button class="btn ghost sm" onclick="closeModal()">关闭</button></div>
        <iframe id="block-preview-frame" class="block-preview-frame" title="自定义拦截页" sandbox referrerpolicy="no-referrer"></iframe>
      </section></div>`;
    $('#block-preview-frame').srcdoc = html;
  } catch (e) { toast(e.message, true); }
}
async function saveRetention() {
  try { await api('/api/settings', {method: 'PUT', body: {log_retention_days: $('#retention').value}}); toast('已保存'); }
  catch (e) { toast(e.message, true); }
}
function profile() {
  $('#main').innerHTML = pageHead('我的账号', esc(currentAccount.username) + ' · ' + esc(roleNames[currentAccount.role] || currentAccount.role)) + `
    <div class="panel">
      <h3>修改密码</h3>
      <div class="form-grid">
        <div class="form-row"><label for="pw-old">原密码</label><input id="pw-old" type="password" autocomplete="current-password"></div>
        <div class="form-row"><label for="pw-new">新密码</label><input id="pw-new" type="password" autocomplete="new-password"></div>
      </div>
      <button class="btn" onclick="changePass()">修改密码</button>
    </div>`;
}

async function accounts() {
  $('#main').innerHTML = pageHead('账号管理', '操作员可以调整防护规则，只有管理员可以修改站点和系统设置。',
    '<button class="btn" id="account-create">添加账号</button>') + `
    <div class="panel table-panel"><table><thead><tr><th>账号</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
    <tbody id="account-rows"></tbody></table></div>`;
  $('#account-create').onclick = () => editAccount();
  const body = $('#account-rows');
  try {
    const entries = await api('/api/accounts');
    if (!body.isConnected) return;
    body.innerHTML = entries.map(user => `<tr>
      <td>${esc(user.username)}</td><td>${esc(roleNames[user.role])}</td>
      <td>${user.enabled ? (user.must_change ? '待改密' : '启用') : '停用'}</td>
      <td>${user.username !== currentAccount.username ? `<button class="btn ghost sm" data-account-edit="${esc(user.username)}">编辑</button>` : '当前账号'}</td>
    </tr>`).join('') || emptyHTML(4, '暂无其他账号');
    body.addEventListener('click', e => {
      const button = e.target.closest('[data-account-edit]');
      if (button) editAccount(entries.find(user => user.username === button.dataset.accountEdit));
    });
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

function editAccount(account) {
  const user = account || {username: '', role: 'viewer', enabled: true};
  $('#modal-root').innerHTML = `<div class="modal-mask" onclick="if(event.target===this)closeModal()"><div class="modal" role="dialog" aria-modal="true" aria-label="控制台账号">
    <h3>${account ? '编辑账号' : '添加账号'}</h3>
    <div class="form-grid">
      <div class="form-row"><label for="account-name">账号名</label><input id="account-name" value="${esc(user.username)}" ${account ? 'readonly' : ''} autocomplete="off"></div>
      <div class="form-row"><label for="account-role">角色</label><select id="account-role">
        ${Object.entries(roleNames).map(([role, label]) => `<option value="${role}" ${role === user.role ? 'selected' : ''}>${label}</option>`).join('')}
      </select></div>
    </div>
    <div class="form-row"><label for="account-password">${account ? '新临时密码（留空保留密码）' : '临时密码'}</label>
      <input id="account-password" type="password" autocomplete="new-password" minlength="8" maxlength="256"></div>
    ${account ? `<label class="check"><input type="checkbox" id="account-enabled" ${user.enabled ? 'checked' : ''}>启用账号</label>` : ''}
    <p class="hint">临时密码须同时含字母和数字，账号首次使用临时密码时需改密。</p>
    <div class="modal-actions">
      ${account ? '<button class="btn danger" id="account-delete">删除账号</button>' : ''}
      <button class="btn ghost" onclick="closeModal()">取消</button>
      <button class="btn" id="account-save">保存</button>
    </div>
  </div></div>`;
  const endpoint = '/api/accounts' + (account ? '/' + encodeURIComponent(user.username) : '');
  const save = $('#account-save');
  save.onclick = async () => {
    save.disabled = true;
    try {
      const body = {username: $('#account-name').value.trim(), role: $('#account-role').value, password: $('#account-password').value};
      if (account) body.enabled = $('#account-enabled').checked;
      await api(endpoint, {method: account ? 'PUT' : 'POST', body});
      closeModal();
      await accounts();
    } catch (e) { toast(e.message, true); }
    finally { save.disabled = false; }
  };
  if (account) $('#account-delete').onclick = async () => {
    if (!confirm('删除账号 ' + user.username + '？')) return;
    try {
      await api(endpoint, {method: 'DELETE'});
      closeModal();
      await accounts();
    } catch (e) { toast(e.message, true); }
  };
}

async function changePass() {
  try {
    await api('/api/password', {method: 'PUT', body: {old: $('#pw-old').value, new: $('#pw-new').value}});
    csrfToken = '';
    toast('密码已修改，请重新登录'); doLogout();
  } catch (e) { toast(e.message, true); }
}

/* ---------------- 审计日志 ---------------- */
async function audit() {
  const m = $('#main');
  m.innerHTML = pageHead('审计日志', '控制台全部操作留痕') + `
  <div class="panel table-panel"><table>
  <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>详情</th></tr></thead>
  <tbody id="audit-body"></tbody></table></div>`;
  try {
    const list = await api('/api/audit');
    $('#audit-body').innerHTML = list.length ? list.map(a => `<tr>
      <td class="mono">${esc(a.ts)}</td><td>${esc(a.user)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('')
      : emptyHTML(4, '暂无审计记录');
  } catch (e) { if (e.message !== '未登录') toast(e.message, true); }
}

window.addEventListener('resize', () => {
  charts.forEach(c => c.resize());
  Object.keys(qpsState).forEach(qpsDraw);
});
(async () => {
  try {
    currentAccount = await api('/api/me');
    if (currentAccount.must_change) {
      $('#login-user').value = currentAccount.username;
      showLogin();
    } else showApp();
  }
  catch { showLogin(); }
})();
