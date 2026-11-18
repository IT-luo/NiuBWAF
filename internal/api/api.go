package api

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/metrics"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

type API struct {
	Store    *store.Store
	Proxy    *proxy.Proxy
	AdminTLS bool   // 管理台是否运行于 TLS，决定会话 Cookie 的 Secure 标志
	DataDir  string // 数据目录，用于数据库热备份
	mu       sync.Mutex
	sessions map[string]time.Time
	fails    map[string]*loginFail
}

type loginFail struct {
	count       int
	lockedUntil time.Time
	last        time.Time
}

func New(st *store.Store, p *proxy.Proxy) *API {
	return &API{Store: st, Proxy: p, sessions: map[string]time.Time{}, fails: map[string]*loginFail{}}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"error": msg})
}

func (a *API) authed(r *http.Request) bool {
	ck, err := r.Cookie("niub_admin")
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[ck.Value]
	if !ok {
		return false
	}
	if time.Now().Before(exp) {
		return true
	}
	delete(a.sessions, ck.Value) // 惰性清理：访问即删除已过期会话
	return false
}

// purgeExpiredSessionsLocked 清扫全部过期会话，防止 sessions map 随登录次数无界增长。
// 调用方必须持有 a.mu。
func (a *API) purgeExpiredSessionsLocked() {
	now := time.Now()
	for k, exp := range a.sessions {
		if !now.Before(exp) {
			delete(a.sessions, k)
		}
	}
}

// PurgeExpiredSessions 是过期会话清扫的加锁入口，供定期维护或测试调用。
func (a *API) PurgeExpiredSessions() {
	a.mu.Lock()
	a.purgeExpiredSessionsLocked()
	a.mu.Unlock()
}

const loginMaxFails = 5

func remoteKey(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

func (a *API) loginLocked(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := a.fails[key]
	return rec != nil && time.Now().Before(rec.lockedUntil)
}

// loginFailed 累计失败并按每满 5 次翻倍锁定（1→2→4…封顶 60 分钟）
func (a *API) loginFailed(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := a.fails[key]
	if rec == nil {
		rec = &loginFail{}
		a.fails[key] = rec
	}
	rec.count++
	rec.last = time.Now()
	if rec.count >= loginMaxFails {
		mins := 1 << (rec.count/loginMaxFails - 1)
		if mins > 60 {
			mins = 60
		}
		rec.lockedUntil = time.Now().Add(time.Duration(mins) * time.Minute)
	}
	if len(a.fails) > 10000 {
		cutoff := time.Now().Add(-24 * time.Hour)
		for k, v := range a.fails {
			if v.last.Before(cutoff) {
				delete(a.fails, k)
			}
		}
	}
}

func (a *API) loginSucceeded(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, key)
}

func (a *API) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: "niub_admin", Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: a.AdminTLS, SameSite: http.SameSiteStrictMode,
	}
}

func securityHeaders(next http.Handler, useTLS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if useTLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) Handler(console http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, "请求格式错误")
			return
		}
		key := remoteKey(r)
		if a.loginLocked(key) {
			a.Store.Audit("admin", "登录锁定", "尝试过于频繁 from "+key)
			writeErr(w, 429, "登录尝试过于频繁，请稍后再试")
			return
		}
		ok, needsRehash := store.VerifyPass(body.Password, a.Store.GetSetting("admin_pass"))
		if !ok {
			a.loginFailed(key)
			a.Store.Audit("admin", "登录失败", "密码错误 from "+key)
			writeErr(w, 401, "密码错误")
			return
		}
		if needsRehash {
			a.Store.SetSetting("admin_pass", store.HashPass(body.Password))
		}
		a.loginSucceeded(key)
		token := store.RandToken()
		a.mu.Lock()
		a.sessions[token] = time.Now().Add(12 * time.Hour)
		a.purgeExpiredSessionsLocked() // 每次登录顺带清扫过期会话，map 规模有界
		a.mu.Unlock()
		http.SetCookie(w, a.sessionCookie(token, 43200))
		a.Store.Audit("admin", "登录成功", key)
		writeJSON(w, map[string]any{"ok": "true", "must_change": a.Store.GetSetting("must_change_pass") == "on"})
	})

	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("niub_admin"); err == nil {
			a.mu.Lock()
			delete(a.sessions, ck.Value)
			a.mu.Unlock()
		}
		http.SetCookie(w, a.sessionCookie("", -1))
		writeJSON(w, map[string]string{"ok": "true"})
	})

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			writeErr(w, 401, "未登录")
			return
		}
		// 仍在使用默认口令时，除改密/登出外一律拒绝，强制先修改默认管理密码
		if a.Store.GetSetting("must_change_pass") == "on" && r.URL.Path != "/api/password" && r.URL.Path != "/api/logout" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(403)
			writeJSON(w, map[string]string{"error": "请先修改默认管理密码", "must_change": "true"})
			return
		}
		a.route(w, r)
	})

	mux.HandleFunc("/metrics", a.metricsHandler)

	mux.Handle("/", console)
	return securityHeaders(mux, a.AdminTLS)
}

// metricsHandler 暴露 Prometheus 抓取端点：配置 metrics_token 时校验 Bearer，
// 未配置时仅允许环回地址访问，避免指标（含站点/上游拓扑）泄露到公网。
func (a *API) metricsHandler(w http.ResponseWriter, r *http.Request) {
	token := a.Store.GetSetting("metrics_token")
	if token != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeErr(w, 401, "metrics token 无效")
			return
		}
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			writeErr(w, 403, "未配置 metrics_token 时仅允许本机访问 /metrics")
			return
		}
	}
	metrics.Default.Handler().ServeHTTP(w, r)
}

func (a *API) route(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/stats" && r.Method == "GET":
		a.stats(w, r)
	case path == "/api/trend" && r.Method == "GET":
		hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		if hours <= 0 || hours > 168 {
			hours = 24
		}
		t, err := a.Store.Trend(hours)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, t)
	case strings.HasPrefix(path, "/api/top/") && r.Method == "GET":
		a.top(w, r, strings.TrimPrefix(path, "/api/top/"))
	case path == "/api/sites" && r.Method == "GET":
		sites, err := a.Store.ListSites()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		for i := range sites {
			sites[i].AuthPass = ""
		}
		writeJSON(w, sites)
	case path == "/api/upstreams" && r.Method == "GET":
		writeJSON(w, a.Proxy.UpstreamHealth())
	case path == "/api/backup" && r.Method == "POST":
		a.backup(w, r)
	case path == "/api/backups" && r.Method == "GET":
		a.listBackups(w, r)
	case path == "/api/sites" && r.Method == "POST":
		a.saveSite(w, r, 0)
	case strings.HasPrefix(path, "/api/sites/") && r.Method == "PUT":
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/api/sites/"), 10, 64)
		a.saveSite(w, r, id)
	case strings.HasPrefix(path, "/api/sites/") && r.Method == "DELETE":
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/api/sites/"), 10, 64)
		if err := a.Store.DeleteSite(id); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		a.Store.Audit("admin", "删除站点", fmt.Sprintf("id=%d", id))
		a.Proxy.Reload()
		writeJSON(w, map[string]string{"ok": "true"})
	case path == "/api/logs" && r.Method == "GET":
		a.logs(w, r)
	case path == "/api/logs" && r.Method == "DELETE":
		a.clearLogs(w, r)
	case path == "/api/logs/export" && r.Method == "GET":
		a.exportCSV(w, r)
	case path == "/api/report" && r.Method == "GET":
		a.report(w, r)
	case path == "/api/ips" && r.Method == "GET":
		list, err := a.Store.ListIPs(r.URL.Query().Get("kind"))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, list)
	case path == "/api/ips" && r.Method == "POST":
		var e store.IPEntry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil || e.IP == "" || (e.Kind != "black" && e.Kind != "white") {
			writeErr(w, 400, "参数错误：需要 kind(black/white) 与 ip")
			return
		}
		if err := a.Store.AddIP(e.Kind, strings.TrimSpace(e.IP), e.Note, e.ExpiresAt); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		a.Store.Audit("admin", "添加IP名单", e.Kind+" "+e.IP)
		a.Proxy.Reload()
		writeJSON(w, map[string]string{"ok": "true"})
	case strings.HasPrefix(path, "/api/ips/") && r.Method == "DELETE":
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/api/ips/"), 10, 64)
		a.Store.DeleteIP(id)
		a.Store.Audit("admin", "删除IP名单", fmt.Sprintf("id=%d", id))
		a.Proxy.Reload()
		writeJSON(w, map[string]string{"ok": "true"})
	case path == "/api/exclusions" && r.Method == "GET":
		list, err := a.Store.ListExclusions()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, list)
	case path == "/api/exclusions" && r.Method == "POST":
		a.addExclusion(w, r)
	case strings.HasPrefix(path, "/api/exclusions/") && r.Method == "DELETE":
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/api/exclusions/"), 10, 64)
		if err := a.Store.DeleteExclusion(id); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		a.Store.Audit("admin", "删除规则豁免", fmt.Sprintf("id=%d", id))
		a.Proxy.Reload()
		writeJSON(w, map[string]string{"ok": "true"})
	case path == "/api/rules" && r.Method == "GET":
		list, err := a.Store.ListRules()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, list)
	case path == "/api/rules" && r.Method == "POST":
		a.saveRule(w, r, 0)
	case strings.HasPrefix(path, "/api/rules/") && r.Method == "PUT":
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/api/rules/"), 10, 64)
		a.saveRule(w, r, id)
	case strings.HasPrefix(path, "/api/rules/") && r.Method == "DELETE":
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/api/rules/"), 10, 64)
		if err := a.Store.DeleteRule(id); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		a.Store.Audit("admin", "删除自定义规则", fmt.Sprintf("id=%d", id))
		a.Proxy.Reload()
		writeJSON(w, map[string]string{"ok": "true"})
	case path == "/api/alert/test" && r.Method == "POST":
		res := a.Proxy.AlertTest()
		a.Store.Audit("admin", "测试告警通知", strings.Join(keysOf(res), ","))
		writeJSON(w, res)
	case path == "/api/reputation" && r.Method == "GET":
		list, err := a.Store.ListReputation(200)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, list)
	case path == "/api/reputation/lookup" && r.Method == "GET":
		a.reputationLookup(w, r)
	case path == "/api/intel/status" && r.Method == "GET":
		writeJSON(w, a.Proxy.IntelStatus())
	case path == "/api/intel/refresh" && r.Method == "POST":
		a.Proxy.IntelRefresh()
		a.Store.Audit("admin", "刷新IP情报", "IDC/Tor 数据源")
		writeJSON(w, map[string]string{"ok": "true"})
	case path == "/api/intel/test" && r.Method == "POST":
		a.intelTest(w, r)
	case strings.HasPrefix(path, "/api/reputation/") && r.Method == "DELETE":
		ip := strings.TrimPrefix(path, "/api/reputation/")
		windowHours := 24
		if v := a.Store.GetSetting("rep_window"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				windowHours = n
			}
		}
		pardon := time.Now().Add(time.Duration(windowHours) * time.Hour).Format("2006-01-02 15:04:05")
		if err := a.Store.Unban(ip, pardon); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		a.Proxy.RefreshBans()
		a.Store.Audit("admin", "信誉解封", ip+" 赦免至 "+pardon)
		writeJSON(w, map[string]string{"ok": "true"})
	case path == "/api/settings" && r.Method == "GET":
		a.getSettings(w)
	case path == "/api/settings" && r.Method == "PUT":
		a.putSettings(w, r)
	case path == "/api/password" && r.Method == "PUT":
		a.changePass(w, r)
	case path == "/api/audit" && r.Method == "GET":
		list, err := a.Store.ListAudit(200)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, list)
	case path == "/api/events" && r.Method == "GET":
		a.events(w, r)
	default:
		writeErr(w, 404, "接口不存在")
	}
}

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	st := a.Store.Stats()
	sites, _ := a.Store.ListSites()
	enabled := 0
	for _, s := range sites {
		if s.Enabled {
			enabled++
		}
	}
	writeJSON(w, map[string]any{
		"today_reqs": st.TodayReqs, "today_blocks": st.TodayBlocks,
		"total_reqs": st.TotalReqs, "total_blocks": st.TotalBlocks,
		"sites": len(sites), "sites_enabled": enabled,
		"geoip_available": a.Proxy.Geo.Available(),
	})
}

func (a *API) top(w http.ResponseWriter, r *http.Request, kind string) {
	var (
		list []store.KV
		err  error
	)
	switch kind {
	case "ips":
		list, err = a.Store.TopIPs(10)
	case "rules":
		list, err = a.Store.TopRules(10)
	case "domains":
		list, err = a.Store.TopDomains(10)
	case "countries":
		list, err = a.Store.TopCountries(10)
	default:
		writeErr(w, 404, "未知统计维度")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if kind == "ips" && a.Proxy.Geo.CityAvailable() {
		out := make([]map[string]any, 0, len(list))
		for _, kv := range list {
			out = append(out, map[string]any{"key": kv.Key, "count": kv.Count, "city": a.Proxy.Geo.CityInfo(kv.Key).City})
		}
		writeJSON(w, out)
		return
	}
	writeJSON(w, list)
}

func (a *API) saveSite(w http.ResponseWriter, r *http.Request, id int64) {
	var s store.Site
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if s.Name == "" || s.Domain == "" || s.Upstream == "" {
		writeErr(w, 400, "名称、域名、上游地址不能为空")
		return
	}
	var ups []string
	for _, raw := range strings.Split(s.Upstream, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			writeErr(w, 400, "上游地址无效（需 http:// 或 https:// 开头，多个用逗号分隔）: "+raw)
			return
		}
		ups = append(ups, raw)
	}
	if len(ups) == 0 {
		writeErr(w, 400, "上游地址不能为空")
		return
	}
	s.Upstream = strings.Join(ups, ",")
	if (s.CertPEM == "") != (s.KeyPEM == "") {
		writeErr(w, 400, "证书与私钥必须同时配置")
		return
	}
	if s.CertPEM != "" {
		if _, err := tls.X509KeyPair([]byte(s.CertPEM), []byte(s.KeyPEM)); err != nil {
			writeErr(w, 400, "证书或私钥无效: "+err.Error())
			return
		}
	}
	if s.WAFMode != "strict" {
		s.WAFMode = "balanced"
	}
	switch s.DynamicMode {
	case "observe", "block":
	default:
		s.DynamicMode = "off"
	}
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	// Basic-Auth 口令哈希落盘：更新时留空表示保留原口令（控制台不回显哈希）
	if id != 0 && s.AuthPass == "" {
		if cur, e := a.Store.GetSite(id); e == nil {
			s.AuthPass = cur.AuthPass
		}
	}
	if s.AuthPass != "" && !strings.HasPrefix(s.AuthPass, "pbkdf2_sha256$") {
		s.AuthPass = store.HashPass(s.AuthPass)
	}
	var err error
	if id == 0 {
		err = a.Store.CreateSite(&s)
		a.Store.Audit("admin", "新增站点", s.Domain+" -> "+s.Upstream)
	} else {
		s.ID = id
		err = a.Store.UpdateSite(&s)
		a.Store.Audit("admin", "修改站点", s.Domain)
	}
	if err != nil {
		writeErr(w, 500, "保存失败（域名可能已存在）: "+err.Error())
		return
	}
	a.Proxy.Reload()
	s.AuthPass = ""
	writeJSON(w, s)
}

var paramRe = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]+$`)

func (a *API) addExclusion(w http.ResponseWriter, r *http.Request) {
	var e store.Exclusion
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	e.URLPrefix = strings.TrimSpace(e.URLPrefix)
	e.Param = strings.TrimSpace(e.Param)
	e.Note = strings.TrimSpace(e.Note)
	if e.RuleID <= 0 || e.RuleID > 9999999 {
		writeErr(w, 400, "rule_id 无效")
		return
	}
	if e.SiteID < 0 {
		writeErr(w, 400, "site_id 无效（0=全局）")
		return
	}
	if len(e.URLPrefix) > 512 {
		writeErr(w, 400, "URL 前缀过长")
		return
	}
	if e.Param != "" && !paramRe.MatchString(e.Param) {
		writeErr(w, 400, "参数名仅允许字母、数字、_ . - [ ]")
		return
	}
	if err := a.Store.AddExclusion(&e); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	a.Store.Audit("admin", "添加规则豁免", fmt.Sprintf("rule=%d site=%d prefix=%q param=%q", e.RuleID, e.SiteID, e.URLPrefix, e.Param))
	a.Proxy.Reload()
	writeJSON(w, e)
}

func (a *API) saveRule(w http.ResponseWriter, r *http.Request, id int64) {
	var cr store.CustomRule
	if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	cr.Name = strings.TrimSpace(cr.Name)
	cr.Note = strings.TrimSpace(cr.Note)
	cr.ActionParam = strings.TrimSpace(cr.ActionParam)
	if cr.Name == "" {
		writeErr(w, 400, "规则名称不能为空")
		return
	}
	if cr.SiteID < 0 {
		writeErr(w, 400, "site_id 无效（0=全局）")
		return
	}
	if cr.Priority < 0 || cr.Priority > 100000 {
		writeErr(w, 400, "priority 需在 0–100000 之间")
		return
	}
	switch cr.Action {
	case "allow", "block", "captcha", "log", "redirect":
	default:
		writeErr(w, 400, "action 必须是 allow/block/captcha/log/redirect")
		return
	}
	if cr.Logic != "and" && cr.Logic != "or" {
		cr.Logic = "and"
	}
	if cr.Action == "redirect" && proxy.SafeRedirect(cr.ActionParam) == "" {
		writeErr(w, 400, "重定向地址无效（需 / 开头的站内路径或 http(s) 绝对地址，禁止 // 与 javascript:）")
		return
	}
	if _, err := engine.CompileRule(engine.RuleDef{
		ID: cr.ID, SiteID: cr.SiteID, Name: cr.Name, Priority: cr.Priority,
		Logic: cr.Logic, Conditions: cr.Conditions, Action: cr.Action, ActionParam: cr.ActionParam,
	}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var err error
	if id == 0 {
		err = a.Store.CreateRule(&cr)
		a.Store.Audit("admin", "新增自定义规则", fmt.Sprintf("%s action=%s site=%d", cr.Name, cr.Action, cr.SiteID))
	} else {
		cr.ID = id
		err = a.Store.UpdateRule(&cr)
		a.Store.Audit("admin", "修改自定义规则", fmt.Sprintf("id=%d %s", id, cr.Name))
	}
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	a.Proxy.Reload()
	writeJSON(w, cr)
}

func (a *API) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 200 {
		size = 20
	}
	list, total, err := a.Store.QueryLogs(q.Get("ip"), q.Get("domain"), q.Get("action"), size, (page-1)*size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if a.Proxy.Geo.CityAvailable() {
		for i := range list {
			if list[i].City == "" {
				list[i].City = a.Proxy.Geo.CityInfo(list[i].ClientIP).City
			}
		}
	}
	writeJSON(w, map[string]any{"list": list, "total": total, "page": page, "size": size})
}

// clearLogs 清空攻击日志（不影响审计日志与生效中的信誉封禁）
func (a *API) clearLogs(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.ClearLogs()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	a.Store.Audit("admin", "清空攻击日志", fmt.Sprintf("%d 条", n))
	writeJSON(w, map[string]any{"ok": "true", "deleted": n})
}

// exportCSV 流式导出：逐行写入响应，不把结果集全量载入内存
func (a *API) exportCSV(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip, domain, action := q.Get("ip"), q.Get("domain"), q.Get("action")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=niubwaf-attack-logs.csv")
	bw := bufio.NewWriterSize(w, 32*1024)
	bw.Write([]byte{0xEF, 0xBB, 0xBF})
	bw.WriteString("时间,站点域名,客户端IP,国家,城市,方法,URL,动作,规则ID,描述,严重级别,状态码,请求ID\n")
	csvEsc := func(s string) string {
		if strings.ContainsAny(s, ",\"\n") {
			return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
		}
		return s
	}
	cityOn := a.Proxy.Geo.CityAvailable()
	rows := 0
	err := a.Store.EachLog(ip, domain, action, func(l *store.AttackLog) error {
		rows++
		if cityOn && l.City == "" {
			l.City = a.Proxy.Geo.CityInfo(l.ClientIP).City
		}
		_, err := fmt.Fprintf(bw, "%s,%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%d,%s\n",
			l.Ts, csvEsc(l.Domain), l.ClientIP, l.Country, csvEsc(l.City), l.Method, csvEsc(l.URL),
			l.Action, l.RuleID, csvEsc(l.Msg), l.Severity, l.Status, l.ReqID)
		return err
	})
	flushErr := bw.Flush()
	if err == nil {
		err = flushErr
	}
	if err != nil {
		log.Printf("导出攻击日志CSV失败: %v", err)
		return
	}
	a.Store.Audit("admin", "导出攻击日志CSV", fmt.Sprintf("%d 条", rows))
}

func (a *API) reputationLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		writeErr(w, 400, "需要 ip 参数")
		return
	}
	intel := a.Proxy.IntelLookup(ip)
	writeJSON(w, map[string]any{
		"ip":           ip,
		"whitelisted":  a.Proxy.IsWhitelisted(ip),
		"blacklisted":  a.Proxy.IsBlacklisted(ip),
		"banned":       a.Proxy.IsRepBanned(ip),
		"attack_count": a.Store.IPAttackCount(ip),
		"reputation":   a.Store.GetReputation(ip),
		"geo_country":  intel.Country,
		"region":       intel.Region,
		"city":         intel.City,
		"latitude":     intel.Latitude,
		"longitude":    intel.Longitude,
		"asn":          intel.ASN,
		"asn_org":      intel.ASNOrg,
		"idc":          intel.IDC,
		"tor":          intel.Tor,
		"threat_tags":  intel.ThreatTags,
		"threat_score": intel.ThreatScore,
		"threat_provider": intel.ThreatProvider,
	})
}

func (a *API) intelTest(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		ip = "8.8.8.8"
	}
	if net.ParseIP(ip) == nil {
		writeErr(w, 400, "ip 参数无效")
		return
	}
	if !a.Proxy.ThreatEnabled() {
		writeJSON(w, map[string]any{"enabled": false, "message": "付费情报未启用（需配置 intel_provider=generic + 密钥 + 地址）"})
		return
	}
	res := a.Proxy.ThreatLookup(ip)
	writeJSON(w, map[string]any{"enabled": true, "ip": ip, "provider": res.Provider, "tags": res.Tags, "score": res.Score})
}

func (a *API) getSettings(w http.ResponseWriter) {
	keys := []string{"block_page", "geoip_mode", "geoip_countries", "log_retention_days", "semantic_mode",
		"reputation_enabled", "rep_window", "rep_threshold", "rep_ban_ttl", "rep_max_ttl", "trusted_proxies",
		"alert_enabled", "alert_webhook", "alert_dingtalk", "alert_wecom", "alert_threshold", "alert_window", "alert_cooldown",
		"acme_enabled", "acme_domains", "acme_email", "acme_staging", "metrics_token",
		"intel_provider", "intel_api_key", "intel_api_url", "body_inspect_kb", "body_scan_kb", "allowed_content_types"}
	out := map[string]string{}
	for _, k := range keys {
		out[k] = a.Store.GetSetting(k)
	}
	if out["geoip_mode"] == "" {
		out["geoip_mode"] = "off"
	}
	if out["log_retention_days"] == "" {
		out["log_retention_days"] = "30"
	}
	if out["semantic_mode"] == "" {
		out["semantic_mode"] = "observe"
	}
	for k, def := range map[string]string{"reputation_enabled": "on", "rep_window": "24", "rep_threshold": "30", "rep_ban_ttl": "60", "rep_max_ttl": "1440",
		"alert_enabled": "off", "alert_threshold": "50", "alert_window": "60", "alert_cooldown": "300",
		"acme_enabled": "off", "acme_staging": "on", "intel_provider": "off", "body_inspect_kb": "2048", "body_scan_kb": "16"} {
		if out[k] == "" {
			out[k] = def
		}
	}
	out["geoip_available"] = fmt.Sprintf("%v", a.Proxy.Geo.Available())
	writeJSON(w, out)
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	allowed := map[string]bool{"block_page": true, "geoip_mode": true, "geoip_countries": true, "log_retention_days": true, "semantic_mode": true,
		"reputation_enabled": true, "rep_window": true, "rep_threshold": true, "rep_ban_ttl": true, "rep_max_ttl": true, "trusted_proxies": true,
		"alert_enabled": true, "alert_webhook": true, "alert_dingtalk": true, "alert_wecom": true, "alert_threshold": true, "alert_window": true, "alert_cooldown": true,
		"acme_enabled": true, "acme_domains": true, "acme_email": true, "acme_staging": true, "metrics_token": true,
		"intel_provider": true, "intel_api_key": true, "intel_api_url": true, "body_inspect_kb": true, "body_scan_kb": true, "allowed_content_types": true}
	numRange := map[string][2]int{"rep_window": {1, 168}, "rep_threshold": {1, 100000}, "rep_ban_ttl": {1, 10080}, "rep_max_ttl": {1, 43200},
		"alert_threshold": {1, 1000000}, "alert_window": {10, 3600}, "alert_cooldown": {10, 86400}, "body_inspect_kb": {64, 102400}, "body_scan_kb": {16, 1024}}
	repChanged := false
	trustedChanged := false
	acmeChanged := false
	ctChanged := false
	scanChanged := false
	for k, v := range body {
		if !allowed[k] {
			continue
		}
		if k == "geoip_mode" && v != "off" && v != "block" && v != "allow" {
			writeErr(w, 400, "geoip_mode 必须是 off/block/allow")
			return
		}
		if k == "semantic_mode" && v != "off" && v != "observe" && v != "block" {
			writeErr(w, 400, "semantic_mode 必须是 off/observe/block")
			return
		}
		if k == "reputation_enabled" && v != "on" && v != "off" {
			writeErr(w, 400, "reputation_enabled 必须是 on/off")
			return
		}
		if k == "alert_enabled" && v != "on" && v != "off" {
			writeErr(w, 400, "alert_enabled 必须是 on/off")
			return
		}
		if (k == "acme_enabled" || k == "acme_staging") && v != "on" && v != "off" {
			writeErr(w, 400, k+" 必须是 on/off")
			return
		}
		if k == "acme_domains" && v != "" {
			for _, d := range strings.Split(v, ",") {
				d = strings.ToLower(strings.TrimSpace(d))
				if d == "" {
					continue
				}
				if !validACMEDomain(d) {
					writeErr(w, 400, "acme_domains 含非法域名（不支持通配符/IP/协议）: "+d)
					return
				}
			}
		}
		if k == "acme_email" && v != "" && !strings.Contains(v, "@") {
			writeErr(w, 400, "acme_email 必须是合法邮箱")
			return
		}
		if k == "intel_provider" && v != "off" && v != "generic" {
			writeErr(w, 400, "intel_provider 必须是 off/generic")
			return
		}
		if k == "intel_api_url" && v != "" {
			if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
				writeErr(w, 400, "intel_api_url 必须以 http:// 或 https:// 开头")
				return
			}
			if !strings.Contains(v, "{ip}") {
				writeErr(w, 400, "intel_api_url 必须包含 {ip} 占位符")
				return
			}
		}
		if k == "allowed_content_types" {
			n := 0
			for _, raw := range strings.Split(v, ",") {
				t := strings.ToLower(strings.TrimSpace(raw))
				if t == "" {
					continue
				}
				n++
				if !engine.ValidContentType(t) {
					writeErr(w, 400, "allowed_content_types 含非法 Content-Type（需形如 type/subtype）: "+raw)
					return
				}
			}
			if n > 32 {
				writeErr(w, 400, "allowed_content_types 最多 32 项")
				return
			}
			ctChanged = true
		}
		if strings.HasPrefix(k, "acme_") {
			acmeChanged = true
		}
		if (k == "alert_webhook" || k == "alert_dingtalk" || k == "alert_wecom") && v != "" &&
			!strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			writeErr(w, 400, k+" 必须以 http:// 或 https:// 开头")
			return
		}
		if k == "trusted_proxies" {
			for _, raw := range strings.Split(v, ",") {
				raw = strings.TrimSpace(raw)
				if raw == "" {
					continue
				}
				if strings.Contains(raw, "/") {
					_, n, err := net.ParseCIDR(raw)
					if err != nil {
						writeErr(w, 400, "trusted_proxies 含非法 CIDR: "+raw)
						return
					}
					if ones, _ := n.Mask.Size(); ones == 0 {
						writeErr(w, 400, "trusted_proxies 不能信任全部网段（"+raw+"），否则客户端可伪造 XFF 绕过访问控制")
						return
					}
				} else if net.ParseIP(raw) == nil {
					writeErr(w, 400, "trusted_proxies 含非法 IP: "+raw)
					return
				}
			}
			trustedChanged = true
		}
		if rg, ok := numRange[k]; ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < rg[0] || n > rg[1] {
				writeErr(w, 400, fmt.Sprintf("%s 必须是 %d–%d 的整数", k, rg[0], rg[1]))
				return
			}
		}
		if strings.HasPrefix(k, "rep_") || k == "reputation_enabled" {
			repChanged = true
		}
		if k == "body_scan_kb" {
			scanChanged = true
		}
		a.Store.SetSetting(k, v)
	}
	a.Store.Audit("admin", "修改设置", strings.Join(keysOf(body), ","))
	if scanChanged {
		// 送检上限是热路径参数，同步生效（不重建引擎）
		kb, _ := strconv.Atoi(a.Store.GetSetting("body_scan_kb"))
		a.Proxy.Engine.SetScanLimit(kb << 10)
	}
	if ctChanged {
		// 同步重建引擎，避免返回 ok 后规则尚未生效
		if err := a.Proxy.Engine.SetContentTypes(engine.ParseContentTypes(a.Store.GetSetting("allowed_content_types"))); err != nil {
			writeErr(w, 500, "应用允许内容类型失败: "+err.Error())
			return
		}
	}
	if repChanged {
		go a.Proxy.RefreshReputation()
	}
	if trustedChanged {
		go a.Proxy.Reload()
	}
	if acmeChanged {
		go a.Proxy.Reload()
	}
	writeJSON(w, map[string]string{"ok": "true"})
}

// validACMEDomain 校验 ACME 域名：纯主机名、含点、无通配符/协议/路径，拒绝 IP。
func validACMEDomain(d string) bool {
	if strings.ContainsAny(d, "/* :\\") || net.ParseIP(d) != nil {
		return false
	}
	if !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func keysOf(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (a *API) changePass(w http.ResponseWriter, r *http.Request) {
	var body struct{ Old, New string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if ok, _ := store.VerifyPass(body.Old, a.Store.GetSetting("admin_pass")); !ok {
		writeErr(w, 403, "原密码错误")
		return
	}
	if len(body.New) < 8 {
		writeErr(w, 400, "新密码至少 8 位")
		return
	}
	if body.New == "admin123" || body.New == body.Old {
		writeErr(w, 400, "新密码不能为默认口令或与原密码相同")
		return
	}
	if !strings.ContainsAny(body.New, "0123456789") || !strings.ContainsAny(body.New, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		writeErr(w, 400, "新密码需同时包含字母和数字")
		return
	}
	a.Store.SetSetting("admin_pass", store.HashPass(body.New))
	a.Store.SetSetting("must_change_pass", "off")
	a.Store.Audit("admin", "修改管理密码", "")
	writeJSON(w, map[string]any{"ok": "true", "must_change": false})
}

func (a *API) backupDir() string {
	return filepath.Join(a.DataDir, "backups")
}

// RunBackup 生成带时间戳的一致性热备份，并清理超出保留份数的旧备份
func (a *API) RunBackup() (string, error) {
	dir := a.backupDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	name := "niubwaf-" + time.Now().Format("20060102-150405") + ".db"
	if err := a.Store.Backup(filepath.Join(dir, name)); err != nil {
		return "", err
	}
	a.pruneBackups(dir, 7)
	return name, nil
}

func (a *API) pruneBackups(dir string, keep int) {
	names := a.backupNames(dir)
	sort.Strings(names) // 时间戳命名，字典序即时间序
	for i := 0; i < len(names)-keep; i++ {
		os.Remove(filepath.Join(dir, names[i]))
	}
}

func (a *API) backupNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "niubwaf-") && strings.HasSuffix(e.Name(), ".db") {
			names = append(names, e.Name())
		}
	}
	return names
}

func (a *API) backup(w http.ResponseWriter, r *http.Request) {
	name, err := a.RunBackup()
	if err != nil {
		writeErr(w, 500, "备份失败: "+err.Error())
		return
	}
	a.Store.Audit("admin", "数据库备份", name)
	writeJSON(w, map[string]string{"ok": "true", "name": name})
}

func (a *API) listBackups(w http.ResponseWriter, r *http.Request) {
	dir := a.backupDir()
	names := a.backupNames(dir)
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	out := []map[string]any{}
	for _, n := range names {
		info, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"name": n, "size": info.Size(), "mtime": info.ModTime().Format("2006-01-02 15:04:05")})
	}
	writeJSON(w, out)
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "不支持 SSE")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch := a.Proxy.Hub.Subscribe()
	defer a.Proxy.Hub.Unsubscribe(ch)
	fmt.Fprintf(w, "data: {\"type\":\"hello\"}\n\n")
	flusher.Flush()
	for {
		select {
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		case <-time.After(25 * time.Second):
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
