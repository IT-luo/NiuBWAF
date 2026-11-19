package proxy

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/metrics"
	"niubwaf/internal/store"

	"golang.org/x/crypto/acme/autocert"
)

type upstreamTarget struct {
	u         *url.URL
	downUntil int64 // unix 秒，原子读写；0=健康
}

type cachedSite struct {
	store.Site
	targets []*upstreamTarget
	rr      uint64
	excl    []engine.Exclusion
	rules   []engine.CompiledRule
}

// pick 轮询选择健康上游；全部故障时仍返回一个尝试转发
func (s *cachedSite) pick() *upstreamTarget {
	n := len(s.targets)
	if n == 0 {
		return nil
	}
	now := time.Now().Unix()
	start := int(atomic.AddUint64(&s.rr, 1))
	for i := 0; i < n; i++ {
		t := s.targets[(start+i)%n]
		if atomic.LoadInt64(&t.downUntil) <= now {
			return t
		}
	}
	return s.targets[start%n]
}

type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *Hub) Broadcast(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- data:
		default:
		}
	}
	h.mu.Unlock()
}

type Proxy struct {
	Store   *store.Store
	Engine  *engine.Engine
	Geo     *GeoIP
	IDC     *IDCMatcher
	Tor     *TorList
	Limiter *Limiter
	Cap     *Captcha
	Hub     *Hub
	Ana     *Analytics
	threat  *ThreatIntel
	// HTTPSAddr 用于 HTTP→HTTPS 跳转时构造目标地址，如 ":8443"
	HTTPSAddr string

	mu          sync.RWMutex
	sites       map[string]*cachedSite
	blackNet    []*net.IPNet
	whiteNet    []*net.IPNet
	trustedNet  []*net.IPNet // 可信代理网段：仅这些对端追加的 XFF 才被采信
	blackIP     map[string]bool
	whiteIP     map[string]bool
	dynBlack    map[string]int64 // IP 信誉自动封禁：ip → unix 到期秒
	certs       map[string]*tls.Certificate
	defaultCert *tls.Certificate

	acme        *autocert.Manager
	acmeDataDir string
	acmeSig     string

	dynSecret []byte

	lastRepLogID atomic.Int64 // 上次信誉聚合时的最大攻击日志 ID，用于空闲跳过
	repIdle      atomic.Int32 // 连续空闲周期计数

	alertMu   sync.Mutex
	lastAlert time.Time
}

func New(st *store.Store, eng *engine.Engine, geo *GeoIP, idc *IDCMatcher, tor *TorList, secret string) *Proxy {
	p := &Proxy{
		Store: st, Engine: eng, Geo: geo, IDC: idc, Tor: tor,
		Limiter: NewLimiter(), Cap: NewCaptcha(secret), Hub: NewHub(),
		Ana:       NewAnalytics(st, geo),
		dynSecret: []byte(secret), threat: NewThreatIntel(st),
	}
	p.Reload()
	go func() {
		for range time.Tick(30 * time.Second) {
			p.Reload()
		}
	}()
	go p.healthLoop()
	go p.reputationLoop()
	go p.alertLoop()
	go p.qpsLoop()
	return p
}

// healthLoop 主动探测上游：任意 HTTP 响应视为健康，连接失败摘除 5 秒
func (p *Proxy) healthLoop() {
	client := &http.Client{Timeout: 2 * time.Second}
	for range time.Tick(5 * time.Second) {
		p.mu.RLock()
		type siteTargets struct {
			domain  string
			targets []*upstreamTarget
		}
		var all []siteTargets
		for _, s := range p.sites {
			all = append(all, siteTargets{s.Domain, s.targets})
		}
		p.mu.RUnlock()
		var ups []metrics.UpstreamSample
		for _, st := range all {
			for _, t := range st.targets {
				resp, err := client.Get(t.u.String() + "/")
				up := err == nil
				if err != nil {
					atomic.StoreInt64(&t.downUntil, time.Now().Unix()+5)
				} else {
					resp.Body.Close()
					atomic.StoreInt64(&t.downUntil, 0)
				}
				ups = append(ups, metrics.UpstreamSample{Site: st.domain, URL: t.u.String(), Up: up})
			}
		}
		metrics.Default.SetUpstreams(ups)
	}
}

type TargetStatus struct {
	URL string `json:"url"`
	Up  bool   `json:"up"`
}

type UpstreamStatus struct {
	SiteID  int64          `json:"site_id"`
	Domain  string         `json:"domain"`
	Targets []TargetStatus `json:"targets"`
}

func (p *Proxy) UpstreamHealth() []UpstreamStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := time.Now().Unix()
	out := []UpstreamStatus{}
	for _, s := range p.sites {
		st := UpstreamStatus{SiteID: s.ID, Domain: s.Domain, Targets: []TargetStatus{}}
		for _, t := range s.targets {
			st.Targets = append(st.Targets, TargetStatus{URL: t.u.String(), Up: atomic.LoadInt64(&t.downUntil) <= now})
		}
		out = append(out, st)
	}
	return out
}

func (p *Proxy) Reload() {
	if err := p.Engine.SetContentTypes(engine.ParseContentTypes(p.Store.GetSetting("allowed_content_types"))); err != nil {
		log.Printf("应用允许内容类型失败: %v", err)
	}
	p.Engine.SetScanLimit(p.bodyScanLimit())
	sites, err := p.Store.ListSites()
	if err != nil {
		log.Printf("加载站点失败: %v", err)
		return
	}
	m := map[string]*cachedSite{}
	excls, _ := p.Store.ListExclusions()
	var globalExcl []engine.Exclusion
	perSite := map[int64][]engine.Exclusion{}
	for _, x := range excls {
		e := engine.Exclusion{RuleID: x.RuleID, URLPrefix: x.URLPrefix, Param: x.Param}
		if x.SiteID == 0 {
			globalExcl = append(globalExcl, e)
		} else {
			perSite[x.SiteID] = append(perSite[x.SiteID], e)
		}
	}
	crs, _ := p.Store.ListRules()
	var globalRules []engine.CompiledRule
	perSiteRules := map[int64][]engine.CompiledRule{}
	for _, r := range crs {
		if !r.Enabled {
			continue
		}
		cr, err := engine.CompileRule(engine.RuleDef{
			ID: r.ID, SiteID: r.SiteID, Name: r.Name, Priority: r.Priority,
			Logic: r.Logic, Conditions: r.Conditions, Action: r.Action, ActionParam: r.ActionParam,
		})
		if err != nil {
			log.Printf("自定义规则 %d(%s) 编译失败，已跳过: %v", r.ID, r.Name, err)
			continue
		}
		if r.SiteID == 0 {
			globalRules = append(globalRules, cr)
		} else {
			perSiteRules[r.SiteID] = append(perSiteRules[r.SiteID], cr)
		}
	}
	p.mu.RLock()
	oldHealth := map[string]int64{}
	for _, os := range p.sites {
		for _, t := range os.targets {
			oldHealth[t.u.String()] = atomic.LoadInt64(&t.downUntil)
		}
	}
	p.mu.RUnlock()
	for _, s := range sites {
		var targets []*upstreamTarget
		for _, raw := range strings.Split(s.Upstream, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				log.Printf("站点 %s 上游地址无效: %s", s.Domain, raw)
				continue
			}
			targets = append(targets, &upstreamTarget{u: u, downUntil: oldHealth[u.String()]})
		}
		if len(targets) == 0 {
			log.Printf("站点 %s 无有效上游地址: %s", s.Domain, s.Upstream)
			continue
		}
		cs := &cachedSite{Site: s, targets: targets}
		cs.excl = append(append([]engine.Exclusion{}, globalExcl...), perSite[s.ID]...)
		cs.rules = append(append([]engine.CompiledRule{}, globalRules...), perSiteRules[s.ID]...)
		sort.SliceStable(cs.rules, func(i, j int) bool {
			if cs.rules[i].Priority != cs.rules[j].Priority {
				return cs.rules[i].Priority < cs.rules[j].Priority
			}
			return cs.rules[i].ID < cs.rules[j].ID
		})
		m[strings.ToLower(s.Domain)] = cs
	}
	ips, _ := p.Store.ListIPs("")
	var bn, wn []*net.IPNet
	bi, wi := map[string]bool{}, map[string]bool{}
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, e := range ips {
		if e.ExpiresAt != "" && e.ExpiresAt < now {
			continue
		}
		if strings.Contains(e.IP, "/") {
			_, n, err := net.ParseCIDR(e.IP)
			if err != nil {
				continue
			}
			if e.Kind == "black" {
				bn = append(bn, n)
			} else {
				wn = append(wn, n)
			}
		} else {
			if e.Kind == "black" {
				bi[e.IP] = true
			} else {
				wi[e.IP] = true
			}
		}
	}
	certs := map[string]*tls.Certificate{}
	for domain, cs := range m {
		if cs.CertPEM == "" || cs.KeyPEM == "" {
			continue
		}
		cert, err := tls.X509KeyPair([]byte(cs.CertPEM), []byte(cs.KeyPEM))
		if err != nil {
			log.Printf("站点 %s 证书解析失败: %v", domain, err)
			continue
		}
		certs[domain] = &cert
	}
	p.mu.Lock()
	p.sites, p.blackNet, p.whiteNet, p.blackIP, p.whiteIP = m, bn, wn, bi, wi
	p.trustedNet = engine.ParseTrustedProxies(p.Store.GetSetting("trusted_proxies"))
	p.certs = certs
	p.dynBlack = p.Store.ActiveBans(now)
	p.mu.Unlock()
	p.refreshACME()
}

func (p *Proxy) SetDefaultCert(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.defaultCert = &cert
	p.mu.Unlock()
	return nil
}

func (p *Proxy) HasCerts() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.defaultCert != nil || len(p.certs) > 0
}

func (p *Proxy) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(hello.ServerName)
			p.mu.RLock()
			cert := p.certs[name]
			def := p.defaultCert
			mgr := p.acme
			p.mu.RUnlock()
			if cert != nil {
				return cert, nil
			}
			// 释放读锁后再尝试 ACME：签发可能耗时数秒，持锁会阻塞 Reload
			if c, err := acmeCertificate(mgr, hello); err == nil && c != nil {
				return c, nil
			}
			if def != nil {
				return def, nil
			}
			return nil, fmt.Errorf("站点 %s 未配置证书", hello.ServerName)
		},
	}
}

func (p *Proxy) matchIP(ip string, nets []*net.IPNet, exact map[string]bool) bool {
	if exact[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	trusted := p.trustedNet
	p.mu.RUnlock()
	ip := engine.ClientIP(r, trusted)

	start := time.Now()
	metricSite, metricBlocked := "", false
	var sw *statusWriter
	defer func() {
		metrics.Default.ObserveDuration(time.Since(start).Seconds())
		if metricSite != "" {
			result := "allowed"
			if metricBlocked {
				result = "blocked"
			}
			metrics.Default.IncRequest(metricSite, result)
		}
		if sw != nil {
			p.Ana.Record(ReqStat{
				IP: ip, Host: metricSite, Path: truncStr(r.URL.Path, pathMaxLen),
				UA: r.Header.Get("User-Agent"), Referer: refererHost(r.Referer(), metricSite),
				Status: sw.code, Blocked: metricBlocked,
			})
		}
	}()

	if r.URL.Path == "/__niubwaf/captcha" && r.Method == http.MethodPost {
		p.Cap.Verify(w, r, ip)
		return
	}

	host := strings.ToLower(stripPort(r.Host))
	metricSite = host
	p.mu.RLock()
	site := p.sites[host]
	black := p.matchIP(ip, p.blackNet, p.blackIP)
	white := p.matchIP(ip, p.whiteNet, p.whiteIP)
	repBanned := p.dynBlack[ip] > time.Now().Unix()
	p.mu.RUnlock()

	if site == nil {
		metricBlocked = true
		WriteBlock(w, http.StatusNotFound, RenderBlockPage("", map[string]string{
			"REQ_ID": store.RandToken()[:12], "REASON": "未找到该域名对应的防护站点",
			"CLIENT_IP": ip, "DOMAIN": host, "TIME": nowStr(),
		}))
		return
	}
	sw = &statusWriter{ResponseWriter: w}
	w = sw

	if site.Enabled && site.HTTPRedirect && r.TLS == nil && p.HTTPSAddr != "" {
		target := "https://" + host
		if p.HTTPSAddr != ":443" {
			target += p.HTTPSAddr
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	reqID := store.RandToken()[:12]
	block := func(status int, action, reason string, ruleID int) {
		metricBlocked = true
		p.logAttack(site, ip, r, action, reason, ruleID, status, reqID)
		WriteBlock(w, status, RenderBlockPage(p.Store.GetSetting("block_page"), map[string]string{
			"REQ_ID": reqID, "REASON": reason, "CLIENT_IP": ip,
			"DOMAIN": host, "TIME": nowStr(), "RULE_ID": fmt.Sprintf("%d", ruleID),
		}))
		p.Store.AddTraffic(site.ID, true, 0)
	}

	if !site.Enabled || white {
		p.forward(w, r, site, ip, reqID, false)
		return
	}
	if black {
		block(http.StatusForbidden, "blacklist", "客户端 IP 位于黑名单", 0)
		return
	}
	if repBanned && p.Store.GetSetting("reputation_enabled") != "off" {
		block(http.StatusForbidden, "reputation", "IP 信誉自动封禁：近期攻击行为过多", 0)
		return
	}

	geoMode := p.Store.GetSetting("geoip_mode")
	geoCountries := p.Store.GetSetting("geoip_countries")
	if !p.Geo.Check(ip, geoMode, geoCountries) {
		block(http.StatusForbidden, "geo", "基于地理位置的访问控制：该区域被限制访问", 0)
		return
	}

	if len(site.rules) > 0 {
		in := &engine.RuleInput{
			ClientIP: ip, Method: r.Method, Path: r.URL.Path, URL: r.URL.RequestURI(),
			Header: r.Header, Query: r.URL.Query(), Country: p.Geo.Country(ip),
		}
		if hit := engine.MatchRule(site.rules, in); hit != nil {
			rid := customRuleIDBase + int(hit.ID)
			switch hit.Action {
			case "allow":
				p.forward(w, r, site, ip, reqID, false)
				return
			case "block":
				reason := hit.ActionParam
				if reason == "" {
					reason = "命中自定义规则：" + hit.Name
				}
				block(http.StatusForbidden, "custom", reason, rid)
				return
			case "redirect":
				if target := SafeRedirect(hit.ActionParam); target != "" {
					p.logAttack(site, ip, r, "custom", "自定义规则重定向："+hit.Name, rid, http.StatusFound, reqID)
					p.Store.AddTraffic(site.ID, false, 0)
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			case "captcha":
				if !p.Cap.ValidCookie(r, ip, site.ID) {
					p.Store.AddTraffic(site.ID, true, 0)
					p.logAttack(site, ip, r, "custom", "命中自定义规则，触发人机验证："+hit.Name, rid, http.StatusTooManyRequests, reqID)
					p.Cap.Issue(w, ip, site.ID, r.URL.RequestURI())
					return
				}
			case "log":
				p.logAttack(site, ip, r, "custom", "命中自定义规则（观察）："+hit.Name, rid, http.StatusOK, reqID)
			}
		}
	}

	// 反爬 Bot 防护：内置爬虫 UA 特征库，命中恶意/自动化客户端按站点动作处置。
	// 置于自定义规则之后（放行规则可豁免特定 UA）、CC 与扫体之前（低成本前置过滤）。
	// 善意爬虫（搜索引擎等）默认放行，仅严格模式处置；已通过人机验证的 cookie 豁免。
	if site.BotMode != "" && site.BotMode != "off" && !p.Cap.ValidCookie(r, ip, site.ID) {
		kind, sig := classifyBotUA(r.Header.Get("User-Agent"))
		if kind == "bad" || (kind == "good" && site.BotStrict) {
			switch site.BotMode {
			case "block":
				block(http.StatusForbidden, "bot", "Bot 防护：识别为自动化爬虫/攻击工具（"+sig+"）", botRuleID)
				return
			case "captcha":
				p.Store.AddTraffic(site.ID, true, 0)
				p.logAttack(site, ip, r, "bot", "Bot 防护：识别为自动化客户端，触发人机验证（"+sig+"）", botRuleID, http.StatusTooManyRequests, reqID)
				p.Cap.Issue(w, ip, site.ID, r.URL.RequestURI())
				return
			case "log":
				p.logAttack(site, ip, r, "bot", "Bot 防护（观察）：识别为自动化爬虫（"+sig+"）", botRuleID, http.StatusOK, reqID)
			}
		}
	}

	if site.CCRate > 0 && !p.Cap.ValidCookie(r, ip, site.ID) {
		if !p.Limiter.Allow(fmt.Sprintf("%s|%d", ip, site.ID), site.CCRate, site.CCBurst) {
			if site.Captcha {
				p.Store.AddTraffic(site.ID, true, 0)
				p.logAttack(site, ip, r, "cc", "访问频率超限，触发人机验证", 0, http.StatusTooManyRequests, reqID)
				p.Cap.Issue(w, ip, site.ID, r.URL.RequestURI())
				return
			}
			block(http.StatusTooManyRequests, "cc", "访问频率超出限制（CC 防护）", 0)
			return
		}
	}

	if site.AuthUser != "" {
		u, pw, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(u), []byte(site.AuthUser)) == 1
		passOK, _ := store.VerifyPass(pw, site.AuthPass)
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="NiuB WAF Authentication"`)
			http.Error(w, "401 Unauthorized - 牛B WAF 身份认证", http.StatusUnauthorized)
			p.Store.AddTraffic(site.ID, false, 0)
			return
		}
	}

	var body []byte
	if r.Body != nil {
		limit := p.bodyInspectLimit()
		// 多读 1 字节用于探测是否超限，避免对超大请求体整体缓冲（每请求占用大内存）
		peek, _ := engine.ReadBodyLimited(r.Body, limit+1)
		if int64(len(peek)) > limit {
			// 超限：拼回原流原样透传（不截断、不缓冲整体），仅对前缀做检测。
			// 不设 GetBody → 该请求不参与上游故障重试（避免为重试缓冲超大体）。
			body = peek[:limit]
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(peek), r.Body))
		} else {
			r.Body.Close()
			body = peek
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			// 缓冲后统一为 Content-Length 形式：避免 chunked 请求被 CRS 误判，
			// 也防止 ReverseProxy 因 ContentLength 未更新而丢失请求体
			r.ContentLength = int64(len(body))
			r.TransferEncoding = nil
			r.Header.Del("Transfer-Encoding")
			if len(body) > 0 || r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				r.Header.Set("Content-Length", strconv.Itoa(len(body)))
			}
		}
	}

	// 二进制体（镜像层/文件上传等）无文本攻击面：跳过 CRS 扫体与语义 body 扫描，
	// 仅做头/URI 检测，避免大二进制流承担 ~4.5µs/字节的正则成本
	binaryCT := isBinaryContentType(r.Header.Get("Content-Type"))
	detectBody := body
	if binaryCT {
		detectBody = nil
	}

	// Go 将 Host 提升至 r.Host，需补回供 CRS 协议检查（920280 等）使用
	hdr := r.Header.Clone()
	hdr.Set("Host", r.Host)
	res := p.Engine.Detect(site.WAFMode, site.excl, &engine.RequestInfo{
		ClientIP: ip, ServerIP: "127.0.0.1",
		Method: r.Method, URL: r.URL.RequestURI(), Proto: r.Proto,
		Headers: hdr, Body: detectBody,
	})
	if res.Blocked {
		block(res.Status, "waf", res.Msg, res.RuleID)
		return
	}
	if res.LogOnly {
		p.logAttack(site, ip, r, "waf", res.Msg+"（语义复核未确认，放行）", res.RuleID, http.StatusOK, reqID)
	}

	semMode := p.Store.GetSetting("semantic_mode")
	if semMode == "" {
		semMode = "observe"
	}
	if semMode != "off" {
		semBody := body
		if binaryCT {
			semBody = nil
		}
		if hit := p.Engine.Semantic(site.excl, r.URL.RequestURI(), semBody); hit != nil {
			if semMode == "block" {
				block(http.StatusForbidden, "semantic", hit.Msg, hit.RuleID)
				return
			}
			p.logAttack(site, ip, r, "semantic", hit.Msg, hit.RuleID, http.StatusOK, reqID)
		}
	}

	// 动态防护：写操作需携带由植入 JS 签发的动态令牌（已通过人机验证的 cookie 可豁免）
	if site.DynamicMode != "" && site.DynamicMode != "off" && isStateChanging(r.Method) && !p.Cap.ValidCookie(r, ip, site.ID) {
		if !p.hasValidDynToken(r, body, ip, site.ID) {
			if site.DynamicMode == "block" {
				block(http.StatusForbidden, "dynamic", "动态防护：缺少有效动态令牌，疑似自动化或重放请求", dynRuleID)
				return
			}
			p.logAttack(site, ip, r, "dynamic", "动态防护（观察）：写操作缺少有效动态令牌", dynRuleID, http.StatusOK, reqID)
		}
	}

	p.forward(w, r, site, ip, reqID, true)
}

// upstreamTransport 共享上游连接池：限制拨号/TLS/响应头等待，防止慢上游耗尽连接。
// ResponseHeaderTimeout 仅约束响应头到达，不限制 SSE/WebSocket 的后续流式 body。
var upstreamTransport = &http.Transport{
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	IdleConnTimeout:       90 * time.Second,
	MaxIdleConns:          200,
	MaxIdleConnsPerHost:   50,
}

// bodyInspectLimit 返回请求体检测上限（字节）。默认 2MB，可由设置 body_inspect_kb 调整
// （范围 64KB–100MB）。超过该上限的请求体不整体缓冲，改为流式透传并仅检测前缀，
// 以约束单请求内存占用、避免大上传被静默截断。
func (p *Proxy) bodyInspectLimit() int64 {
	kb := 2048
	if v := p.Store.GetSetting("body_inspect_kb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			kb = n
		}
	}
	return int64(kb) << 10
}

// bodyScanLimit 返回送检上限（字节）。默认 16KB，可由设置 body_scan_kb 调整（16KB–1MB）。
// CRS 正则扫描成本约 4.5µs/字节，因此该上限决定单请求检测的 CPU 上界；
// 超出部分仍原样转发给上游，只是不做内容检测。
func (p *Proxy) bodyScanLimit() int {
	kb := 16
	if v := p.Store.GetSetting("body_scan_kb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			kb = n
		}
	}
	return kb << 10
}

// isBinaryContentType 判定二进制类 Content-Type（无文本攻击面），用于跳过请求体扫描
func isBinaryContentType(ct string) bool {
	base := strings.ToLower(ct)
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	switch base {
	case "application/octet-stream", "application/zip", "application/gzip", "application/x-gzip",
		"application/x-tar", "application/x-bzip2", "application/x-xz", "application/zstd",
		"application/wasm", "application/x-7z-compressed", "application/x-rar-compressed",
		"application/java-archive", "application/x-iso9660-image", "application/pdf":
		return true
	}
	return strings.HasPrefix(base, "image/") || strings.HasPrefix(base, "video/") ||
		strings.HasPrefix(base, "audio/") || strings.HasPrefix(base, "font/")
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, site *cachedSite, ip, reqID string, countTraffic bool) {
	needResp := site.RespDetect && site.Enabled
	needDyn := site.DynamicMode != "" && site.DynamicMode != "off" && site.Enabled
	var hdr http.Header
	if needResp || needDyn {
		hdr = r.Header.Clone()
		hdr.Set("Host", r.Host)
	}
	attempts := len(site.targets)
	for i := 0; i < attempts; i++ {
		t := site.pick()
		if t == nil {
			break
		}
		var respBlocked bool
		var respBytes int64
		var failed bool
		rp := &httputil.ReverseProxy{
			Transport: upstreamTransport,
			Director: func(req *http.Request) {
				req.URL.Scheme = t.u.Scheme
				req.URL.Host = t.u.Host
				req.Host = t.u.Host
				req.Header.Set("X-Real-IP", ip)
				req.Header.Set("X-NiuB-WAF-Req-ID", reqID)
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				failed = true
				atomic.StoreInt64(&t.downUntil, time.Now().Unix()+10)
				log.Printf("上游错误 %s: %v", t.u, err)
			},
		}
		if hdr != nil {
			rp.ModifyResponse = func(resp *http.Response) error {
				ct := resp.Header.Get("Content-Type")
				ce := resp.Header.Get("Content-Encoding")
				// SSE(text/event-stream) 必须流式透传，缓冲会断流；编码内容/非文本同样跳过
				if ce != "" || resp.Body == nil || strings.Contains(ct, "text/event-stream") || (!strings.Contains(ct, "text/") && !strings.Contains(ct, "json")) {
					return nil
				}
				isHTML := strings.Contains(ct, "text/html")
				if !needResp && !(needDyn && isHTML) {
					return nil
				}
				limit := int64(1 << 20)
				if needDyn && isHTML {
					limit = 5 << 20
				}
				// 已知超大响应直接透传，避免缓冲占用与截断
				if resp.ContentLength > limit {
					return nil
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
				if err != nil {
					resp.Body.Close()
					return err
				}
				if int64(len(body)) > limit {
					// 长度未知且超限：拼接已读部分与剩余流，原样透传不截断
					resp.Body = &multiReadCloser{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
					return nil
				}
				resp.Body.Close()
				respBytes = int64(len(body))
				if needResp {
					res := p.Engine.DetectResponse(site.WAFMode, site.excl, &engine.RequestInfo{
						ClientIP: ip, Method: r.Method, URL: r.URL.RequestURI(), Proto: r.Proto, Headers: hdr,
					}, resp.StatusCode, resp.Header, body)
					if res.Blocked {
						respBlocked = true
						html := RenderBlockPage(p.Store.GetSetting("block_page"), map[string]string{
							"REQ_ID": reqID, "REASON": "响应内容检测：" + res.Msg, "CLIENT_IP": ip,
							"DOMAIN": site.Domain, "TIME": nowStr(), "RULE_ID": fmt.Sprintf("%d", res.RuleID),
						})
						p.logAttack(site, ip, r, "resp", res.Msg, res.RuleID, res.Status, reqID)
						resp.StatusCode = res.Status
						resp.Body = io.NopCloser(strings.NewReader(html))
						resp.ContentLength = int64(len(html))
						resp.Header.Set("Content-Type", "text/html; charset=utf-8")
						resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(html)))
						resp.Header.Del("Content-Encoding")
						return nil
					}
				}
				if needDyn && isHTML {
					body = p.injectDynamic(body, ip, site.ID)
				}
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))
				resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
				return nil
			}
		}

		if i > 0 && r.GetBody != nil {
			r.Body, _ = r.GetBody()
		}
		rec := &countWriter{ResponseWriter: w}
		rp.ServeHTTP(rec, r)
		if !failed {
			metrics.Default.AddResponseBytes(rec.n + respBytes)
			if countTraffic {
				p.Store.AddTraffic(site.ID, respBlocked, rec.n+respBytes)
			}
			return
		}
		// 请求体无法回卷时不再重试，避免向上游发送残缺请求
		// （ContentLength!=0 涵盖已知长度>0 与 chunked 未知长度-1 两种有体情形）
		if r.GetBody == nil && r.ContentLength != 0 {
			break
		}
	}
	WriteBlock(w, http.StatusBadGateway, RenderBlockPage("", map[string]string{
		"REQ_ID": reqID, "REASON": "上游站点无法访问", "CLIENT_IP": ip,
		"DOMAIN": site.Domain, "TIME": nowStr(),
	}))
	if countTraffic {
		p.Store.AddTraffic(site.ID, false, 0)
	}
}

type countWriter struct {
	http.ResponseWriter
	n int64
}

// statusWriter 记录响应状态码供流量分析聚合（未显式 WriteHeader 视为 200）
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.code != 0 {
		return // 与 net/http 一致：重复 WriteHeader 忽略，避免 superfluous 日志
	}
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := h.Hijack()
		if err == nil && s.code == 0 {
			// 劫持成功（如 WebSocket 升级）记为 101，流量分析不再出现状态码 0
			s.code = http.StatusSwitchingProtocols
		}
		return conn, rw, err
	}
	return nil, nil, fmt.Errorf("niubwaf: 底层 ResponseWriter 不支持连接劫持")
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

// Unwrap 让 http.ResponseController 穿透包装层触达底层 Flusher/Hijacker/超时控制
func (c *countWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// Flush 透传流式刷新，支持 SSE / chunked 长连接
func (c *countWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack 透传连接劫持，支持 WebSocket / HTTP Upgrade
func (c *countWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := c.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("niubwaf: 底层 ResponseWriter 不支持连接劫持")
}

// multiReadCloser 把已缓冲字节与剩余上游流拼接回完整响应体，超限时原样透传不截断
type multiReadCloser struct {
	io.Reader
	io.Closer
}

func (p *Proxy) logAttack(site *cachedSite, ip string, r *http.Request, action, msg string, ruleID, status int, reqID string) {
	metrics.Default.IncAttack(action)
	geo := p.Geo.CityInfo(ip)
	lat, lon := geoCoords(geo)
	p.Ana.Event(EvStat{IP: ip, Action: action, Msg: msg, RuleID: ruleID, Status: status, Country: geo.Country, City: geo.City, Lat: lat, Lon: lon, URL: r.URL.RequestURI(), Domain: site.Domain})
	l := &store.AttackLog{
		SiteID: site.ID, Domain: site.Domain, ClientIP: ip, Country: geo.Country,
		Method: r.Method, URL: r.URL.RequestURI(), Action: action,
		RuleID: ruleID, Msg: msg, Severity: severityOf(action), Status: status, ReqID: reqID,
	}
	if err := p.Store.LogAttack(l); err != nil {
		log.Printf("写入攻击日志失败: %v", err)
	}
	p.Hub.Broadcast(map[string]any{
		"type": "attack", "ts": nowStr(), "domain": site.Domain, "ip": ip,
		"country": geo.Country, "city": geo.City, "method": r.Method, "url": l.URL,
		"action": action, "msg": msg, "status": status, "lat": lat, "lon": lon,
	})
}

func severityOf(action string) string {
	switch action {
	case "waf", "resp":
		return "CRITICAL"
	case "cc", "semantic", "reputation", "custom", "dynamic", "bot":
		return "WARNING"
	default:
		return "NOTICE"
	}
}

// customRuleIDBase 自定义规则日志规则号偏移，避免与 CRS/语义规则号冲突
const customRuleIDBase = 200000

// SafeRedirect 仅允许站内相对路径（单 / 开头）或 http(s) 绝对地址，杜绝 //evil.com 与 javascript: 开放重定向
func SafeRedirect(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") && !strings.HasPrefix(target, "/\\") {
		return target
	}
	if u, err := url.Parse(target); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		return target
	}
	return ""
}