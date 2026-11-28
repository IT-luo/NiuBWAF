package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"niubwaf/internal/apispec"
	"niubwaf/internal/engine"
	"niubwaf/internal/metrics"
	"niubwaf/internal/store"
)

type upstreamTarget struct {
	u            *url.URL
	dialAddress  string
	slots        chan struct{}
	downUntil    int64 // Unix 秒，0 表示健康
	nextErrorLog int64 // Unix 秒，限制同一上游故障的重复日志
}

type cachedSite struct {
	store.Site
	targets        []*upstreamTarget
	rr             uint64
	excl           []engine.Exclusion
	rules          []engine.CompiledRule
	rateRules      []engine.CompiledRule
	shadowRules    []cachedShadowRule
	apiPolicy      *apispec.Policy
	apiDigest      [sha256.Size]byte
	uploadPolicies map[uploadRoute]store.UploadPolicy
	verifyCrawlers bool
	botPathLimit   int
	ingressSeen    *atomic.Int64
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
	mu         sync.Mutex
	subs       map[chan []byte]struct{}
	relay      *hubRelayPeer
	ratePaused bool
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
	defer h.mu.Unlock()
	if h.ratePaused {
		if event, ok := v.(map[string]any); ok && event["type"] == "qps" {
			return
		}
	}
	h.broadcastLocked(data)
	if h.relay != nil {
		h.relay.enqueue(data)
	}
}

func (h *Hub) broadcastLocked(data []byte) {
	for ch := range h.subs {
		select {
		case ch <- data:
		default:
		}
	}
}

type Proxy struct {
	Store             *store.Store
	Engine            *engine.Engine
	Geo               *GeoIP
	IDC               *IDCMatcher
	Tor               *TorList
	Limiter           *Limiter
	Cap               *Captcha
	Hub               *Hub
	Ana               *Analytics
	threat            *ThreatIntel
	crawlers          *crawlerVerifier
	botPaths          botPathTracker
	upstreamLimit     int
	upstreamTransport *http.Transport
	uploadBudget      uploadBudget
	diagnostics       diagnosticCache
	ingress           ingressVerifier
	// HTTPSAddr 用于 HTTP→HTTPS 跳转时构造目标地址，如 ":8443"
	HTTPSAddr string

	reloadMu     sync.Mutex
	mu           sync.RWMutex
	sites        map[string]*cachedSite
	blackNet     []*net.IPNet
	whiteNet     []*net.IPNet
	trustedNet   []*net.IPNet // 可信代理网段：仅这些对端追加的 XFF 才被采信
	blackIP      map[string]bool
	whiteIP      map[string]bool
	dynBlack     map[string]int64 // IP 信誉自动封禁：ip → unix 到期秒
	certs        map[string]*tls.Certificate
	managedCerts map[string]*tls.Certificate
	defaultCert  *tls.Certificate

	dynSecret []byte
	dynMu     sync.Mutex
	dynPools  map[int64]*dynNoncePool

	lastRepLogID atomic.Int64 // 上次信誉聚合时的最大攻击日志 ID，用于空闲跳过
	repIdle      atomic.Int32 // 连续空闲周期计数

	alertMu   sync.Mutex
	lastAlert time.Time

	backgroundMu   sync.Mutex
	stopBackground context.CancelFunc
}

func New(st *store.Store, eng *engine.Engine, geo *GeoIP, idc *IDCMatcher, tor *TorList, secret string) *Proxy {
	return NewWithUpstreamLimit(st, eng, geo, idc, tor, secret, DefaultUpstreamConnections)
}

func NewWithUpstreamLimit(st *store.Store, eng *engine.Engine, geo *GeoIP, idc *IDCMatcher, tor *TorList, secret string, limit int) *Proxy {
	p := NewWithPausedBackgroundJobs(st, eng, geo, idc, tor, secret, limit)
	p.ResumeBackgroundJobs()
	return p
}

// NewWithPausedBackgroundJobs initializes a worker without running global
// reputation calculations or alerts before that worker is active.
func NewWithPausedBackgroundJobs(st *store.Store, eng *engine.Engine, geo *GeoIP, idc *IDCMatcher, tor *TorList, secret string, limit int) *Proxy {
	if limit <= 0 {
		limit = DefaultUpstreamConnections
	}
	p := &Proxy{
		Store: st, Engine: eng, Geo: geo, IDC: idc, Tor: tor,
		Limiter: NewLimiter(), Cap: NewCaptcha(secret), Hub: NewHub(),
		Ana:       NewAnalytics(st, geo),
		dynSecret: []byte(secret), threat: NewThreatIntel(st), crawlers: newCrawlerVerifier(),
		upstreamLimit: limit, upstreamTransport: newUpstreamTransport(limit),
	}
	p.Hub.pauseRateFeed(true)
	p.Reload()
	go func() {
		for range time.Tick(30 * time.Second) {
			p.Reload()
		}
	}()
	go p.healthLoop()
	go p.qpsLoop()
	return p
}

// ResumeBackgroundJobs schedules the recurring operations owned by the active
// worker. Reloads, health checks and request handling run in every worker.
func (p *Proxy) ResumeBackgroundJobs() {
	p.backgroundMu.Lock()
	defer p.backgroundMu.Unlock()
	if p.stopBackground != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.stopBackground = cancel
	p.Hub.pauseRateFeed(false)
	go p.reputationLoop(ctx)
	go p.alertLoop(ctx)
}

// PauseBackgroundJobs stops scheduling alerts and reputation calculations
// while a retiring worker continues to serve its established connections.
func (p *Proxy) PauseBackgroundJobs() {
	p.backgroundMu.Lock()
	defer p.backgroundMu.Unlock()
	if p.stopBackground != nil {
		p.stopBackground()
		p.stopBackground = nil
	}
}

const healthCheckUserAgent = "NiuBWAF-HealthCheck/1.0"

// healthLoop 定期探测已启用站点的上游。
func (p *Proxy) healthLoop() {
	for range time.Tick(5 * time.Second) {
		metrics.Default.SetUpstreams(p.checkUpstreams())
	}
}

// 只探测配置的上游。任意 HTTP 响应仍视为可达，连接失败时摘除 5 秒。
func (p *Proxy) checkUpstreams() []metrics.UpstreamSample {
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	p.mu.RLock()
	var sites []*cachedSite
	for _, site := range p.sites {
		if site.Enabled {
			sites = append(sites, site)
		}
	}
	p.mu.RUnlock()
	var ups []metrics.UpstreamSample
	for _, site := range sites {
		for _, target := range site.targets {
			up := probeUpstream(client, target.u.String()+"/") == nil
			var downUntil int64
			if !up {
				downUntil = time.Now().Unix() + 5
			}
			atomic.StoreInt64(&target.downUntil, downUntil)
			ups = append(ups, metrics.UpstreamSample{Site: site.Domain, URL: store.DisplayUpstreamURL(target.u), Up: up})
		}
	}
	return ups
}

func probeUpstream(client *http.Client, target string) error {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", healthCheckUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
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
			st.Targets = append(st.Targets, TargetStatus{URL: store.DisplayUpstreamURL(t.u), Up: atomic.LoadInt64(&t.downUntil) <= now})
		}
		out = append(out, st)
	}
	return out
}

func (p *Proxy) Reload() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	sites, err := p.Store.ListSites()
	if err != nil {
		log.Printf("加载站点失败: %v", err)
		return
	}
	policies, err := p.Store.EnabledAPIPolicies()
	if err != nil {
		log.Printf("加载 API 契约失败: %v", err)
		return
	}
	uploadPolicies, err := p.Store.UploadPoliciesBySite()
	if err != nil {
		log.Printf("加载上传策略失败: %v", err)
		return
	}
	m := map[string]*cachedSite{}
	excls, err := p.Store.ListExclusions()
	if err != nil {
		log.Printf("加载规则豁免失败: %v", err)
		return
	}
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
	crs, err := p.Store.ListRules()
	if err != nil {
		log.Printf("加载自定义规则失败: %v", err)
		return
	}
	var globalRules []engine.CompiledRule
	var globalShadowRules []cachedShadowRule
	perSiteRules := map[int64][]engine.CompiledRule{}
	perSiteShadowRules := map[int64][]cachedShadowRule{}
	for _, r := range crs {
		if !r.Enabled {
			continue
		}
		cr, err := engine.CompileRule(engine.RuleDef{
			ID: r.ID, SiteID: r.SiteID, Name: r.Name, Priority: r.Priority,
			Logic: r.Logic, Conditions: r.Conditions, Action: r.Action, ActionParam: r.ActionParam, Shadow: r.Shadow,
		})
		if err != nil {
			log.Printf("自定义规则 %d(%s) 编译失败，已跳过: %v", r.ID, r.Name, err)
			continue
		}
		if r.Shadow {
			sr := cachedShadowRule{rule: cr, definition: shadowRuleDefinition(r)}
			if r.SiteID == 0 {
				globalShadowRules = append(globalShadowRules, sr)
			} else {
				perSiteShadowRules[r.SiteID] = append(perSiteShadowRules[r.SiteID], sr)
			}
		} else if r.SiteID == 0 {
			globalRules = append(globalRules, cr)
		} else {
			perSiteRules[r.SiteID] = append(perSiteRules[r.SiteID], cr)
		}
	}
	p.mu.RLock()
	type targetKey struct {
		siteID int64
		url    string
	}
	oldTargets := map[targetKey]*upstreamTarget{}
	originSlots := map[string]chan struct{}{}
	oldShadow := map[shadowRuleKey]cachedShadowRule{}
	oldPolicies := map[int64]*cachedSite{}
	for _, os := range p.sites {
		if os.apiPolicy != nil {
			oldPolicies[os.ID] = os
		}
		for _, t := range os.targets {
			oldTargets[targetKey{os.ID, t.u.String()}] = t
			originSlots[upstreamOrigin(t.u)] = t.slots
		}
		for _, sr := range os.shadowRules {
			oldShadow[shadowRuleKey{siteID: os.ID, ruleID: sr.rule.ID}] = sr
		}
	}
	p.mu.RUnlock()
	limit := p.upstreamLimit
	if limit <= 0 {
		limit = DefaultUpstreamConnections
	}
	verifyCrawlers := p.Store.GetSetting("bot_verify_crawlers") == "on"
	botPathLimit, _ := strconv.Atoi(p.Store.GetSetting("bot_path_limit"))
	botPathLimit = max(0, min(128, botPathLimit))
	for _, s := range sites {
		var targets []*upstreamTarget
		for _, raw := range strings.Split(s.Upstream, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				log.Printf("站点 %s 存在无效上游地址", s.Domain)
				continue
			}
			target := oldTargets[targetKey{s.ID, u.String()}]
			if target == nil {
				address := upstreamAddress(u)
				origin := u.Scheme + "://" + address
				slots := originSlots[origin]
				if slots == nil {
					slots = make(chan struct{}, limit)
					originSlots[origin] = slots
				}
				target = &upstreamTarget{u: u, dialAddress: address, slots: slots}
			}
			targets = append(targets, target)
		}
		if len(targets) == 0 {
			log.Printf("站点 %s 无有效上游地址", s.Domain)
			continue
		}
		cs := &cachedSite{Site: s, targets: targets, verifyCrawlers: verifyCrawlers, botPathLimit: botPathLimit}
		if policies := uploadPolicies[s.ID]; len(policies) > 0 {
			cs.uploadPolicies = make(map[uploadRoute]store.UploadPolicy, len(policies))
			for _, policy := range policies {
				cs.uploadPolicies[uploadRoute{method: policy.Method, path: policy.Path}] = policy
			}
		}
		if cs.verifyCrawlers && cs.Enabled && cs.BotMode != "" && cs.BotMode != "off" && p.crawlers != nil {
			p.crawlers.refreshIfDue()
		}
		if config, ok := policies[s.ID]; ok {
			digest := sha256.Sum256([]byte(config.Document))
			old := oldPolicies[s.ID]
			if old != nil && old.apiDigest == digest && old.apiPolicy.Mode == config.Mode && old.apiPolicy.Prefix == config.Prefix {
				cs.apiPolicy, cs.apiDigest = old.apiPolicy, digest
			} else {
				policy, err := apispec.Compile(context.Background(), config.Mode, config.Prefix, config.Document)
				if err != nil {
					log.Printf("站点 %s API 契约编译失败: %v", s.Domain, err)
					if old != nil {
						cs.apiPolicy, cs.apiDigest = old.apiPolicy, old.apiDigest
					}
				} else {
					cs.apiPolicy, cs.apiDigest = policy, digest
				}
			}
		}
		cs.excl = append(append([]engine.Exclusion{}, globalExcl...), perSite[s.ID]...)
		rules := append(append([]engine.CompiledRule{}, globalRules...), perSiteRules[s.ID]...)
		sort.SliceStable(rules, func(i, j int) bool {
			if rules[i].Priority != rules[j].Priority {
				return rules[i].Priority < rules[j].Priority
			}
			return rules[i].ID < rules[j].ID
		})
		for _, rule := range rules {
			if rule.Action == engine.RuleActionRateLimit {
				cs.rateRules = append(cs.rateRules, rule)
			} else {
				cs.rules = append(cs.rules, rule)
			}
		}
		shadowRules := append(append([]cachedShadowRule{}, globalShadowRules...), perSiteShadowRules[s.ID]...)
		for _, sr := range shadowRules {
			key := shadowRuleKey{siteID: s.ID, ruleID: sr.rule.ID}
			if old, ok := oldShadow[key]; ok && old.definition == sr.definition {
				sr.stats = old.stats
			} else {
				sr.stats = &shadowRuleStats{since: time.Now()}
			}
			cs.shadowRules = append(cs.shadowRules, sr)
		}
		sort.SliceStable(cs.shadowRules, func(i, j int) bool {
			if cs.shadowRules[i].rule.Priority != cs.shadowRules[j].rule.Priority {
				return cs.shadowRules[i].rule.Priority < cs.shadowRules[j].rule.Priority
			}
			return cs.shadowRules[i].rule.ID < cs.shadowRules[j].rule.ID
		})
		m[strings.ToLower(s.Domain)] = cs
	}
	ips, err := p.Store.ListIPs("")
	if err != nil {
		log.Printf("加载 IP 名单失败: %v", err)
		return
	}
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
	managed, err := p.Store.ManagedSiteCertificates()
	if err != nil {
		log.Printf("加载托管证书失败: %v", err)
		return
	}
	managedCerts := make(map[string]*tls.Certificate, len(managed))
	for _, item := range managed {
		cert, err := tls.X509KeyPair([]byte(item.CertPEM), []byte(item.KeyPEM))
		if err != nil {
			log.Printf("站点 %s 托管证书解析失败: %v", item.Domain, err)
			continue
		}
		if cert.Leaf == nil {
			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				log.Printf("站点 %s 托管证书解析失败: %v", item.Domain, err)
				continue
			}
		}
		managedCerts[strings.ToLower(item.Domain)] = &cert
	}
	dynBlack, err := p.Store.ActiveBans(now)
	if err != nil {
		log.Printf("加载 IP 封禁失败: %v", err)
		return
	}
	if err := p.Engine.SetContentTypes(engine.ParseContentTypes(p.Store.GetSetting("allowed_content_types"))); err != nil {
		log.Printf("应用允许内容类型失败: %v", err)
	}
	p.Engine.SetScanLimit(p.bodyScanLimit())
	p.mu.Lock()
	p.initIngressTraffic(m)
	p.sites, p.blackNet, p.whiteNet, p.blackIP, p.whiteIP = m, bn, wn, bi, wi
	p.trustedNet = engine.ParseTrustedProxies(p.Store.GetSetting("trusted_proxies"))
	p.certs = certs
	p.managedCerts = managedCerts
	p.dynBlack = dynBlack
	p.pruneDynPools(m)
	p.mu.Unlock()
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
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(hello.ServerName)
			p.mu.RLock()
			cert := p.certs[name]
			managed := p.managedCerts[name]
			def := p.defaultCert
			p.mu.RUnlock()
			if managed != nil {
				now := time.Now()
				if !now.Before(managed.Leaf.NotBefore) && now.Before(managed.Leaf.NotAfter) {
					return managed, nil
				}
			}
			if cert != nil {
				return cert, nil
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

const publicServerName = "NiuBWAF"

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", publicServerName)
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT is not supported", http.StatusMethodNotAllowed)
		return
	}
	p.mu.RLock()
	trusted := p.trustedNet
	p.mu.RUnlock()
	ip := engine.ClientIP(r, trusted)

	start := time.Now()
	metricSite, metricBlocked := "", false
	var sw *statusWriter
	defer func() {
		if sw != nil && sw.diagnostic.Module == "resp" && sw.diagnostic.Outcome == "blocked" {
			metricBlocked = true
		}
		metrics.Default.ObserveDuration(time.Since(start).Seconds())
		if metricSite != "" {
			result := "allowed"
			if metricBlocked {
				result = "blocked"
			}
			metrics.Default.IncRequest(metricSite, result)
		}
		if sw != nil {
			sw.diagnostic.complete(sw.code)
			p.diagnostics.record(sw.diagnostic)
			refHost, refPage := externalReferer(r.Referer(), metricSite)
			p.Ana.Record(ReqStat{
				IP: ip, Host: metricSite, Path: truncStr(r.URL.Path, pathMaxLen), Page: visitedPage(r.TLS != nil, metricSite, r.URL.EscapedPath()),
				UA: r.Header.Get("User-Agent"), Referer: refHost, RefererPage: refPage,
				Status: sw.code, Blocked: metricBlocked,
			})
		}
	}()

	if r.URL.Path == "/__niubwaf/captcha" && r.Method == http.MethodPost {
		p.Cap.Verify(w, r, ip)
		return
	}

	host := strings.ToLower(stripPort(r.Host))
	metricSite = "unknown"
	p.mu.RLock()
	site := p.sites[host]
	black := p.matchIP(ip, p.blackNet, p.blackIP)
	white := p.matchIP(ip, p.whiteNet, p.whiteIP)
	repBanned := p.dynBlack[ip] > time.Now().Unix()
	p.mu.RUnlock()

	reqID := store.RandToken()[:12]
	w.Header().Set(requestDiagnosticHeader, reqID)
	if site == nil {
		metricBlocked = true
		d := RequestDiagnostic{ReqID: reqID, TS: start, Method: diagnosticMethod(r.Method), Status: http.StatusNotFound}
		d.setWAFDecision("rejected", "未找到该域名对应的防护站点", "routing", 0)
		p.diagnostics.record(d)
		WriteBlock(w, http.StatusNotFound, RenderBlockPage("", map[string]string{
			"REQ_ID": reqID, "REASON": d.Reason,
			"CLIENT_IP": ip, "DOMAIN": host, "TIME": nowStr(),
		}))
		return
	}
	metricSite = host
	site.noteIngressTraffic(start, r)
	sw = &statusWriter{ResponseWriter: w, diagnostic: RequestDiagnostic{
		ReqID: reqID, TS: start, Domain: site.Domain, Method: diagnosticMethod(r.Method),
	}}
	w = sw

	if len(r.Header.Values(ingressVerificationHeader)) != 0 {
		if probe := p.claimIngressProbe(r, site, ip, reqID, white); probe != nil {
			r = probe.attach(r)
			defer func() { probe.finish(sw.code) }()
			if probe.block {
				sw.diagnostic.setWAFDecision("blocked", "接入验收测试拦截", "ingress_verification", 0)
				writeIngressBlock(w, reqID, ip, host)
				return
			}
		}
	}

	if site.Enabled && site.HTTPRedirect && r.TLS == nil && p.HTTPSAddr != "" {
		sw.diagnostic.setWAFDecision("redirected", "站点配置将 HTTP 重定向至 HTTPS", "routing", 0)
		target := "https://" + host
		if p.HTTPSAddr != ":443" {
			target += p.HTTPSAddr
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	block := func(status int, action, reason string, ruleID int) {
		metricBlocked = true
		sw.diagnostic.setWAFDecision("blocked", DiagnosticRuleReason(action, status), action, ruleID)
		p.logAttack(site, ip, r, action, reason, ruleID, status, reqID)
		WriteBlock(w, status, RenderBlockPage(p.Store.GetSetting("block_page"), map[string]string{
			"REQ_ID": reqID, "REASON": reason, "CLIENT_IP": ip,
			"DOMAIN": host, "TIME": nowStr(), "RULE_ID": fmt.Sprintf("%d", ruleID),
		}))
		p.Store.AddTraffic(site.ID, true, 0)
	}
	logEvent := func(outcome, action, msg string, ruleID, status int) {
		if outcome == "observed" {
			sw.diagnostic.observe(action, ruleID)
		} else {
			sw.diagnostic.setWAFDecision(outcome, DiagnosticRuleReason(action, status), action, ruleID)
		}
		p.logAttack(site, ip, r, action, msg, ruleID, status, reqID)
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

	var rateRule *engine.CompiledRule
	if len(site.rules) > 0 || len(site.shadowRules) > 0 || len(site.rateRules) > 0 {
		in := &engine.RuleInput{
			ClientIP: ip, Method: r.Method, Path: r.URL.Path, URL: r.URL.RequestURI(),
			Header: r.Header, Query: r.URL.Query(), Country: p.Geo.Country(ip),
		}
		// 全部影子规则独立评估完成后，才进入原有真实规则动作链。
		evaluateShadowRules(site.shadowRules, in)
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
					logEvent("redirected", "custom", "自定义规则重定向："+hit.Name, rid, http.StatusFound)
					p.Store.AddTraffic(site.ID, false, 0)
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			case "captcha":
				purpose := "rule-" + strconv.FormatInt(hit.ID, 10)
				if !p.Cap.ValidCookie(r, ip, site.ID, purpose) {
					p.Store.AddTraffic(site.ID, true, 0)
					logEvent("challenged", "custom", "命中自定义规则，触发人机验证："+hit.Name, rid, http.StatusTooManyRequests)
					p.Cap.Issue(w, ip, host, site.ID, purpose, r.URL.RequestURI())
					return
				}
			case "log":
				logEvent("observed", "custom", "命中自定义规则（观察）："+hit.Name, rid, http.StatusOK)
			}
		}
		rateRule = engine.MatchRule(site.rateRules, in)
	}

	// 反爬 Bot 防护：内置爬虫 UA 特征库，命中恶意/自动化客户端按站点动作处置。
	// 置于自定义规则之后（放行规则可豁免特定 UA）、CC 与扫体之前（低成本前置过滤）。
	// 善意爬虫（搜索引擎等）默认放行，仅严格模式处置。
	if site.BotMode != "" && site.BotMode != "off" {
		kind, sig := classifyBotUA(r.Header.Get("User-Agent"))
		verified := false
		if site.verifyCrawlers && kind == "good" {
			match, available := p.crawlers.verified(sig, ip)
			verified = available && match
			if available && !match {
				kind, sig = "bad", sig+" 来源未通过验证"
			}
		}
		identified := kind == "bad" || (kind == "good" && site.BotStrict)
		pathLimited, first := false, false
		if !identified && !verified && site.botPathLimit > 0 {
			pathLimited, first = p.botPaths.limitNewPath(site.ID, ip, r.URL.Path, site.botPathLimit, time.Now().Unix())
			if pathLimited {
				sig = "短时间访问不同路径过多"
			}
		}
		if identified || pathLimited {
			reason := "Bot 防护：" + sig
			switch site.BotMode {
			case "block":
				status := http.StatusForbidden
				if pathLimited {
					status = http.StatusTooManyRequests
					w.Header().Set("Retry-After", strconv.Itoa(botPathWindowSeconds))
				}
				block(status, "bot", reason, botRuleID)
				return
			case "captcha":
				if !p.Cap.ValidCookie(r, ip, site.ID, captchaBot) {
					metricBlocked = true
					p.Store.AddTraffic(site.ID, true, 0)
					logEvent("challenged", "bot", reason+"，触发人机验证", botRuleID, http.StatusTooManyRequests)
					p.Cap.Issue(w, ip, host, site.ID, captchaBot, r.URL.RequestURI())
					return
				}
			case "log":
				if identified || first {
					logEvent("observed", "bot", "Bot 防护观察："+sig, botRuleID, http.StatusOK)
				}
			}
		}
	}

	if site.CCRate > 0 || rateRule != nil {
		rate, burst := site.CCRate, site.CCBurst
		key := ip + "|" + strconv.FormatInt(site.ID, 10)
		scope, reason, ruleID := "site", "访问频率超出限制（CC 防护）", 0
		if rateRule != nil {
			rate, burst = rateRule.Rate, rateRule.Burst
			key += "|" + strconv.FormatInt(rateRule.ID, 10)
			scope, reason, ruleID = "rule", "接口访问频率超出限制："+rateRule.Name, customRuleIDBase+int(rateRule.ID)
		}
		if !p.Limiter.Allow(key, rate, burst) {
			metrics.Default.IncRateLimited(scope)
			w.Header().Set("Retry-After", "1")
			if site.Captcha && !p.Cap.ValidCookie(r, ip, site.ID, captchaRate) {
				metricBlocked = true
				p.Store.AddTraffic(site.ID, true, 0)
				logEvent("challenged", "cc", reason+"，触发人机验证", ruleID, http.StatusTooManyRequests)
				p.Cap.Issue(w, ip, host, site.ID, captchaRate, r.URL.RequestURI())
				return
			}
			block(http.StatusTooManyRequests, "cc", reason, ruleID)
			return
		}
	}

	if !p.requireSiteAuth(w, r, site) {
		return
	}
	for _, encoding := range r.Header.Values("Content-Encoding") {
		if !strings.EqualFold(strings.TrimSpace(encoding), "identity") {
			block(http.StatusUnsupportedMediaType, "waf", "防护站点仅接受未压缩的请求体", 0)
			return
		}
	}
	defaultLimit := min(p.bodyInspectLimit(), int64(p.Engine.ScanLimit()))
	limit := defaultLimit
	route := uploadRoute{method: r.Method, path: r.URL.EscapedPath()}
	uploadPolicy, matchedUpload := site.uploadPolicies[route]
	if matchedUpload {
		limit = int64(uploadPolicy.MaxBodyMiB) << 20
		sw.diagnostic.BodyLimitKind = "upload_policy"
	} else {
		sw.diagnostic.BodyLimitKind = "inspection"
	}
	sw.diagnostic.BodyLimitBytes = limit
	if r.ContentLength > 0 {
		sw.diagnostic.BodyBytes = r.ContentLength
		sw.diagnostic.BodyBytesKind = "declared"
	}
	if r.ContentLength > limit {
		block(http.StatusRequestEntityTooLarge, "waf", "请求体超过完整检测上限", 0)
		return
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		largeUpload := matchedUpload && (r.ContentLength < 0 || r.ContentLength > defaultLimit)
		if largeUpload {
			reserve := limit
			if r.ContentLength >= 0 {
				reserve = r.ContentLength
			}
			key := uploadRouteKey{siteID: site.ID, route: route}
			if !p.uploadBudget.acquire(key, uploadPolicy, reserve) {
				metrics.Default.IncOverloadRejected("upload_capacity")
				sw.diagnostic.setWAFDecision("rejected", "大文件上传并发槽位或在途请求体容量已满", "upload_capacity", 0)
				w.Header().Set("Retry-After", "1")
				WriteBlock(w, http.StatusServiceUnavailable, RenderBlockPage(p.Store.GetSetting("block_page"), map[string]string{
					"REQ_ID": reqID, "REASON": "大文件上传繁忙，请稍后重试",
					"CLIENT_IP": ip, "DOMAIN": host, "TIME": nowStr(),
				}))
				p.Store.AddTraffic(site.ID, false, 0)
				return
			}
			defer p.uploadBudget.release(key, reserve)
			// 已知长度时按实际长度限制读取，分块上传按策略上限预留。
			limit = reserve
		}
		var err error
		boundedBody := http.MaxBytesReader(sw.ResponseWriter, r.Body, limit)
		if largeUpload {
			body, err = readUploadBody(boundedBody, r.ContentLength)
		} else {
			body, err = io.ReadAll(boundedBody)
		}
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				if tooLarge.Limit != sw.diagnostic.BodyLimitBytes {
					sw.diagnostic.BodyLimitKind = "declared_upload"
				}
				sw.diagnostic.BodyLimitBytes = tooLarge.Limit
				sw.diagnostic.BodyBytes = tooLarge.Limit + 1
				sw.diagnostic.BodyBytesKind = "at_least"
				block(http.StatusRequestEntityTooLarge, "waf", "请求体超过完整检测上限", 0)
			} else {
				block(http.StatusBadRequest, "waf", "请求体读取失败", 0)
			}
			return
		}
		sw.diagnostic.BodyBytes = int64(len(body))
		sw.diagnostic.BodyBytesKind = "read"
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
		r.Trailer = nil
		r.Header.Del("Transfer-Encoding")
		r.Header.Del("Trailer")
		// 请求体已接收；回源时避免上游再发一次 100 Continue。
		r.Header.Del("Expect")
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	// Go 将 Host 提升至 r.Host，需补回供 CRS 协议检查（920280 等）使用
	hdr := r.Header.Clone()
	hdr.Set("Host", r.Host)
	requestInfo := &engine.RequestInfo{
		ClientIP: ip, ServerIP: "127.0.0.1",
		Method: r.Method, URL: r.URL.RequestURI(), Proto: r.Proto,
		Headers: hdr, Body: body,
	}
	detect := func(info *engine.RequestInfo) engine.Result {
		if matchedUpload {
			return p.Engine.DetectUpload(site.WAFMode, site.excl, info, int(limit))
		}
		return p.Engine.Detect(site.WAFMode, site.excl, info)
	}
	res := detect(requestInfo)
	if !res.Blocked && len(body) > 0 {
		if reviewCT := bodyReviewContentType(r.Header.Get("Content-Type"), body); reviewCT != "" {
			// Coraza 对未识别的 Content-Type 不运行正文处理器。保留上述原始头/URI检测，
			// 再用实际正文适配的处理器复核，避免伪造 binary 类型令 ARGS/REQUEST_BODY 为空。
			reviewHeaders := hdr.Clone()
			reviewHeaders.Set("Content-Type", reviewCT)
			reviewInfo := *requestInfo
			reviewInfo.Headers = reviewHeaders
			review := detect(&reviewInfo)
			if review.Blocked || (review.LogOnly && !res.LogOnly) {
				res = review
			}
		}
	}
	if res.Blocked {
		block(res.Status, "waf", res.Msg, res.RuleID)
		return
	}
	if res.LogOnly {
		logEvent("observed", "waf", res.Msg+"（语义复核未确认，放行）", res.RuleID, http.StatusOK)
	}

	if diagnostic := site.apiPolicy.Check(r, body); diagnostic != "" {
		if site.apiPolicy.Mode == "block" {
			block(http.StatusBadRequest, "api_schema", diagnostic, 0)
			return
		}
		logEvent("observed", "api_schema", "API 契约观察："+diagnostic, 0, http.StatusOK)
	}

	semMode := p.Store.GetSetting("semantic_mode")
	if semMode == "" {
		semMode = "observe"
	}
	if semMode != "off" {
		if hit := p.Engine.Semantic(site.excl, r.URL.RequestURI(), body); hit != nil {
			if semMode == "block" {
				block(http.StatusForbidden, "semantic", hit.Msg, hit.RuleID)
				return
			}
			logEvent("observed", "semantic", hit.Msg, hit.RuleID, http.StatusOK)
		}
	}

	// 动态防护要求写操作携带由植入 JS 签发的动态令牌。
	nextDynToken := ""
	if site.DynamicMode != "" && site.DynamicMode != "off" && isStateChanging(r.Method) {
		if !p.consumeDynToken(r, body, ip, site.ID) {
			if site.DynamicMode == "block" {
				block(http.StatusForbidden, "dynamic", "动态防护：缺少有效动态令牌，疑似自动化或重放请求", dynRuleID)
				return
			}
			logEvent("observed", "dynamic", "动态防护（观察）：写操作缺少有效动态令牌", dynRuleID, http.StatusOK)
		} else {
			nextDynToken = p.issueDynToken(ip, site.ID)
		}
	}

	p.forwardWithDynToken(w, r, site, ip, reqID, true, nextDynToken)
}

const (
	DefaultUpstreamConnections = 256
	upstreamSlotWait           = time.Second
	upstreamDialTimeout        = 5 * time.Second
	upstreamErrorLogInterval   = 5 * time.Second
	proxyResponseBufferSize    = 32 << 10
)

var (
	upstreamDialer      = net.Dialer{Timeout: upstreamDialTimeout, KeepAlive: 30 * time.Second}
	upstreamDialSlots   = make(chan struct{}, 64)
	errDialQueueTimeout = errors.New("等待上游拨号名额超时")
	errUpstreamBusy     = errors.New("上游连接池已满")
	responseBuffers     = proxyBufferPool{pool: sync.Pool{
		New: func() any { return new([proxyResponseBufferSize]byte) },
	}}
)

func upstreamOrigin(u *url.URL) string {
	return u.Scheme + "://" + upstreamAddress(u)
}

func upstreamAddress(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host, zone, scoped := strings.Cut(u.Hostname(), "%")
	host = strings.ToLower(host)
	if scoped {
		host += "%" + zone
	}
	return net.JoinHostPort(host, port)
}

func (t *upstreamTarget) acquire(ctx context.Context) error {
	if t.slots == nil {
		return nil
	}
	select {
	case t.slots <- struct{}{}:
		return nil
	default:
	}
	waitStart := time.Now()
	metrics.Default.StartUpstreamWait()
	defer func() { metrics.Default.FinishUpstreamWait(time.Since(waitStart)) }()
	timer := time.NewTimer(upstreamSlotWait)
	defer timer.Stop()
	select {
	case t.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errUpstreamBusy
	}
}

func (t *upstreamTarget) serve(rp *httputil.ReverseProxy, w http.ResponseWriter, r *http.Request) {
	if t.slots != nil {
		defer func() { <-t.slots }()
	}
	rp.ServeHTTP(w, r)
}

// dialUpstream 限制同时建连的数量，已建立的连接继续服务请求与长流。
func dialUpstream(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamDialTimeout)
	defer cancel()
	select {
	case upstreamDialSlots <- struct{}{}:
		defer func() { <-upstreamDialSlots }()
	case <-ctx.Done():
		return nil, errDialQueueTimeout
	}
	conn, err := upstreamDialer.DialContext(ctx, network, address)
	if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		// Windows reports WSAEADDRINUSE / WSAEADDRNOTAVAIL with Winsock error numbers.
		(runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(10048)) || errors.Is(err, syscall.Errno(10049)))) {
		return nil, fmt.Errorf("%w: %w", errUpstreamBusy, err)
	}
	return conn, err
}

type proxyBufferPool struct{ pool sync.Pool }

func (p *proxyBufferPool) Get() []byte {
	return p.pool.Get().(*[proxyResponseBufferSize]byte)[:]
}

func (p *proxyBufferPool) Put(buf []byte) {
	p.pool.Put((*[proxyResponseBufferSize]byte)(buf))
}

func (t *upstreamTarget) recordFailure(err error) {
	now := time.Now().Unix()
	atomic.StoreInt64(&t.downUntil, now+10)
	next := atomic.LoadInt64(&t.nextErrorLog)
	if now >= next && atomic.CompareAndSwapInt64(&t.nextErrorLog, next, now+int64(upstreamErrorLogInterval/time.Second)) {
		log.Printf("上游错误 %s (%T)", store.DisplayUpstreamURL(t.u), err)
	}
}

// 活跃连接与单上游空闲连接使用同一上限，避免高峰期反复新建和淘汰连接。
// ResponseHeaderTimeout 仅约束响应头到达，不限制 SSE/WebSocket 的后续流式 body。
func newUpstreamTransport(limit int) *http.Transport {
	return &http.Transport{
		DialContext:           dialUpstream,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          max(512, limit),
		MaxIdleConnsPerHost:   limit,
		MaxConnsPerHost:       limit,
	}
}

var upstreamTransport = newUpstreamTransport(DefaultUpstreamConnections)

// bodyInspectLimit 返回请求体缓冲上限，完整检查还受引擎送检上限约束。
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
func (p *Proxy) bodyScanLimit() int {
	kb := 16
	if v := p.Store.GetSetting("body_scan_kb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			kb = n
		}
	}
	return kb << 10
}

// bodyReviewContentType 为没有 CRS 正文处理器的类型选择仅用于检测的处理器。
// 返回空串表示原请求已具备 JSON/XML/表单处理器，无需第二次送检。
func bodyReviewContentType(contentType string, body []byte) string {
	mediaType := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = strings.TrimSpace(mediaType[:i])
	}
	if mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data" ||
		mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") ||
		mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml") {
		return ""
	}
	if json.Valid(body) {
		return "application/json"
	}
	return "application/x-www-form-urlencoded"
}

func isSafeRetryMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, site *cachedSite, ip, reqID string, countTraffic bool) {
	if p.requireSiteAuth(w, r, site) {
		p.forwardWithDynToken(w, r, site, ip, reqID, countTraffic, "")
	}
}

func (p *Proxy) requireSiteAuth(w http.ResponseWriter, r *http.Request, site *cachedSite) bool {
	if site.AuthUser == "" {
		return true
	}
	if user, pass, ok := r.BasicAuth(); ok && subtle.ConstantTimeCompare([]byte(user), []byte(site.AuthUser)) == 1 {
		if passOK, _ := store.VerifyPass(pass, site.AuthPass); passOK {
			return true
		}
	}
	if sw, ok := w.(*statusWriter); ok {
		sw.diagnostic.setWAFDecision("rejected", "未通过站点身份认证", "site_auth", 0)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="NiuB WAF Authentication"`)
	http.Error(w, "401 Unauthorized - NiuB WAF 身份认证", http.StatusUnauthorized)
	p.Store.AddTraffic(site.ID, false, 0)
	return false
}

func (p *Proxy) forwardWithDynToken(w http.ResponseWriter, r *http.Request, site *cachedSite, ip, reqID string, countTraffic bool, nextDynToken string) {
	if r.Context().Err() != nil {
		return
	}
	sw, _ := w.(*statusWriter)
	transport := p.upstreamTransport
	if transport == nil {
		transport = upstreamTransport
	}
	needResp := site.RespDetect && site.Enabled
	needDyn := site.DynamicMode != "" && site.DynamicMode != "off" && site.Enabled
	var hdr http.Header
	if needResp {
		hdr = r.Header.Clone()
		hdr.Set("Host", r.Host)
	}
	attempts := 1
	if isSafeRetryMethod(r.Method) {
		attempts = len(site.targets)
	}
	for i := 0; i < attempts; i++ {
		t := site.pick()
		if t == nil {
			break
		}
		if err := t.acquire(r.Context()); err != nil {
			if errors.Is(err, errUpstreamBusy) {
				p.writeUpstreamBusy(w, site.ID, nextDynToken, countTraffic, "origin_queue")
			}
			return
		}
		var respBlocked bool
		var responseBlock engine.Result
		var upstreamErr error
		rp := &httputil.ReverseProxy{
			Transport:  transport,
			BufferPool: &responseBuffers,
			Rewrite: func(pr *httputil.ProxyRequest) {
				// 保留原有上游路由行为：仅替换 scheme/host，不拼接上游路径。
				pr.Out.URL.Scheme = t.u.Scheme
				pr.Out.URL.Host = t.dialAddress
				if pr.Out.URL.Host == "" {
					pr.Out.URL.Host = t.u.Host
				}
				pr.Out.Host = t.u.Host

				// Rewrite 在逐跳头清理后执行。先清除所有客户端可伪造的转发身份，
				// 再用 WAF 已解析的客户端与入站协议重建，避免 Connection 指定这些头后被剥离。
				for _, h := range []string{
					"Forwarded", "X-Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
					"X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server",
					"X-Forwarded-Ssl", "X-Original-Forwarded-For", "X-Real-IP",
					requestDiagnosticHeader, ingressVerificationHeader,
				} {
					pr.Out.Header.Del(h)
				}
				filterProxyCookies(pr.Out.Header, "Cookie", true)
				if site.AuthUser != "" {
					pr.Out.Header.Del("Authorization")
				}
				proto := "http"
				if pr.In.TLS != nil {
					proto = "https"
				}
				pr.Out.Header.Set("X-Forwarded-For", ip)
				pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
				pr.Out.Header.Set("X-Forwarded-Proto", proto)
				pr.Out.Header.Set("X-Real-IP", ip)
				pr.Out.Header.Set(requestDiagnosticHeader, reqID)
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				// 客户端取消请求不会降低上游健康状态，也无需继续尝试。
				if r.Context().Err() != nil {
					return
				}
				// ReverseProxy clears the header map after forwarding a 1xx.
				w.Header().Set("Server", publicServerName)
				if errors.Is(err, errResponseInspectionBlocked) {
					msg := "响应内容检测：" + responseBlock.Msg
					WriteBlock(w, responseBlock.Status, RenderBlockPage(p.Store.GetSetting("block_page"), map[string]string{
						"REQ_ID": reqID, "REASON": msg, "CLIENT_IP": ip,
						"DOMAIN": site.Domain, "TIME": nowStr(), "RULE_ID": strconv.Itoa(responseBlock.RuleID),
					}))
					return
				}
				upstreamErr = err
				if !errors.Is(err, errDialQueueTimeout) && !errors.Is(err, errUpstreamBusy) {
					var timeout net.Error
					if errors.As(err, &timeout) && timeout.Timeout() {
						metrics.Default.IncUpstreamTimeout()
					}
					t.recordFailure(err)
				}
				if nextDynToken != "" {
					w.Header().Set("X-NiuB-Dyn-Token", nextDynToken)
					w.Header().Set("Cache-Control", "no-store")
				}
			},
		}
		rp.ModifyResponse = func(resp *http.Response) error {
			observeIngressOrigin(r, resp.StatusCode)
			if sw != nil {
				sw.diagnostic.UpstreamStatus = resp.StatusCode
			}
			resp.Header.Del(requestDiagnosticHeader)
			resp.Trailer.Del(requestDiagnosticHeader)
			filterProxyCookies(resp.Header, "Set-Cookie", false)
			// 续发令牌只由 WAF 生成，忽略上游伪造的同名响应头。
			resp.Header.Del("X-NiuB-Dyn-Token")
			if nextDynToken != "" {
				resp.Header.Set("X-NiuB-Dyn-Token", nextDynToken)
				resp.Header.Set("Cache-Control", "no-store")
			}
			if needResp {
				res, err := p.inspectUpstreamResponse(r, site, &engine.RequestInfo{
					ClientIP: ip, Method: r.Method, URL: r.URL.RequestURI(), Proto: r.Proto, Headers: hdr,
				}, resp)
				if res.Blocked {
					respBlocked = true
					responseBlock = res
					if sw != nil {
						sw.diagnostic.setWAFDecision("blocked", DiagnosticRuleReason("resp", res.Status), "resp", res.RuleID)
					}
					p.logAttack(site, ip, r, "resp", res.Msg, res.RuleID, res.Status, reqID)
					return errResponseInspectionBlocked
				}
				if err != nil {
					return err
				}
			}
			// Response inspection still sees the original upstream headers.
			// The proxy adds upstream headers to the existing response, so
			// remove all upstream Server values before copying (including 101).
			resp.Header.Del("Server")
			resp.Trailer.Del("Server")
			w.Header().Set("Server", publicServerName)
			if needDyn {
				return p.injectDynamicResponse(resp, r, ip, site.ID)
			}
			return nil
		}

		if i > 0 && r.GetBody != nil {
			r.Body, _ = r.GetBody()
		}
		if sw != nil {
			sw.diagnostic.UpstreamAttempted = true
			sw.diagnostic.UpstreamStatus = 0
		}
		rec := &countWriter{ResponseWriter: w}
		t.serve(rp, rec, r)
		// Trailers received at EOF may be added after ModifyResponse.
		w.Header().Del(http.TrailerPrefix + "Server")
		if r.Context().Err() != nil {
			return
		}
		if upstreamErr == nil {
			metrics.Default.AddResponseBytes(rec.n)
			if countTraffic {
				p.Store.AddTraffic(site.ID, respBlocked, rec.n)
			}
			return
		}
		if errors.Is(upstreamErr, errDialQueueTimeout) {
			p.writeUpstreamBusy(w, site.ID, nextDynToken, countTraffic, "dial_queue")
			return
		}
		if errors.Is(upstreamErr, errUpstreamBusy) {
			p.writeUpstreamBusy(w, site.ID, nextDynToken, countTraffic, "dial_capacity")
			return
		}
		// 请求体无法回卷时不再重试，避免向上游发送残缺请求
		// （ContentLength!=0 涵盖已知长度>0 与 chunked 未知长度-1 两种有体情形）
		if r.GetBody == nil && r.ContentLength != 0 {
			break
		}
	}
	if sw != nil {
		sw.diagnostic.Source, sw.diagnostic.Outcome = "upstream", "upstream_error"
		sw.diagnostic.Reason, sw.diagnostic.Module = "回源失败，WAF 未能转发有效的上游响应", "upstream_unavailable"
	}
	WriteBlock(w, http.StatusBadGateway, RenderBlockPage("", map[string]string{
		"REQ_ID": reqID, "REASON": "上游站点无法访问", "CLIENT_IP": ip,
		"DOMAIN": site.Domain, "TIME": nowStr(),
	}))
	if countTraffic {
		p.Store.AddTraffic(site.ID, false, 0)
	}
}

func (p *Proxy) writeUpstreamBusy(w http.ResponseWriter, siteID int64, nextDynToken string, countTraffic bool, reason string) {
	if sw, ok := w.(*statusWriter); ok {
		sw.diagnostic.Source, sw.diagnostic.Outcome = "upstream", "rejected"
		sw.diagnostic.Reason, sw.diagnostic.Module = "回源连接池繁忙，WAF 拒绝请求", reason
	}
	metrics.Default.IncOverloadRejected(reason)
	w.Header().Set("Retry-After", "1")
	if nextDynToken != "" {
		w.Header().Set("X-NiuB-Dyn-Token", nextDynToken)
		w.Header().Set("Cache-Control", "no-store")
	}
	http.Error(w, "上游连接池繁忙，请稍后重试", http.StatusServiceUnavailable)
	if countTraffic {
		p.Store.AddTraffic(siteID, false, 0)
	}
}

func filterProxyCookies(h http.Header, header string, request bool) {
	values := h.Values(header)
	if len(values) == 0 {
		return
	}
	h.Del(header)
	for _, value := range values {
		if !request {
			name, _, _ := strings.Cut(value, "=")
			if !isProxyCookie(strings.TrimSpace(name)) {
				h.Add(header, value)
			}
			continue
		}
		var cookies []string
		for _, cookie := range strings.Split(value, ";") {
			name, _, _ := strings.Cut(cookie, "=")
			if !isProxyCookie(strings.TrimSpace(name)) {
				cookies = append(cookies, strings.TrimSpace(cookie))
			}
		}
		if len(cookies) > 0 {
			h.Add(header, strings.Join(cookies, "; "))
		}
	}
}

func isProxyCookie(name string) bool {
	return name == "niub_admin" || name == "niub_pass" || strings.HasPrefix(name, "niub_pass_")
}

type countWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		// Informational responses bypass ReverseProxy.ModifyResponse.
		c.Header().Set("Server", publicServerName)
	}
	c.ResponseWriter.WriteHeader(code)
}

// statusWriter 记录响应状态码供流量分析聚合（未显式 WriteHeader 视为 200）
type statusWriter struct {
	http.ResponseWriter
	code       int
	diagnostic RequestDiagnostic
}

func (s *statusWriter) WriteHeader(code int) {
	if s.code != 0 {
		return // 与 net/http 一致：重复 WriteHeader 忽略，避免 superfluous 日志
	}
	if s.diagnostic.ReqID != "" {
		s.Header().Set(requestDiagnosticHeader, s.diagnostic.ReqID)
	}
	// 103 等临时状态之后仍需记录并发送真正响应。
	if code >= 200 || code == http.StatusSwitchingProtocols {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		if s.diagnostic.ReqID != "" {
			s.Header().Set(requestDiagnosticHeader, s.diagnostic.ReqID)
		}
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
	observation := status == http.StatusOK
	if !observation {
		metrics.Default.IncAttack(action)
	}
	geo := p.Geo.CityInfo(ip)
	lat, lon := geo.Coordinates()
	logURL := r.URL.EscapedPath()
	if !observation {
		p.Ana.Event(EvStat{IP: ip, Action: action, Msg: msg, RuleID: ruleID, Status: status, Country: geo.Country, City: geo.City, Lat: lat, Lon: lon, URL: logURL, Domain: site.Domain})
	}
	l := &store.AttackLog{
		SiteID: site.ID, Domain: site.Domain, ClientIP: ip, Country: geo.Country,
		Method: r.Method, URL: logURL, QueryRedacted: r.URL.RawQuery != "", Action: action,
		RuleID: ruleID, Msg: msg, Severity: severityOf(action), Status: status, ReqID: reqID,
	}
	if err := p.Store.LogAttack(l); err != nil {
		log.Printf("写入攻击日志失败: %v", err)
	}
	eventType := "attack"
	if observation {
		eventType = "observation"
	}
	p.Hub.Broadcast(map[string]any{
		"type": eventType, "ts": nowStr(), "domain": site.Domain, "ip": ip,
		"country": geo.Country, "city": geo.City, "method": r.Method, "url": l.URL,
		"action": action, "msg": msg, "status": status, "lat": lat, "lon": lon, "req_id": reqID,
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
