package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"niubwaf/internal/store"
)

const (
	ingressVerificationHeader = "X-NiuB-Ingress-Verify"
	ingressChallengeLifetime  = 5 * time.Minute
	ingressResultLifetime     = 24 * time.Hour
	maxIngressVerifications   = 512
)

var (
	ErrIngressSiteUnavailable = errors.New("站点尚未启用或未加载到当前代理节点")
	ingressHostnamePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)
	ingressPathPattern        = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

type IngressVerificationOptions struct {
	Scheme string `json:"scheme"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	Source string `json:"source"`
}

type SiteIngressStatus struct {
	EntryURL  string              `json:"entry_url"`
	Source    string              `json:"source"`
	CreatedAt time.Time           `json:"created_at"`
	ExpiresAt time.Time           `json:"expires_at"`
	Pass      *IngressProbeResult `json:"pass,omitempty"`
	Block     *IngressProbeResult `json:"block,omitempty"`
	Verified  bool                `json:"verified"`
}

type IngressProbeResult struct {
	ObservedAt   time.Time `json:"observed_at"`
	RequestID    string    `json:"request_id"`
	Status       int       `json:"status"`
	OriginStatus int       `json:"origin_status,omitempty"`
	Matched      bool      `json:"matched"`
	ClientIP     string    `json:"client_ip"`
	Scheme       string    `json:"scheme"`
	Port         int       `json:"port"`
	Reason       string    `json:"reason"`
}

type StartedIngressVerification struct {
	Status     SiteIngressStatus `json:"status"`
	Header     string            `json:"header"`
	PassToken  string            `json:"pass_token"`
	BlockToken string            `json:"block_token"`
}

type ingressVerifier struct {
	mu       sync.Mutex
	sessions map[int64]*ingressSession
}

type ingressSession struct {
	status     SiteIngressStatus
	domain     string
	upstream   string
	path       string
	scheme     string
	port       int
	passToken  [sha256.Size]byte
	blockToken [sha256.Size]byte
}

type ingressProbe struct {
	verifier     *ingressVerifier
	session      *ingressSession
	siteID       int64
	block        bool
	originStatus int
	result       IngressProbeResult
}

type ingressProbeKey struct{}

func ingressEntryURL(domain string, options *IngressVerificationOptions) (string, error) {
	if len(domain) > 253 || !ingressHostnamePattern.MatchString(domain) || strings.Contains(domain, "..") {
		return "", errors.New("接入验收需要有效的站点域名")
	}
	if options.Scheme != "http" && options.Scheme != "https" {
		return "", errors.New("验收协议必须为 HTTP 或 HTTPS")
	}
	if options.Port < 0 || options.Port > 65535 {
		return "", errors.New("验收端口无效")
	}
	if options.Source != "external" && options.Source != "local" {
		return "", errors.New("请选择验证请求的发起位置")
	}
	if options.Path == "" {
		options.Path = "/"
	}
	entryPath := options.Path
	if len(entryPath) > 256 || !ingressPathPattern.MatchString(entryPath) ||
		strings.Contains(entryPath, "//") ||
		(entryPath != "/" && path.Clean(entryPath) != strings.TrimSuffix(entryPath, "/")) ||
		strings.HasPrefix(entryPath, "/__niubwaf/") {
		return "", errors.New("验收路径必须为普通绝对路径，不含转义、参数或保留路径")
	}
	authority := domain
	if options.Port != 0 {
		authority = net.JoinHostPort(domain, strconv.Itoa(options.Port))
	}
	return options.Scheme + "://" + authority + entryPath, nil
}

func (p *Proxy) ingressSite(siteID int64, domain string) *cachedSite {
	p.mu.RLock()
	site := p.sites[domain]
	p.mu.RUnlock()
	if site == nil || site.ID != siteID {
		return nil
	}
	return site
}

func (p *Proxy) StartIngressVerification(siteID int64, domain string, options IngressVerificationOptions) (*StartedIngressVerification, error) {
	domain = strings.ToLower(domain)
	site := p.ingressSite(siteID, domain)
	if site == nil || !site.Enabled {
		return nil, ErrIngressSiteUnavailable
	}
	entryURL, err := ingressEntryURL(domain, &options)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	passToken, blockToken := store.RandToken(), store.RandToken()
	status := SiteIngressStatus{
		EntryURL: entryURL, Source: options.Source, CreatedAt: now, ExpiresAt: now.Add(ingressChallengeLifetime),
	}
	port := options.Port
	if port == 0 {
		port = ingressDefaultPort(options.Scheme)
	}
	session := &ingressSession{
		status: status, domain: domain, upstream: site.Upstream, path: options.Path, scheme: options.Scheme, port: port,
		passToken: sha256.Sum256([]byte(passToken)), blockToken: sha256.Sum256([]byte(blockToken)),
	}
	p.ingress.mu.Lock()
	defer p.ingress.mu.Unlock()
	if p.ingress.sessions == nil {
		p.ingress.sessions = make(map[int64]*ingressSession)
	}
	for id, item := range p.ingress.sessions {
		if !now.Before(item.status.CreatedAt.Add(ingressResultLifetime)) {
			delete(p.ingress.sessions, id)
		}
	}
	if len(p.ingress.sessions) >= maxIngressVerifications && p.ingress.sessions[siteID] == nil {
		var oldestID int64
		oldest := now
		for id, item := range p.ingress.sessions {
			if oldestID == 0 || item.status.CreatedAt.Before(oldest) {
				oldestID, oldest = id, item.status.CreatedAt
			}
		}
		delete(p.ingress.sessions, oldestID)
	}
	p.ingress.sessions[siteID] = session
	return &StartedIngressVerification{Status: status, Header: ingressVerificationHeader, PassToken: passToken, BlockToken: blockToken}, nil
}

func (p *Proxy) SiteIngressStatus(siteID int64, domain string) *SiteIngressStatus {
	domain = strings.ToLower(domain)
	site := p.ingressSite(siteID, domain)
	if site == nil || !site.Enabled {
		return nil
	}
	p.ingress.mu.Lock()
	defer p.ingress.mu.Unlock()
	session := p.ingress.sessions[siteID]
	if session == nil || session.domain != domain || session.upstream != site.Upstream ||
		!time.Now().Before(session.status.CreatedAt.Add(ingressResultLifetime)) {
		return nil
	}
	status := session.status
	return &status
}

// Only the exact, one-use marker opts a bodyless GET into verification.
// Strip the reserved header before normal rule evaluation and proxying.
func (p *Proxy) claimIngressProbe(r *http.Request, site *cachedSite, ip, reqID string, bypass bool) *ingressProbe {
	values := r.Header.Values(ingressVerificationHeader)
	r.Header.Del(ingressVerificationHeader)
	if !site.Enabled || bypass || r.Method != http.MethodGet || r.ContentLength != 0 ||
		len(r.TransferEncoding) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		len(values) != 1 || len(values[0]) != 48 {
		return nil
	}
	host, suppliedPort, err := net.SplitHostPort(r.Host)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	port := ingressDefaultPort(scheme)
	if err != nil {
		host = r.Host
	} else if port, err = strconv.Atoi(suppliedPort); err != nil {
		return nil
	}
	domain := strings.ToLower(host)
	digest := sha256.Sum256([]byte(values[0]))
	now := time.Now().UTC()
	p.ingress.mu.Lock()
	defer p.ingress.mu.Unlock()
	session := p.ingress.sessions[site.ID]
	if session == nil || !now.Before(session.status.ExpiresAt) || session.domain != domain ||
		session.upstream != site.Upstream || session.path != r.URL.EscapedPath() ||
		session.scheme != scheme || session.port != port {
		return nil
	}
	var empty [sha256.Size]byte
	block := subtle.ConstantTimeCompare(digest[:], session.blockToken[:]) == 1
	switch {
	case block:
		session.blockToken = empty
	case subtle.ConstantTimeCompare(digest[:], session.passToken[:]) == 1:
		session.passToken = empty
	default:
		return nil
	}
	result := IngressProbeResult{ObservedAt: now, RequestID: reqID, ClientIP: ip, Scheme: scheme, Port: port}
	return &ingressProbe{verifier: &p.ingress, session: session, siteID: site.ID, block: block, result: result}
}

func ingressDefaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func (probe *ingressProbe) attach(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ingressProbeKey{}, probe))
}

func observeIngressOrigin(r *http.Request, status int) {
	if probe, _ := r.Context().Value(ingressProbeKey{}).(*ingressProbe); probe != nil {
		probe.originStatus = status
	}
}

func (probe *ingressProbe) finish(status int) {
	probe.result.Status = status
	probe.result.OriginStatus = probe.originStatus
	switch {
	case probe.block && status == http.StatusForbidden:
		probe.result.Matched, probe.result.Reason = true, "verification_blocked"
	case status == 0:
		probe.result.Reason = "request_interrupted"
	case probe.originStatus == 0:
		probe.result.Reason = "no_origin_response"
	case status != probe.originStatus:
		probe.result.Reason = "response_status_changed"
	case status < 200 || status >= 400:
		probe.result.Reason = "origin_error_status"
	default:
		probe.result.Matched, probe.result.Reason = true, "origin_reached"
	}
	probe.verifier.mu.Lock()
	defer probe.verifier.mu.Unlock()
	if probe.verifier.sessions[probe.siteID] != probe.session {
		return
	}
	current := &probe.session.status
	if probe.block {
		current.Block = &probe.result
	} else {
		current.Pass = &probe.result
	}
	current.Verified = current.Pass != nil && current.Pass.Matched && current.Block != nil && current.Block.Matched
}

func writeIngressBlock(w http.ResponseWriter, reqID, ip, host string) {
	WriteBlock(w, http.StatusForbidden, RenderBlockPage("", map[string]string{
		"REQ_ID": reqID, "REASON": "站点接入验收：验证请求已被拦截",
		"CLIENT_IP": ip, "DOMAIN": host, "TIME": nowStr(),
	}))
}

// initIngressTraffic is called under p.mu before publishing reloaded sites.
func (p *Proxy) initIngressTraffic(next map[string]*cachedSite) {
	for host, site := range next {
		if old := p.sites[host]; old != nil && old.ID == site.ID && old.ingressSeen != nil {
			site.ingressSeen = old.ingressSeen
		} else {
			site.ingressSeen = &atomic.Int64{}
		}
	}
}

func (s *cachedSite) noteIngressTraffic(start time.Time, r *http.Request) {
	if s.ingressSeen == nil || r.UserAgent() == healthCheckUserAgent || len(r.Header.Values(ingressVerificationHeader)) != 0 {
		return
	}
	stamp := start.Unix()
	for previous := s.ingressSeen.Load(); stamp > previous; previous = s.ingressSeen.Load() {
		if s.ingressSeen.CompareAndSwap(previous, stamp) {
			return
		}
	}
}

func (p *Proxy) SiteTrafficObservedAt(siteID int64, domain string) *time.Time {
	site := p.ingressSite(siteID, strings.ToLower(domain))
	if site == nil || site.ingressSeen == nil {
		return nil
	}
	if stamp := site.ingressSeen.Load(); stamp != 0 {
		observed := time.Unix(stamp, 0).UTC()
		return &observed
	}
	return nil
}
