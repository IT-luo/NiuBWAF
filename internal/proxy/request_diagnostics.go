package proxy

import (
	"net/http"
	"sync"
	"time"
)

const requestDiagnosticHeader = "X-NiuB-WAF-Req-ID"

const (
	diagnosticShardSize = 128
	diagnosticRetention = 15 * time.Minute
)

// DiagnosticObservation identifies a non-blocking rule match without retaining payload data.
type DiagnosticObservation struct {
	Module string `json:"module"`
	RuleID int    `json:"rule_id,omitempty"`
}

// RequestDiagnostic describes a completed request. Status is the outward response,
// while UpstreamStatus is what the origin returned before response filtering.
type RequestDiagnostic struct {
	ReqID             string                  `json:"req_id"`
	TS                time.Time               `json:"ts"`
	Domain            string                  `json:"domain,omitempty"`
	Method            string                  `json:"method,omitempty"`
	Status            int                     `json:"status,omitempty"`
	Source            string                  `json:"source"`
	Outcome           string                  `json:"outcome"`
	Reason            string                  `json:"reason"`
	Module            string                  `json:"module,omitempty"`
	RuleID            int                     `json:"rule_id,omitempty"`
	Observations      []DiagnosticObservation `json:"observations,omitempty"`
	UpstreamAttempted bool                    `json:"upstream_attempted,omitempty"`
	UpstreamStatus    int                     `json:"upstream_status,omitempty"`
	BodyLimitBytes    int64                   `json:"body_limit_bytes,omitempty"`
	BodyLimitKind     string                  `json:"body_limit_kind,omitempty"`
	BodyBytes         int64                   `json:"body_bytes,omitempty"`
	BodyBytesKind     string                  `json:"body_bytes_kind,omitempty"`
	Historical        bool                    `json:"historical,omitempty"`
}

func diagnosticMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	default:
		return "其他"
	}
}

// DiagnosticRuleReason only uses engine decision metadata. Some rule messages
// contain matched data, so they are deliberately excluded from diagnostics.
func DiagnosticRuleReason(module string, status int) string {
	switch module {
	case "waf":
		switch status {
		case http.StatusRequestEntityTooLarge:
			return "请求体超过完整检测上限"
		case http.StatusUnsupportedMediaType:
			return "请求体编码不受支持"
		case http.StatusBadRequest:
			return "请求格式或请求体读取未通过检查"
		default:
			return "命中 WAF 请求检测规则"
		}
	case "resp":
		return "命中 WAF 响应内容检测规则"
	case "blacklist":
		return "客户端 IP 命中黑名单"
	case "reputation":
		return "客户端 IP 命中信誉封禁"
	case "geo":
		return "命中地理访问控制规则"
	case "custom":
		return "命中自定义规则"
	case "bot":
		return "命中 Bot 防护规则"
	case "cc":
		return "超过站点或接口的访问频率限制"
	case "api_schema":
		return "请求未通过 API 契约校验"
	case "semantic":
		return "命中语义检测规则"
	case "dynamic":
		return "未通过动态令牌检查"
	default:
		return "命中防护规则"
	}
}

func (d *RequestDiagnostic) setWAFDecision(outcome, reason, module string, ruleID int) {
	d.Source = "waf"
	d.Outcome = outcome
	d.Reason = reason
	d.Module = module
	d.RuleID = ruleID
}

func (d *RequestDiagnostic) observe(module string, ruleID int) {
	if len(d.Observations) < 6 {
		d.Observations = append(d.Observations, DiagnosticObservation{Module: module, RuleID: ruleID})
	}
}

func (d *RequestDiagnostic) complete(status int) {
	d.Status = status
	if d.Outcome != "" {
		return
	}
	if status == 0 {
		d.Source, d.Outcome, d.Reason = "unknown", "unknown", "请求未生成最终 HTTP 响应"
		return
	}
	if d.UpstreamStatus != 0 {
		d.Source = "origin"
		if d.UpstreamStatus >= 400 {
			d.Outcome, d.Reason = "origin_error", "错误状态由上游返回，WAF 已转发请求"
		} else if len(d.Observations) > 0 {
			d.Outcome, d.Reason = "observed", "有规则以观察模式命中，请求已转发"
		} else {
			d.Outcome, d.Reason = "allowed", "WAF 已转发请求"
		}
		return
	}
	d.Source, d.Outcome, d.Reason = "unknown", "unknown", "未记录最终处置来源"
}

type diagnosticRing struct {
	entries []RequestDiagnostic
	byID    map[string]int
	next    int
}

func (r *diagnosticRing) add(d RequestDiagnostic) {
	if r.byID == nil {
		r.byID = make(map[string]int, diagnosticShardSize)
		r.entries = make([]RequestDiagnostic, diagnosticShardSize)
	}
	if i, ok := r.byID[d.ReqID]; ok {
		r.entries[i] = d
		return
	}
	delete(r.byID, r.entries[r.next].ReqID)
	r.entries[r.next] = d
	r.byID[d.ReqID] = r.next
	r.next = (r.next + 1) % len(r.entries)
}

func (r *diagnosticRing) find(id string, after time.Time) (RequestDiagnostic, bool) {
	if i, ok := r.byID[id]; ok && !r.entries[i].TS.Before(after) {
		return r.entries[i], true
	}
	return RequestDiagnostic{}, false
}

type diagnosticShard struct {
	mu      sync.Mutex
	regular diagnosticRing
	events  diagnosticRing
}

type diagnosticCache [16]diagnosticShard

func (c *diagnosticCache) shard(id string) *diagnosticShard {
	if id == "" {
		return &c[0]
	}
	ch := id[0]
	if ch >= '0' && ch <= '9' {
		return &c[ch-'0']
	}
	if ch >= 'a' && ch <= 'f' {
		return &c[ch-'a'+10]
	}
	return &c[0]
}

func (c *diagnosticCache) record(d RequestDiagnostic) {
	s := c.shard(d.ReqID)
	s.mu.Lock()
	if d.Status >= 400 || len(d.Observations) > 0 {
		s.events.add(d)
	} else {
		s.regular.add(d)
	}
	s.mu.Unlock()
}

// FindRequestDiagnostic searches the recent in-memory window for a completed request.
func (p *Proxy) FindRequestDiagnostic(id string) (RequestDiagnostic, bool) {
	s := p.diagnostics.shard(id)
	after := time.Now().Add(-diagnosticRetention)
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.events.find(id, after); ok {
		return d, true
	}
	return s.regular.find(id, after)
}
