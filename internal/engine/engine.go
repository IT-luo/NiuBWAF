package engine

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	crs "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type Result struct {
	Blocked  bool
	Status   int
	RuleID   int
	Msg      string
	Severity string
}

type Engine struct {
	mu        sync.RWMutex
	wafs      map[string]coraza.WAF
	variants  map[string]coraza.WAF
	extraCT   []string     // 追加允许的请求体 Content-Type（CRS 920420 白名单）
	scanLimit atomic.Int64 // 请求体送检上限（字节）
	matched   sync.Map
}

// defaultScanLimit 请求体送检上限默认值。CRS 正则扫描成本约 4.5µs/字节（2MB 请求体
// 需 ~9 秒 CPU），必须设上限，否则大体积请求可被用作低成本 CPU 拒绝服务。
const defaultScanLimit = 128 << 10

// maxScanLimit 送检上限的硬上限，与 SecRequestBodyInMemoryLimit 一致，
// 确保请求体始终留在内存、不落临时文件。
const maxScanLimit = 1 << 20

// truncatedExclusions 请求体被截断送检时豁免的规则：Coraza 的 multipart/urlencoded/JSON
// 解析器看到不完整结构会置位 MULTIPART_STRICT_ERROR / REQBODY_ERROR，而这两条规则直接
// deny 400，会让所有超过送检上限的正常上传被误拦。截断是我们主动做的（后端仍收到完整
// 请求体），因此只豁免这两条“解析完整性”规则，内容检测规则照常作用于已送检的前缀。
var truncatedExclusions = []Exclusion{{RuleID: 200002}, {RuleID: 200003}}

// SetScanLimit 设置请求体送检上限（字节），非正值回落默认值
func (e *Engine) SetScanLimit(n int) {
	if n <= 0 {
		n = defaultScanLimit
	}
	if n > maxScanLimit {
		n = maxScanLimit
	}
	e.scanLimit.Store(int64(n))
}

func (e *Engine) ScanLimit() int { return int(e.scanLimit.Load()) }

// scanBody 按送检上限截断请求体，返回送检内容与是否发生截断
func (e *Engine) scanBody(body []byte) ([]byte, bool) {
	lim := int(e.scanLimit.Load())
	if lim <= 0 || len(body) <= lim {
		return body, false
	}
	return body[:lim], true
}

// crsContentTypes CRS4 默认允许的请求体 Content-Type，追加项在此基础上扩展
var crsContentTypes = []string{
	"application/x-www-form-urlencoded", "multipart/form-data", "multipart/related",
	"text/xml", "application/xml", "application/soap+xml", "application/json",
	"application/cloudevents+json", "application/cloudevents-batch+json",
}

// ParseContentTypes 解析逗号分隔的追加类型，丢弃形状非法的项并去重
func ParseContentTypes(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range crsContentTypes {
		seen[t] = true
	}
	for _, raw := range strings.Split(s, ",") {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" || seen[t] || !ValidContentType(t) {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ValidContentType 校验 MIME 类型形状（type/subtype，仅 token 字符）。
// 该值会被拼进 SecAction 指令，因此必须拒绝空格与引号等元字符。
func ValidContentType(t string) bool {
	if len(t) == 0 || len(t) > 128 {
		return false
	}
	i := strings.Index(t, "/")
	if i <= 0 || i == len(t)-1 || strings.Contains(t[i+1:], "/") {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_', r == '+', r == '/':
		default:
			return false
		}
	}
	return true
}

// SetContentTypes 更新追加允许的请求体类型；内容未变化时直接返回，避免重建引擎
func (e *Engine) SetContentTypes(extra []string) error {
	e.mu.RLock()
	same := len(extra) == len(e.extraCT)
	if same {
		for i := range extra {
			if extra[i] != e.extraCT[i] {
				same = false
				break
			}
		}
	}
	e.mu.RUnlock()
	if same {
		return nil
	}
	wafs := map[string]coraza.WAF{}
	for _, mode := range []string{"balanced", "strict"} {
		w, err := e.buildWAF(mode, nil, extra)
		if err != nil {
			return fmt.Errorf("构建 %s 模式引擎失败: %w", mode, err)
		}
		wafs[mode] = w
	}
	e.mu.Lock()
	e.wafs = wafs
	e.variants = map[string]coraza.WAF{}
	e.extraCT = append([]string(nil), extra...)
	e.mu.Unlock()
	return nil
}

type Exclusion struct {
	RuleID    int
	URLPrefix string
	Param     string
}

func New() (*Engine, error) {
	e := &Engine{wafs: map[string]coraza.WAF{}, variants: map[string]coraza.WAF{}}
	e.scanLimit.Store(defaultScanLimit)
	for _, mode := range []string{"balanced", "strict"} {
		w, err := e.buildWAF(mode, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("构建 %s 模式引擎失败: %w", mode, err)
		}
		e.wafs[mode] = w
	}
	return e, nil
}

func (e *Engine) buildWAF(mode string, excl []Exclusion, extraCT []string) (coraza.WAF, error) {
	pl := 1
	if mode == "strict" {
		pl = 2
	}
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 10485760
SecRequestBodyInMemoryLimit 1048576
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess On
SecResponseBodyLimit 1048576
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecAuditEngine Off
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
%s%sSecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY "(?:;|\||\x60|&&|\$\()\s*(?:cat|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php|chmod|chown|rm|dd|mkfifo|telnet)\b" "id:100001,phase:2,block,t:none,t:urlDecodeUni,t:lowercase,setvar:tx.anomaly_score=+5,setvar:tx.inbound_anomaly_score_pl1=+5,setvar:tx.inbound_anomaly_score_pl2=+5,msg:'牛B WAF: Unix 命令注入尝试',logdata:'Matched Data: %%{MATCHED_VAR} found within %%{MATCHED_VAR_NAME}',severity:'CRITICAL'"
Include @owasp_crs/*.conf
`, pl, pl, contentTypeDirectives(extraCT), exclusionDirectives(excl))
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(crs.FS).
		WithErrorCallback(func(mr types.MatchedRule) {
			id := mr.TransactionID()
			v, _ := e.matched.LoadOrStore(id, &[]types.MatchedRule{})
			lst := v.(*[]types.MatchedRule)
			*lst = append(*lst, mr)
		}).
		WithDirectives(directives))
}

// 豁免指令置于 CRS 之前，确保 phase:1 的规则也能被移除
func exclusionDirectives(excl []Exclusion) string {
	var b strings.Builder
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	for i, x := range excl {
		ctl := fmt.Sprintf("ctl:ruleRemoveById=%d", x.RuleID)
		if x.Param != "" {
			ctl = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;ARGS:%s", x.RuleID, x.Param)
		}
		if x.URLPrefix != "" {
			fmt.Fprintf(&b, "SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,nolog,t:none,%s\"\n", esc.Replace(x.URLPrefix), 100100+i, ctl)
		} else {
			fmt.Fprintf(&b, "SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", 100100+i, ctl)
		}
	}
	return b.String()
}

// contentTypeDirectives 在 CRS 初始化前覆盖 tx.allowed_request_content_type（规则 920420 的白名单）。
// CRS 仅在该变量为空时写入默认值，因此必须带上全部默认类型再追加自定义项。
func contentTypeDirectives(extra []string) string {
	if len(extra) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`SecAction "id:900002,phase:1,nolog,pass,t:none,setvar:'tx.allowed_request_content_type=`)
	for _, t := range crsContentTypes {
		fmt.Fprintf(&b, "|%s| ", t)
	}
	for _, t := range extra {
		fmt.Fprintf(&b, "|%s| ", t)
	}
	b.WriteString(`'"` + "\n")
	return b.String()
}

func (e *Engine) wafFor(mode string, excl []Exclusion) coraza.WAF {
	if mode != "strict" {
		mode = "balanced"
	}
	e.mu.RLock()
	extraCT := e.extraCT
	e.mu.RUnlock()
	if len(excl) == 0 {
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.wafs[mode]
	}
	parts := make([]string, len(excl))
	for i, x := range excl {
		parts[i] = fmt.Sprintf("%d|%s|%s", x.RuleID, x.URLPrefix, x.Param)
	}
	sort.Strings(parts)
	key := mode + "#" + strings.Join(parts, ";")
	e.mu.RLock()
	w, ok := e.variants[key]
	e.mu.RUnlock()
	if ok {
		return w
	}
	w, err := e.buildWAF(mode, excl, extraCT)
	if err != nil {
		log.Printf("构建豁免引擎失败，回退基础引擎: %v", err)
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.wafs[mode]
	}
	e.mu.Lock()
	if len(e.variants) > 128 {
		e.variants = map[string]coraza.WAF{}
	}
	e.variants[key] = w
	e.mu.Unlock()
	return w
}

func (e *Engine) takeMatched(txID string) []types.MatchedRule {
	if v, ok := e.matched.LoadAndDelete(txID); ok {
		return *v.(*[]types.MatchedRule)
	}
	return nil
}

type RequestInfo struct {
	ClientIP string
	ServerIP string
	Method   string
	URL      string
	Proto    string
	Headers  http.Header
	Body     []byte
}

func (e *Engine) Detect(mode string, excl []Exclusion, r *RequestInfo) Result {
	body, truncated := e.scanBody(r.Body)
	if truncated {
		excl = withTruncationExclusions(excl)
	}
	w := e.wafFor(mode, excl)

	tx := w.NewTransaction()
	defer tx.Close()
	txID := tx.ID()

	tx.ProcessConnection(r.ClientIP, 0, r.ServerIP, 0)
	tx.ProcessURI(r.URL, r.Method, r.Proto)
	for k, vv := range r.Headers {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return resultFrom(it, e.takeMatched(txID))
	}
	if len(body) > 0 {
		if it, _, err := tx.WriteRequestBody(body); err == nil && it != nil {
			return resultFrom(it, e.takeMatched(txID))
		}
	}
	if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
		return resultFrom(it, e.takeMatched(txID))
	}
	e.takeMatched(txID)
	return Result{}
}

// withTruncationExclusions 复制豁免列表（调用方切片跨请求共享，不可原地追加）
func withTruncationExclusions(excl []Exclusion) []Exclusion {
	out := make([]Exclusion, 0, len(excl)+len(truncatedExclusions))
	out = append(out, excl...)
	return append(out, truncatedExclusions...)
}

func (e *Engine) DetectResponse(mode string, excl []Exclusion, req *RequestInfo, status int, headers http.Header, body []byte) Result {
	w := e.wafFor(mode, excl)
	tx := w.NewTransaction()
	defer tx.Close()
	txID := tx.ID()

	tx.ProcessConnection(req.ClientIP, 0, req.ServerIP, 0)
	tx.ProcessURI(req.URL, req.Method, req.Proto)
	for k, vv := range req.Headers {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.ProcessRequestHeaders()
	reqBody, _ := e.scanBody(req.Body)
	if len(reqBody) > 0 {
		tx.WriteRequestBody(reqBody)
		tx.ProcessRequestBody()
	}
	for k, vv := range headers {
		for _, v := range vv {
			tx.AddResponseHeader(k, v)
		}
	}
	if it := tx.ProcessResponseHeaders(status, req.Proto); it != nil {
		return resultFrom(it, e.takeMatched(txID))
	}
	respBody, _ := e.scanBody(body)
	if len(respBody) > 0 {
		if it, _, err := tx.WriteResponseBody(respBody); err == nil && it != nil {
			return resultFrom(it, e.takeMatched(txID))
		}
	}
	if it, err := tx.ProcessResponseBody(); err == nil && it != nil {
		return resultFrom(it, e.takeMatched(txID))
	}
	e.takeMatched(txID)
	return Result{}
}

func resultFrom(it *types.Interruption, matched []types.MatchedRule) Result {
	res := Result{Blocked: true, Status: it.Status}
	if res.Status == 0 {
		res.Status = http.StatusForbidden
	}
	res.RuleID = it.RuleID
	// 优先报告实际命中的检测规则（而非 949/959 汇总拦截规则），便于误报定位与豁免
	pick := -1
	for i, mr := range matched {
		id := mr.Rule().ID()
		if id == 949110 || id == 949120 || id == 959100 {
			continue
		}
		if pick == -1 {
			pick = i
		}
		if mr.Rule().Severity().String() == "CRITICAL" {
			pick = i
			break
		}
	}
	if pick >= 0 {
		mr := matched[pick]
		res.RuleID = mr.Rule().ID()
		res.Msg = mr.Message()
		res.Severity = mr.Rule().Severity().String()
	}
	if res.Msg == "" {
		for _, mr := range matched {
			if mr.Rule().ID() == it.RuleID {
				res.Msg = mr.Message()
				res.Severity = mr.Rule().Severity().String()
				break
			}
		}
	}
	if res.Msg == "" {
		res.Msg = "命中防护规则"
	}
	return res
}

func ReadBodyLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

// ClientIP 解析真实客户端 IP。仅当直连对端位于可信代理网段时才采信 X-Forwarded-For /
// X-Real-IP，并从右向左跳过可信代理取第一个不可信 IP；否则一律使用 RemoteAddr，
// 杜绝客户端伪造 XFF 绕过黑名单/白名单/信誉/地域策略。trusted 为空即安全默认（忽略转发头）。
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	remote := net.ParseIP(host)
	if remote == nil {
		return host
	}
	if !ipInNets(remote, trusted) {
		return remote.String()
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			cand := net.ParseIP(strings.TrimSpace(parts[i]))
			if cand != nil && !ipInNets(cand, trusted) {
				return cand.String()
			}
		}
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		if cand := net.ParseIP(strings.TrimSpace(xr)); cand != nil {
			return cand.String()
		}
	}
	return remote.String()
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies 解析逗号分隔的可信代理列表（CIDR 或单 IP），单 IP 自动补 /32 或 /128
func ParseTrustedProxies(s string) []*net.IPNet {
	var nets []*net.IPNet
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			if _, n, err := net.ParseCIDR(raw); err == nil {
				nets = append(nets, n)
			}
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}
