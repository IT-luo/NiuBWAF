package engine

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	corazaConfig "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/lts/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
)

const CRSVersion = crs.Version

var ruleFiles = mergefs.Merge(corazaConfig.FS, crs.FS)

type Result struct {
	Blocked  bool
	LogOnly  bool // 命中但按策略仅记录不拦截（如 932235 语义复核未确认）
	Status   int
	RuleID   int
	Msg      string
	Severity string
}

type Engine struct {
	buildMu   sync.Mutex // 串行构建引擎及豁免变体，缓存命中无需持有
	mu        sync.RWMutex
	wafs      map[string]coraza.WAF
	variants  map[string]coraza.WAF
	extraCT   []string     // 追加允许的请求体 Content-Type（CRS 920420 白名单）
	scanLimit atomic.Int64 // 请求体送检上限（字节）
	matched   sync.Map
}

// defaultScanLimit 请求体送检上限默认值。CRS 正则扫描成本约 4.5µs/字节（实测 64KB
// 二进制体单请求 ~380ms），必须设上限，否则大体积请求可被用作低成本 CPU 拒绝服务；
// 16KB 已覆盖绝大多数攻击载荷位置；客户端 Content-Type 不用于跳过送检。
const defaultScanLimit = 16 << 10

// maxScanLimit 送检上限的硬上限，与 SecRequestBodyInMemoryLimit 一致，
// 确保请求体始终留在内存、不落临时文件。
const maxScanLimit = 1 << 20

// MaxUploadBodyMiB 仅用于管理员明确配置的上传接口。
const MaxUploadBodyMiB = 64

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
	e.buildMu.Lock()
	defer e.buildMu.Unlock()
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
		w, err := e.buildWAF(mode, nil, extra, maxScanLimit)
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
		w, err := e.buildWAF(mode, nil, nil, maxScanLimit)
		if err != nil {
			return nil, fmt.Errorf("构建 %s 模式引擎失败: %w", mode, err)
		}
		e.wafs[mode] = w
	}
	return e, nil
}

func (e *Engine) buildWAF(mode string, excl []Exclusion, extraCT []string, bodyLimit int) (coraza.WAF, error) {
	pl := 1
	if mode == "strict" {
		pl = 2
	}
	// 用下方同阶段的本地规则保留原有参数限额规则 ID。
	// 响应体扫描在代理层限长，给 Coraza 的阈值多留一字节，避免正好达到上限时被标为截断。
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
SecRuleRemoveById 200004 200005
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit 1048576
SecRequestBodyLimitAction Reject
SecArgumentsLimit 1000
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:100010,phase:1,t:none,deny,status:400,log,msg:'Request query argument limit exceeded'"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:100011,phase:2,t:none,deny,status:400,log,msg:'Request body argument limit exceeded'"
SecRule REQUEST_HEADERS:Content-Type "@rx ^[^/;[:blank:]]+/[^;[:blank:]]+[+]json[[:blank:]]*(?:;|$)" "id:100012,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "@rx ^[^/;[:blank:]]+/[^;[:blank:]]+[+]xml[[:blank:]]*(?:;|$)" "id:100013,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecResponseBodyAccess On
SecResponseBodyLimit %d
SecResponseBodyMimeType text/plain text/html text/xml application/xml application/json
SecAuditEngine Off
Include @crs-setup-lts.conf.example
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
SecAction "id:900003,phase:1,nolog,pass,t:none,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
%s%sSecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY "(?:;|\||\x60|&&|\$\()\s*(?:cat|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php|chmod|chown|rm|dd|mkfifo|telnet)(?:[\s/\\;|&]|$)" "id:100001,phase:2,block,t:none,t:urlDecodeUni,t:lowercase,setvar:tx.anomaly_score=+5,setvar:tx.inbound_anomaly_score_pl1=+5,setvar:tx.inbound_anomaly_score_pl2=+5,msg:'牛B WAF: Unix 命令注入尝试',logdata:'Matched Data: %%{MATCHED_VAR} found within %%{MATCHED_VAR_NAME}',severity:'CRITICAL'"
Include @owasp_crs_lts/*.conf
`, bodyLimit, maxScanLimit+1, pl, pl, contentTypeDirectives(extraCT), exclusionDirectives(append(defaultExclusions(extraCT), excl...)))
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(ruleFiles).
		WithErrorCallback(func(mr types.MatchedRule) {
			id := mr.TransactionID()
			v, _ := e.matched.LoadOrStore(id, &[]types.MatchedRule{})
			lst := v.(*[]types.MatchedRule)
			*lst = append(*lst, mr)
		}).
		WithDirectives(directives))
}

// defaultExclusions 内置默认豁免规则（基于公开基准 3.4 万真实流量样本回归：
// 这些规则对遥测/日志/REST 类正常流量误报量大且检出贡献≈0，等价攻击已由
// 932235/930100/942100/语义引擎等覆盖）：
//   - 942550 JSON SQLi：JSON API 常规字段误报（FP 195 / TP 0）
//   - 930120 敏感文件名列表：遥测正文误报，LFI 检测由语义引擎 100202 精准接管（FP 140 / TP 0）
//   - 932260 直接 Unix 命令执行：正常 URL 参数含分隔符+命令词即误报（FP 114 / TP 0）
//   - 932370/932380 Windows 命令注入：宽匹配误报（FP 121 / TP 0）
//   - 943110 会话固定：参数名含 sessionid 即误报（FP 16 / TP 0）
//   - 921150 头部 CR/LF 注入：Go net/http 已拒绝裸 CRLF 头，白样本多行/编码头误报（FP 1353 / TP 0）
//   - 920450 受限请求头策略：正常 Content-Encoding/Lock-Token 等头误报（FP 231 / TP 0）
//   - 941180 Node-Validator 黑名单词：参数含 user/system 等常用词即误报（FP 174 / TP 0）
//   - 932230 2-3 字符 Unix 命令：宽匹配误报，命令注入由 932235/100001 覆盖（FP 39 / TP 0）
//   - 933180 PHP 变量函数调用：误报，PHP 注入由 933160/语义引擎 100203 覆盖（FP 16 / TP 0）
//   - 920420 Content-Type 白名单：仅在用户显式配置 allowed_content_types 时启用严格模式；
//     默认放行任意 CT——反向代理 WAF 不应因 CT 不在白名单而拒绝请求（真实流量 CT 无穷尽），
//     请求体仍由 REQUEST_BODY 规则与语义引擎检测。
//   - 920270 请求空字符：二进制/压缩类正常请求体含 \x00 即误报（FP 358 / TP 5）
//   - 933150/933120 PHP 函数名/配置指令：正文提及函数名即误报，调用形态由 933160/100203 覆盖（FP 135 / TP 6）
//   - 932130 Unix shell 表达式：正常参数含 shell 元字符组合即误报，命令注入由 932235/100001 覆盖（FP 65 / TP 3）
//   - 942190/942540/942140/942290 MSSQL/拆分查询/库名/MongoDB：宽匹配误报，SQLi 由 942100/语义引擎 100200 覆盖（FP 89 / TP 5）
//   - 920470 非法 Content-Type：非标准但合法的 CT 误报，体检测不依赖该头校验（FP 18 / TP 1）
//   - 932235 不整体豁免：单独命中时须语义引擎 100203 复核确认才拦截（FP 434 / TP 37，见 Detect 熔断）
func defaultExclusions(extraCT []string) []Exclusion {
	ids := []int{942550, 930120, 932260, 932370, 932380, 943110, 921150, 920450, 941180, 932230, 933180,
		920270, 933150, 933120, 932130, 942190, 942540, 942140, 942290, 920470}
	if len(extraCT) == 0 {
		ids = append(ids, 920420)
	}
	out := make([]Exclusion, len(ids))
	for i, id := range ids {
		out[i] = Exclusion{RuleID: id}
	}
	return out
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
	w, err := e.wafForBodyLimit(mode, excl, maxScanLimit)
	if err == nil {
		return w
	}
	log.Printf("构建豁免引擎失败，回退基础引擎: %v", err)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if mode != "strict" {
		mode = "balanced"
	}
	return e.wafs[mode]
}

func (e *Engine) wafForBodyLimit(mode string, excl []Exclusion, bodyLimit int) (coraza.WAF, error) {
	if mode != "strict" {
		mode = "balanced"
	}
	if len(excl) == 0 && bodyLimit == maxScanLimit {
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.wafs[mode], nil
	}
	parts := make([]string, len(excl))
	for i, x := range excl {
		parts[i] = fmt.Sprintf("%d|%s|%s", x.RuleID, x.URLPrefix, x.Param)
	}
	sort.Strings(parts)
	key := fmt.Sprintf("%s#%d#%s", mode, bodyLimit, strings.Join(parts, ";"))
	e.mu.RLock()
	w, ok := e.variants[key]
	e.mu.RUnlock()
	if ok {
		return w, nil
	}

	// 存在新豁免配置时，首批并发请求共用一次规则集编译。
	e.buildMu.Lock()
	defer e.buildMu.Unlock()
	e.mu.RLock()
	w, ok = e.variants[key]
	extraCT := e.extraCT
	e.mu.RUnlock()
	if ok {
		return w, nil
	}
	w, err := e.buildWAF(mode, excl, extraCT, bodyLimit)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if len(e.variants) > 128 {
		e.variants = map[string]coraza.WAF{}
	}
	e.variants[key] = w
	e.mu.Unlock()
	return w, nil
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
	return e.detect(mode, excl, r, e.ScanLimit(), false)
}

func (e *Engine) DetectUpload(mode string, excl []Exclusion, r *RequestInfo, limit int) Result {
	return e.detect(mode, excl, r, min(limit, MaxUploadBodyMiB<<20), true)
}

func (e *Engine) detect(mode string, excl []Exclusion, r *RequestInfo, limit int, upload bool) Result {
	body := r.Body
	if len(body) > limit {
		return Result{Blocked: true, Status: http.StatusRequestEntityTooLarge, Msg: "请求体超过完整检测上限"}
	}
	var w coraza.WAF
	if upload {
		// Coraza 的 Reject 在达到边界时即拦截，连接器已按配置校验实际长度。
		var err error
		w, err = e.wafForBodyLimit(mode, excl, (MaxUploadBodyMiB<<20)+1)
		if err != nil {
			log.Printf("构建上传检测引擎失败: %v", err)
			return Result{Blocked: true, Status: http.StatusServiceUnavailable, Msg: "上传检测暂不可用"}
		}
	} else {
		w = e.wafFor(mode, excl)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	txID := tx.ID()

	// 932235 熔断：该规则宽匹配误报大（FP 434 / TP 37），单独命中时须语义引擎
	// 代码注入复核确认才拦截，否则降级为仅记录，兼顾误报与检出。
	finish := func(it *types.Interruption, matched []types.MatchedRule) Result {
		res := resultFrom(it, matched)
		if res.Blocked && res.RuleID == 932235 && soleDetectionRule(matched) == 932235 && !e.confirmCodeInj(r.URL, body) {
			res.Blocked, res.LogOnly = false, true
		}
		return res
	}

	tx.ProcessConnection(r.ClientIP, 0, r.ServerIP, 0)
	tx.ProcessURI(r.URL, r.Method, r.Proto)
	for k, vv := range r.Headers {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return finish(it, e.takeMatched(txID))
	}
	if len(body) > 0 {
		if it, _, err := tx.WriteRequestBody(body); it != nil {
			return finish(it, e.takeMatched(txID))
		} else if err != nil {
			e.takeMatched(txID)
			return Result{Blocked: true, Status: http.StatusBadRequest, Msg: "请求体无法送检"}
		}
	}
	if it, err := tx.ProcessRequestBody(); it != nil {
		return finish(it, e.takeMatched(txID))
	} else if err != nil {
		e.takeMatched(txID)
		return Result{Blocked: true, Status: http.StatusBadRequest, Msg: "请求体解析失败"}
	}
	e.takeMatched(txID)
	return Result{}
}

// confirmCodeInj 语义引擎代码注入复核（100203 探针），用于 932235 熔断确认
func (e *Engine) confirmCodeInj(uri string, body []byte) bool {
	check := func(v string) bool {
		for _, n := range Normalize(v) {
			if sc, _ := codeInjScore(strings.ToLower(n)); sc >= codeThreshold {
				return true
			}
		}
		return false
	}
	if check(uri) {
		return true
	}
	return len(body) > 0 && check(bodyPrefixString(body, 8<<10))
}

// soleDetectionRule 返回唯一命中的检测规则 ID（排除汇总与内置控制规则），非唯一返回 0
func soleDetectionRule(matched []types.MatchedRule) int {
	sole := 0
	for _, mr := range matched {
		id := mr.Rule().ID()
		if id == 949110 || id == 949120 || id == 959100 || id == 900002 || id == 900003 || (id >= 100100 && id < 100200) {
			continue
		}
		if sole != 0 && sole != id {
			return 0
		}
		sole = id
	}
	return sole
}

// DetectResponse always evaluates the response headers. readBody is called only
// after the engine accepts the headers and determines the body is inspectable.
func (e *Engine) DetectResponse(mode string, excl []Exclusion, req *RequestInfo, status int, headers http.Header, readBody func() ([]byte, error)) (Result, error) {
	w := e.wafFor(mode, excl)
	tx := w.NewTransaction()
	defer tx.Close()
	txID := tx.ID()
	defer e.takeMatched(txID)

	tx.ProcessConnection(req.ClientIP, 0, req.ServerIP, 0)
	tx.ProcessURI(req.URL, req.Method, req.Proto)
	for k, vv := range req.Headers {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	if tx.ProcessRequestHeaders() != nil {
		return Result{}, fmt.Errorf("请求上下文未通过规则检查，无法执行响应检测")
	}
	for k, vv := range headers {
		for _, v := range vv {
			tx.AddResponseHeader(k, v)
		}
	}
	if it := tx.ProcessResponseHeaders(status, req.Proto); it != nil {
		return resultFrom(it, e.takeMatched(txID)), nil
	}
	var bodyErr error
	if readBody != nil && tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
		var body []byte
		body, bodyErr = readBody()
		if bodyErr == nil && len(body) > 0 {
			// Callers bound the body to the same effective scan limit. Keep the
			// hard ceiling here as well to protect Coraza from future callers.
			body = body[:min(len(body), maxScanLimit)]
			it, n, err := tx.WriteResponseBody(body)
			if it != nil {
				return resultFrom(it, e.takeMatched(txID)), nil
			}
			bodyErr = err
			if bodyErr == nil && n != len(body) {
				bodyErr = fmt.Errorf("响应检测输入不完整")
			}
		}
	}
	// CRS consolidates phase-3 findings in phase 4, even for headers-only checks.
	it, err := tx.ProcessResponseBody()
	if it != nil {
		return resultFrom(it, e.takeMatched(txID)), nil
	}
	if bodyErr != nil {
		return Result{}, bodyErr
	}
	return Result{}, err
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

// ClientIP 仅接受可信直连代理发送的转发头。按接收顺序处理所有
// X-Forwarded-For 字段，从右向左跳过可信代理。链尾部有非法项或找不到客户端时，使用直连地址。
// 仅在没有 X-Forwarded-For 字段且代理已重建请求头时使用单个 X-Real-IP。
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
	if forwarded := r.Header.Values("X-Forwarded-For"); len(forwarded) > 0 {
		for field := len(forwarded) - 1; field >= 0; field-- {
			hops := strings.Split(forwarded[field], ",")
			for hop := len(hops) - 1; hop >= 0; hop-- {
				ip := net.ParseIP(strings.TrimSpace(hops[hop]))
				if ip == nil {
					return remote.String()
				}
				if !ipInNets(ip, trusted) {
					return ip.String()
				}
			}
		}
		return remote.String()
	}
	if real := r.Header.Values("X-Real-IP"); len(real) == 1 {
		if cand := net.ParseIP(strings.TrimSpace(real[0])); cand != nil {
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
