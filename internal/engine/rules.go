package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const RuleActionRateLimit = "rate_limit"

// RuleDef 是自定义规则的原始定义（与存储层解耦，由代理转换传入）
type RuleDef struct {
	ID          int64
	SiteID      int64
	Name        string
	Priority    int
	Logic       string
	Conditions  string
	Action      string
	ActionParam string
	Shadow      bool
}

// RuleCondition 单条匹配条件：field 取值字段，op 操作符，value 比较值，name 用于 header/param 字段名
type RuleCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
	Name  string `json:"name"`
}

type compiledCond struct {
	field, op, value, name string
	re                     *regexp.Regexp
	nets                   []*net.IPNet
	set                    map[string]bool
}

// CompiledRule 编译后的规则：正则/CIDR/集合预编译，请求路径上零解析开销
type CompiledRule struct {
	ID          int64
	SiteID      int64
	Name        string
	Priority    int
	Logic       string
	Action      string
	ActionParam string
	Shadow      bool
	Rate        int
	Burst       int
	Conditions  []compiledCond
}

// RuleInput 规则评估所需的请求快照
type RuleInput struct {
	QueryRedacted bool // 历史记录只保留路径时，完整 URL 和查询参数不可用。
	ClientIP      string
	Method        string
	Path          string
	URL           string
	Header        http.Header
	Query         url.Values
	Country       string
}

var ruleFields = map[string]bool{"ip": true, "path": true, "url": true, "method": true, "header": true, "param": true, "country": true}
var ruleOps = map[string]bool{"eq": true, "ne": true, "contains": true, "prefix": true, "suffix": true, "regex": true, "cidr": true, "in": true}

const maxCondValueScan = 16384

// CompileRule 解析并预编译规则；条件非法（正则/CIDR/字段/操作符）时返回错误，供 API 拒绝保存
func CompileRule(d RuleDef) (CompiledRule, error) {
	cr := CompiledRule{ID: d.ID, SiteID: d.SiteID, Name: d.Name, Priority: d.Priority, Action: d.Action, ActionParam: d.ActionParam, Shadow: d.Shadow}
	if d.Action == RuleActionRateLimit {
		rate, burst, err := parseRateLimit(d.ActionParam)
		if err != nil {
			return cr, err
		}
		cr.Rate, cr.Burst = rate, burst
	}
	cr.Logic = "and"
	if d.Logic == "or" {
		cr.Logic = "or"
	}
	var conds []RuleCondition
	if err := json.Unmarshal([]byte(d.Conditions), &conds); err != nil {
		return cr, fmt.Errorf("条件 JSON 无效: %w", err)
	}
	if len(conds) == 0 {
		return cr, fmt.Errorf("至少需要一个匹配条件")
	}
	if len(conds) > 20 {
		return cr, fmt.Errorf("匹配条件最多 20 条")
	}
	for _, c := range conds {
		cc, err := compileCond(c)
		if err != nil {
			return cr, err
		}
		cr.Conditions = append(cr.Conditions, cc)
	}
	return cr, nil
}

// parseRateLimit 接受 action_param 的「每秒请求数」或「每秒请求数,突发容量」。
func parseRateLimit(param string) (rate, burst int, err error) {
	const maxRate = 1_000_000
	rateText, burstText, hasBurst := strings.Cut(param, ",")
	rate, err = strconv.Atoi(strings.TrimSpace(rateText))
	if err != nil || rate < 1 || rate > maxRate {
		return 0, 0, fmt.Errorf("限流速率须为 1–%d 之间的整数", maxRate)
	}
	if hasBurst {
		burst, err = strconv.Atoi(strings.TrimSpace(burstText))
		if err != nil || burst < 0 || burst > maxRate {
			return 0, 0, fmt.Errorf("突发容量须为 0–%d 之间的整数", maxRate)
		}
	}
	return rate, burst, nil
}

func compileCond(c RuleCondition) (compiledCond, error) {
	cc := compiledCond{field: c.Field, op: c.Op, name: strings.TrimSpace(c.Name)}
	if !ruleFields[c.Field] {
		return cc, fmt.Errorf("未知匹配字段: %q", c.Field)
	}
	if !ruleOps[c.Op] {
		return cc, fmt.Errorf("未知操作符: %q", c.Op)
	}
	if (c.Field == "header" || c.Field == "param") && cc.name == "" {
		return cc, fmt.Errorf("%s 字段需要指定名称", c.Field)
	}
	// method/country 大小写不敏感，统一大写比较
	if c.Field == "method" || c.Field == "country" {
		cc.value = strings.ToUpper(strings.TrimSpace(c.Value))
	} else {
		cc.value = c.Value
	}
	switch c.Op {
	case "regex":
		if cc.value == "" {
			return cc, fmt.Errorf("regex 操作符需要非空表达式")
		}
		re, err := regexp.Compile(c.Value)
		if err != nil {
			return cc, fmt.Errorf("正则表达式无效: %w", err)
		}
		cc.re = re
	case "cidr":
		for _, raw := range strings.Split(c.Value, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if strings.Contains(raw, "/") {
				_, n, err := net.ParseCIDR(raw)
				if err != nil {
					return cc, fmt.Errorf("CIDR 无效: %s", raw)
				}
				cc.nets = append(cc.nets, n)
			} else if ip := net.ParseIP(raw); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				cc.nets = append(cc.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			} else {
				return cc, fmt.Errorf("IP/CIDR 无效: %s", raw)
			}
		}
		if len(cc.nets) == 0 {
			return cc, fmt.Errorf("cidr 操作符需要至少一个 IP/CIDR")
		}
	case "in":
		cc.set = map[string]bool{}
		for _, raw := range strings.Split(c.Value, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if c.Field == "method" || c.Field == "country" {
				raw = strings.ToUpper(raw)
			}
			cc.set[raw] = true
		}
		if len(cc.set) == 0 {
			return cc, fmt.Errorf("in 操作符需要至少一个值")
		}
	default:
		if c.Op != "eq" && c.Op != "ne" && cc.value == "" {
			return cc, fmt.Errorf("%s 操作符需要非空比较值", c.Op)
		}
	}
	return cc, nil
}

func (c *compiledCond) match(in *RuleInput) bool {
	var val string
	switch c.field {
	case "ip":
		val = in.ClientIP
	case "path":
		val = in.Path
	case "url":
		val = in.URL
	case "method":
		val = strings.ToUpper(in.Method)
	case "country":
		val = strings.ToUpper(in.Country)
	case "header":
		val = in.Header.Get(c.name)
	case "param":
		val = in.Query.Get(c.name)
	default:
		return false
	}
	if len(val) > maxCondValueScan {
		val = val[:maxCondValueScan]
	}
	switch c.op {
	case "eq":
		return val == c.value
	case "ne":
		return val != c.value
	case "contains":
		return strings.Contains(val, c.value)
	case "prefix":
		return strings.HasPrefix(val, c.value)
	case "suffix":
		return strings.HasSuffix(val, c.value)
	case "regex":
		return c.re != nil && c.re.MatchString(val)
	case "in":
		return c.set[val]
	case "cidr":
		ip := net.ParseIP(val)
		if ip == nil {
			return false
		}
		for _, n := range c.nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return false
}

// Match 按 and/or 逻辑判定规则是否命中；无条件视为不命中，避免误配全局拦截
func (cr *CompiledRule) Match(in *RuleInput) bool {
	if len(cr.Conditions) == 0 {
		return false
	}
	if cr.Logic == "or" {
		for i := range cr.Conditions {
			if cr.Conditions[i].match(in) {
				return true
			}
		}
		return false
	}
	for i := range cr.Conditions {
		if !cr.Conditions[i].match(in) {
			return false
		}
	}
	return true
}

// MatchState 是日志回放的三值匹配结果。攻击日志没有请求头，不能把
// header 条件的“无法确定”当成实时匹配中的 false。
type MatchState uint8

const (
	MatchFalse MatchState = iota
	MatchTrue
	MatchUnknown
)

// MatchReplay 在 attack_logs 可用字段上评估规则。AND 任一 false 即为 false，
// 否则任一 unknown 即为 unknown；OR 任一 true 即为 true，否则任一 unknown
// 即为 unknown。实时请求仍使用上面的布尔 Match，语义保持不变。
func (cr *CompiledRule) MatchReplay(in *RuleInput) MatchState {
	if len(cr.Conditions) == 0 {
		return MatchFalse
	}
	if cr.Logic == "or" {
		state := MatchFalse
		for i := range cr.Conditions {
			var condState MatchState
			if !cr.Conditions[i].availableForReplay(in) {
				condState = MatchUnknown
			} else if cr.Conditions[i].match(in) {
				condState = MatchTrue
			}
			if condState == MatchTrue {
				return MatchTrue
			}
			if condState == MatchUnknown {
				state = MatchUnknown
			}
		}
		return state
	}

	state := MatchTrue
	for i := range cr.Conditions {
		var condState MatchState
		if !cr.Conditions[i].availableForReplay(in) {
			condState = MatchUnknown
		} else if cr.Conditions[i].match(in) {
			condState = MatchTrue
		}
		if condState == MatchFalse {
			return MatchFalse
		}
		if condState == MatchUnknown {
			state = MatchUnknown
		}
	}
	return state
}

func (c *compiledCond) availableForReplay(in *RuleInput) bool {
	return c.field != "header" && !(in.QueryRedacted && (c.field == "url" || c.field == "param"))
}

// MatchRule 返回按优先级排序后首个命中的规则
func MatchRule(rules []CompiledRule, in *RuleInput) *CompiledRule {
	for i := range rules {
		if rules[i].Match(in) {
			return &rules[i]
		}
	}
	return nil
}
