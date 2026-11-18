package engine

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// 语义引擎自定义规则 ID（可被规则调优豁免）
const (
	SemSQLiRuleID = 100200
	SemXSSRuleID  = 100201
	sqlThreshold  = 6
	xssThreshold  = 6
)

type SemanticHit struct {
	RuleID int
	Msg    string
	Score  int
	Param  string
}

type token struct {
	kind byte // w 词 s 字符串 n 数字 x 十六进制 o 运算符 p 标点 c 注释
	val  string
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
func isWordStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$' || c >= 0x80
}
func isWordChar(c byte) bool { return isWordStart(c) || isDigit(c) }

func tokenize(s string) []token {
	toks := make([]token, 0, 32)
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f':
			i++
		case c == '\'' || c == '"':
			i++
			var b strings.Builder
			closed := false
			for i < n {
				if s[i] == '\\' && i+1 < n {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == c {
					if i+1 < n && s[i+1] == c {
						b.WriteByte(c)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				b.WriteByte(s[i])
				i++
			}
			k := byte('s')
			if !closed {
				k = 'u' // 未闭合引号：注入中常用于闭合应用侧 SQL 字符串
			}
			toks = append(toks, token{k, b.String()})
		case c == '#', c == '-' && i+1 < n && s[i+1] == '-':
			j := i
			for j < n && s[j] != '\n' {
				j++
			}
			toks = append(toks, token{'c', s[i:j]})
			i = j
		case c == '/' && i+1 < n && s[i+1] == '*':
			j := i + 2
			for j+1 < n && !(s[j] == '*' && s[j+1] == '/') {
				j++
			}
			if j+1 < n {
				j += 2
			} else {
				j = n
			}
			toks = append(toks, token{'c', s[i:j]})
			i = j
		case isDigit(c):
			j := i
			if c == '0' && i+1 < n && (s[i+1] == 'x' || s[i+1] == 'X') {
				j = i + 2
				for j < n && isHex(s[j]) {
					j++
				}
				toks = append(toks, token{'x', s[i:j]})
			} else {
				for j < n && (isDigit(s[j]) || s[j] == '.') {
					j++
				}
				toks = append(toks, token{'n', s[i:j]})
			}
			i = j
		case isWordStart(c):
			j := i + 1
			for j < n && isWordChar(s[j]) {
				j++
			}
			toks = append(toks, token{'w', strings.ToLower(s[i:j])})
			i = j
		case c == '(' || c == ')' || c == ',' || c == ';' || c == '.':
			toks = append(toks, token{'p', string(c)})
			i++
		default:
			if i+1 < n {
				switch s[i : i+2] {
				case "||", "&&", "<=", ">=", "<>", "!=", ":=":
					toks = append(toks, token{'o', s[i : i+2]})
					i += 2
					continue
				}
			}
			toks = append(toks, token{'o', string(c)})
			i++
		}
	}
	return toks
}

var sqlFuncs = map[string]int{
	"sleep": 6, "benchmark": 6, "load_file": 5, "extractvalue": 5, "updatexml": 5,
}
var stackKeywords = map[string]bool{
	"select": true, "insert": true, "update": true, "delete": true, "drop": true,
	"alter": true, "create": true, "exec": true, "execute": true, "truncate": true, "grant": true,
}
var blindFuncs = map[string]bool{"substring": true, "substr": true, "mid": true, "ascii": true, "ord": true}
var infoFuncs = map[string]bool{"version": true, "user": true, "database": true, "schema": true}
var concatFuncs = map[string]bool{"concat": true, "concat_ws": true, "group_concat": true}

func isCmp(op string) bool {
	switch op {
	case "=", "==", "<>", "!=", ">", "<", ">=", "<=":
		return true
	}
	return false
}

type operand struct {
	str string
	num float64
	isN bool
}

func litOperand(t token) (operand, bool) {
	switch t.kind {
	case 's', 'u': // 未闭合引号按字面量处理：真实注入中闭合引号由应用侧 SQL 提供
		return operand{str: t.val}, true
	case 'n':
		f, err := strconv.ParseFloat(t.val, 64)
		return operand{num: f, isN: true}, err == nil
	case 'x':
		v, err := strconv.ParseUint(t.val[2:], 16, 64)
		return operand{num: float64(v), isN: true}, err == nil
	}
	return operand{}, false
}

func cmpTrue(l operand, op string, r operand) bool {
	if l.isN != r.isN {
		return false
	}
	if l.isN {
		switch op {
		case "=", "==":
			return l.num == r.num
		case "<>", "!=":
			return l.num != r.num
		case ">":
			return l.num > r.num
		case "<":
			return l.num < r.num
		case ">=":
			return l.num >= r.num
		case "<=":
			return l.num <= r.num
		}
		return false
	}
	switch op {
	case "=", "==":
		return l.str == r.str
	case "<>", "!=":
		return l.str != r.str
	}
	return false
}

// sqlScore 语法级评分：恒真式/UNION 结构/堆叠/危险函数/盲注/编码混淆
func sqlScore(toks []token) (int, string) {
	score, best := 0, 0
	reason := ""
	add := func(pts int, r string) {
		score += pts
		if pts > best {
			best, reason = pts, r
		}
	}
	word := func(i int) string {
		if i >= 0 && i < len(toks) && toks[i].kind == 'w' {
			return toks[i].val
		}
		return ""
	}
	is := func(i int, k byte, v string) bool {
		return i >= 0 && i < len(toks) && toks[i].kind == k && (v == "" || toks[i].val == v)
	}
	for i, t := range toks {
		w := word(i)
		switch {
		case w == "union" && (word(i+1) == "select" || (word(i+1) == "all" || word(i+1) == "distinct") && word(i+2) == "select"):
			add(6, "UNION SELECT 结构")
		case t.kind == 'p' && t.val == ";" && stackKeywords[word(i+1)]:
			add(6, "堆叠查询")
		case sqlFuncs[w] > 0 && is(i+1, 'p', "("):
			pts := sqlFuncs[w]
			if word(i-1) == "and" || word(i-1) == "or" {
				pts += 2
			}
			add(pts, "危险函数 "+w)
		case w == "waitfor" && word(i+1) == "delay":
			add(6, "时间盲注 WAITFOR")
		case w == "into" && (word(i+1) == "outfile" || word(i+1) == "dumpfile"):
			add(6, "写文件 INTO OUTFILE")
		case w == "information_schema":
			add(4, "探测 information_schema")
		case infoFuncs[w] && is(i+1, 'p', "("):
			add(4, "信息函数 "+w)
		case t.kind == 'o' && t.val == "@" && is(i+1, 'o', "@") && infoFuncs[word(i+2)]:
			add(4, "系统变量 @@")
		case concatFuncs[w] && is(i+1, 'p', "("):
			add(3, "字符串拼接 "+w)
		case t.kind == 'o' && (t.val == "||" || t.val == "+") && is(i-1, 's', "") && is(i+1, 's', ""):
			add(3, "字符串拼接运算")
		case t.kind == 'x' && len(t.val) >= 10:
			add(3, "十六进制编码")
		case (w == "char" || w == "chr") && is(i+1, 'p', "("):
			add(3, "CHAR 编码还原")
		case blindFuncs[w] && is(i+1, 'p', "("):
			add(4, "盲注函数 "+w)
		case t.kind == 'o' && isCmp(t.val):
			var l, r operand
			var ok1, ok2 bool
			if i > 0 {
				l, ok1 = litOperand(toks[i-1])
			}
			if i+1 < len(toks) {
				r, ok2 = litOperand(toks[i+1])
			}
			if ok1 && ok2 && cmpTrue(l, t.val, r) {
				if word(i-2) == "or" || word(i-2) == "and" || is(i-2, 'o', "||") || is(i-2, 'o', "&&") {
					add(6, "OR/AND 恒真式")
				} else {
					add(4, "恒真表达式")
				}
			}
		case (t.kind == 's' || t.kind == 'n') && is(i+1, 'c', "") && i+1 == len(toks)-1:
			add(3, "注释截断")
		case t.kind == 'u' && i == len(toks)-1:
			add(3, "引号截断")
		}
	}
	if score > 20 {
		score = 20
	}
	return score, reason
}

var xssProbes = []struct {
	re   *regexp.Regexp
	pts  int
	name string
}{
	{regexp.MustCompile(`<\s*script`), 6, "script 标签"},
	{regexp.MustCompile(`<[^>]+\son[a-z]{2,}\s*=`), 5, "事件处理器属性"},
	{regexp.MustCompile(`(href|src|action|formaction|data|poster|background)\s*=\s*["']?\s*(javascript|vbscript)\s*:`), 5, "伪协议注入"},
	{regexp.MustCompile(`<\s*(svg|math|iframe|object|embed|form|input|img|body|video|audio|details|marquee)\b[^>]*(on[a-z]+\s*=|srcdoc\s*=)`), 5, "危险标签+活动属性"},
	{regexp.MustCompile(`javascript\s*:`), 4, "javascript 伪协议"},
	{regexp.MustCompile(`string\s*\.\s*fromcharcode`), 4, "字符码混淆"},
	{regexp.MustCompile(`\beval\s*\(`), 4, "eval 执行"},
	{regexp.MustCompile(`\bexpression\s*\(`), 4, "CSS expression"},
	{regexp.MustCompile(`document\s*\.\s*(cookie|write|location)`), 4, "敏感 DOM 操作"},
	{regexp.MustCompile(`\b(atob|unescape|decodeuri|decodeuricomponent)\s*\(`), 3, "解码函数"},
	{regexp.MustCompile(`\b(alert|prompt|confirm)\s*\(`), 3, "弹窗探测"},
	{regexp.MustCompile(`innerhtml\s*=`), 3, "innerHTML 注入"},
}

func xssScore(low string) (int, string) {
	score, best := 0, 0
	reason := ""
	for _, p := range xssProbes {
		if p.re.MatchString(low) {
			score += p.pts
			if p.pts > best {
				best, reason = p.pts, p.name
			}
		}
	}
	return score, reason
}

type semField struct{ name, val string }

// sqlTexts 追加“引号逃逸”解析变体：注入载荷的前导引号用于闭合应用侧字符串，
// 去掉它之后的内容才是真正进入 SQL 语法的代码
func sqlTexts(v string) []string {
	out := []string{v}
	if idx := strings.IndexAny(v, "'\""); idx >= 0 && idx <= 8 {
		out = append(out, v[idx+1:])
	}
	return out
}

// Semantic 对归一化后的请求字段做语法级/上下文级检测，返回最高分命中（尊重豁免）
func (e *Engine) Semantic(excl []Exclusion, uri string, body []byte) *SemanticHit {
	path := uri
	fields := []semField{{"path", uri}}
	if u, err := url.ParseRequestURI(uri); err == nil {
		path = u.Path
		fields[0].val = u.Path
		for k, vv := range u.Query() {
			for _, v := range vv {
				fields = append(fields, semField{k, v})
			}
		}
	}
	if len(body) > 0 {
		bs := truncUTF8(string(body), 64<<10)
		fields = append(fields, semField{"body", bs})
		trimmed := strings.TrimLeft(bs, " \t\r\n")
		if strings.Contains(bs, "=") && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "<") {
			if q, err := url.ParseQuery(bs); err == nil {
				for k, vv := range q {
					for _, v := range vv {
						fields = append(fields, semField{k, v})
					}
				}
			}
		}
	}

	hits := map[int]*SemanticHit{}
	consider := func(ruleID, score int, kind, reason, param string) {
		if h := hits[ruleID]; h == nil || score > h.Score || (score == h.Score && h.Param == "body" && param != "body") {
			hits[ruleID] = &SemanticHit{
				RuleID: ruleID, Score: score, Param: param,
				Msg: "牛B WAF 语义引擎: " + kind + "（" + reason + "，评分 " + strconv.Itoa(score) + "）",
			}
		}
	}
	for _, f := range fields {
		for _, v := range Normalize(f.val) {
			low := strings.ToLower(v)
			for _, st := range sqlTexts(low) {
				if sc, r := sqlScore(tokenize(st)); sc >= sqlThreshold {
					consider(SemSQLiRuleID, sc, "SQL 注入语法级命中", r, f.name)
				}
			}
			if sc, r := xssScore(low); sc >= xssThreshold {
				consider(SemXSSRuleID, sc, "XSS 上下文级命中", r, f.name)
			}
		}
	}

	var best *SemanticHit
	for _, h := range hits {
		excluded := false
		for _, x := range excl {
			if x.RuleID != h.RuleID {
				continue
			}
			if x.URLPrefix != "" && !strings.HasPrefix(path, x.URLPrefix) {
				continue
			}
			if x.Param != "" && x.Param != h.Param {
				continue
			}
			excluded = true
			break
		}
		if !excluded && (best == nil || h.Score > best.Score) {
			best = h
		}
	}
	return best
}