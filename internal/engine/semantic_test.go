package engine

import (
	"encoding/base64"
	"net/url"
	"regexp/syntax"
	"strings"
	"testing"
)

func hasVariant(vs []string, sub string) bool {
	for _, v := range vs {
		if strings.Contains(strings.ToLower(v), sub) {
			return true
		}
	}
	return false
}

func TestSemanticProbeMarkers(t *testing.T) {
	for _, g := range []struct {
		probes []semanticProbe
		chars  string
		word   string
	}{
		{xssProbes, xssProbeMarkerChars, xssProbeMarkerWord},
		{lfiProbes, lfiProbeMarkerChars, ""},
		{codeInjProbes, codeProbeMarkerChars, ""},
	} {
		for _, p := range g.probes {
			tree, err := syntax.Parse(p.re.String(), syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			if canMatchWithoutMarker(tree, g.chars, g.word) {
				t.Errorf("cannot prove that %q requires a prefilter marker", p.name)
			}
		}
	}
}

// Conservative proof: unknown or optional nodes may match without a marker.
func canMatchWithoutMarker(re *syntax.Regexp, chars, word string) bool {
	switch re.Op {
	case syntax.OpNoMatch:
		return false
	case syntax.OpLiteral:
		text := string(re.Rune)
		hasWord := re.Flags&syntax.FoldCase == 0 && word != "" && strings.Contains(text, word)
		return !strings.ContainsAny(text, chars) && !hasWord
	case syntax.OpCharClass:
		for i := 0; i < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if !strings.ContainsRune(chars, r) {
					return true
				}
			}
		}
		return false
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !canMatchWithoutMarker(sub, chars, word) {
				return false
			}
		}
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if canMatchWithoutMarker(sub, chars, word) {
				return true
			}
		}
		return false
	case syntax.OpCapture, syntax.OpPlus:
		return canMatchWithoutMarker(re.Sub[0], chars, word)
	case syntax.OpRepeat:
		return re.Min == 0 || canMatchWithoutMarker(re.Sub[0], chars, word)
	}
	return true
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"%2555nion%2520select", "union select"},   // 双重 URL 编码
		{"%u0055nion select", "union select"},      // IIS %u
		{"&#85;NION SELECT", "union select"},       // HTML 实体
		{"ＵＮＩＯＮ ＳＥＬＥＣＴ", "union select"},           // 全角 NFKC
		{"UNION/**/SELECT", "union select"},        // 块注释折叠
		{"/*!50000UNION*/ SELECT", "union select"}, // MySQL 可执行注释
		{"%3Cscript%3E", "<script>"},               // 编码标签
	}
	for _, c := range cases {
		vs := Normalize(c.in)
		if !hasVariant(vs, c.want) {
			t.Errorf("Normalize(%q) 变体 %v 未包含 %q", c.in, vs, c.want)
		}
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("1 UNION SELECT 1,2"))
	if !hasVariant(Normalize(b64), "union select") {
		t.Error("base64 变体未还原")
	}
	if vs := Normalize("hello world"); len(vs) != 1 {
		t.Errorf("普通文本不应产生多余变体: %v", vs)
	}
}

func TestNormalizeJSEscape(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`\x65\x76\x61\x6c`, "eval"},            // \xNN
		{`\u0061lert(1)`, "alert(1)"},           // \uNNNN
		{`\u{61}lert(1)`, "alert(1)"},           // ES6 \u{N}
		{`parent['\145val']`, "parent['eval']"}, // 八进制
	}
	for _, c := range cases {
		if !hasVariant(Normalize(c.in), c.want) {
			t.Errorf("Normalize(%q) 变体未还原出 %q", c.in, c.want)
		}
	}
	// 非法序列原样保留，不应产生新变体
	if vs := Normalize(`\xZZ\u12`); len(vs) != 1 {
		t.Errorf("非法转义序列不应产生变体: %v", vs)
	}
	// 双层 base64 还原（webshell 包装）
	inner := base64.StdEncoding.EncodeToString([]byte("<?php eval($_POST['x']); ?>"))
	if !hasVariant(Normalize(base64.StdEncoding.EncodeToString([]byte(inner))), "<?php") {
		t.Error("双层 base64 未还原")
	}
	// 截断的 base64 载荷（基准样本常见形态）
	full := base64.StdEncoding.EncodeToString([]byte("union select password from users"))
	if !hasVariant(Normalize(full[:len(full)-2]), "union select") {
		t.Error("截断 base64 未还原")
	}
}

func sqlHit(t *testing.T, payload string) bool {
	t.Helper()
	for _, v := range Normalize(payload) {
		for _, st := range sqlTexts(strings.ToLower(v)) {
			if sc, _ := sqlScore(tokenize(st)); sc >= sqlThreshold {
				return true
			}
		}
	}
	return false
}

func TestSemanticSQL(t *testing.T) {
	positives := []string{
		"' OR 1=1-- ",
		"' OR 'a'='a",
		"1 UNION SELECT username,password FROM users",
		"1 UNION ALL SELECT 1,2,3",
		"1; DROP TABLE users",
		"1 AND SLEEP(5)",
		"1 AND BENCHMARK(1000000,MD5(1))",
		"1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))",
		"1 INTO OUTFILE '/tmp/x'",
		"1 AND ASCII(SUBSTRING((SELECT user()),1,1))>64",
		"1' AND '1'='1",
		"' UNION SELECT 0x61646d696e,CHAR(65,66)",
		"%2555nion%2520select%25201,2", // 双重编码绕过 CRS
		"ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2",             // 全角绕过
		"UNION/**/SELECT 1,2",          // 注释分隔绕过
		"SELECT * FROM all_tables",     // libinjection 漏报的裸查询结构
		"1; INSERT INTO logs VALUES(1)",
	}
	for _, p := range positives {
		if !sqlHit(t, p) {
			t.Errorf("SQL 语义漏报: %q", p)
		}
	}
	negatives := []string{
		"hello world",
		"price=100",
		"q=union of sets",
		"order=id",
		"search=O'Reilly",
		"note=1=1",
		"expr=2>1",
		"callback=javascript is fun",
		"name=张三",
		"page=2&sort=desc",
		"select their representatives from among the members", // 英文叙述不应命中 SELECT…FROM 结构
	}
	for _, p := range negatives {
		if sqlHit(t, p) {
			t.Errorf("SQL 语义误报: %q", p)
		}
	}
}

func xssHit(t *testing.T, payload string) bool {
	t.Helper()
	for _, v := range Normalize(payload) {
		if sc, _ := xssScore(strings.ToLower(v)); sc >= xssThreshold {
			return true
		}
	}
	return false
}

func TestSemanticXSS(t *testing.T) {
	positives := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<a href=javascript:alert(1)>x</a>",
		"eval(String.fromCharCode(97,108,101,114,116))",
		"<iframe srcdoc='<script>alert(1)</script>'>",
		"%3Cscript%3Ealert(1)%3C/script%3E",
		"＜ｓｃｒｉｐｔ＞alert(1)＜/ｓｃｒｉｐｔ＞", // 全角标签
		"&#60;script&#62;alert(1)&#60;/script&#62;",
		`parent['\x65\x76\x61\x6c']('boom')`, // JS 转义混淆的括号属性访问
	}
	for _, p := range positives {
		if !xssHit(t, p) {
			t.Errorf("XSS 语义漏报: %q", p)
		}
	}
	negatives := []string{
		"hello world",
		"redirect=https://example.com/?a=1",
		"comment=I love <3 you",
		"title=script writing guide",
		"q=alert me when done",
	}
	for _, p := range negatives {
		if xssHit(t, p) {
			t.Errorf("XSS 语义误报: %q", p)
		}
	}
}

func TestSemanticExclusions(t *testing.T) {
	e := &Engine{}
	uri := "/product?id=1%20UNION%20SELECT%201,2"
	hit := e.Semantic(nil, uri, nil)
	if hit == nil || hit.RuleID != SemSQLiRuleID || hit.Param != "id" {
		t.Fatalf("期望 id 参数 SQLi 命中, got %+v", hit)
	}
	// 参数级豁免生效
	hit = e.Semantic([]Exclusion{{RuleID: SemSQLiRuleID, Param: "id"}}, uri, nil)
	if hit != nil {
		t.Error("参数级豁免未生效")
	}
	// 其他参数不豁免
	hit = e.Semantic([]Exclusion{{RuleID: SemSQLiRuleID, Param: "foo"}}, uri, nil)
	if hit == nil {
		t.Error("豁免不应跨参数")
	}
	// URL 前缀不匹配不豁免
	hit = e.Semantic([]Exclusion{{RuleID: SemSQLiRuleID, URLPrefix: "/other"}}, uri, nil)
	if hit == nil {
		t.Error("前缀不匹配不应豁免")
	}
	// 表单体参数
	hit = e.Semantic(nil, "/", []byte("q=%3Cscript%3Ealert(1)%3C/script%3E"))
	if hit == nil || hit.RuleID != SemXSSRuleID || hit.Param != "q" {
		t.Fatalf("期望表单 q 参数 XSS 命中, got %+v", hit)
	}
}

func TestSemanticLFICodeInj(t *testing.T) {
	e := &Engine{}
	lfiCases := []string{
		"/f.php?file=php://filter/read=convert.base64-encode/resource=index.php",
		"/x?page=../../../../etc/passwd",
		"/x?f=http://169.254.169.254/latest/meta-data/",
		"/x?f=file:////etc/shadow",
	}
	for _, uri := range lfiCases {
		hit := e.Semantic(nil, uri, nil)
		if hit == nil || hit.RuleID != SemLFIRuleID {
			t.Errorf("LFI/SSRF 漏报 %q, got %+v", uri, hit)
		}
	}
	// 普通下载路径不应命中
	if hit := e.Semantic(nil, "/download?file=report-2026.pdf", nil); hit != nil {
		t.Errorf("普通文件参数误报: %+v", hit)
	}
	// 豁免生效
	if hit := e.Semantic([]Exclusion{{RuleID: SemLFIRuleID}}, "/x?page=../../../../etc/passwd", nil); hit != nil {
		t.Errorf("豁免 %d 未生效: %+v", SemLFIRuleID, hit)
	}

	// base64 还原后暴露的 PHP 载荷 → 代码注入
	enc := base64.StdEncoding.EncodeToString([]byte("<?php system($_GET['c']); ?>"))
	hit := e.Semantic(nil, "/upload", []byte("payload="+url.QueryEscape(enc)))
	if hit == nil || hit.RuleID != SemCodeInjRuleID {
		t.Errorf("base64 PHP 载荷漏报, got %+v", hit)
	}
	// 明文 webshell 特征
	if hit := e.Semantic(nil, "/shell.jsp", []byte("x="+url.QueryEscape(`<%@ page import="java.io.*"%>`))); hit == nil || hit.RuleID != SemCodeInjRuleID {
		t.Errorf("JSP webshell 漏报, got %+v", hit)
	}
	// Struts OGNL 注入
	if hit := e.Semantic(nil, "/x", []byte("p="+url.QueryEscape("(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"))); hit == nil || hit.RuleID != SemCodeInjRuleID {
		t.Errorf("OGNL 注入漏报, got %+v", hit)
	}
	// 普通内容不应命中代码注入
	if hit := e.Semantic(nil, "/api/doc", []byte("topic=php tutorial for beginners")); hit != nil {
		t.Errorf("普通文本误报代码注入: %+v", hit)
	}
}
