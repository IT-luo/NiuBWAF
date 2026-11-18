package engine

import (
	"encoding/base64"
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

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"%2555nion%2520select", "union select"},      // 双重 URL 编码
		{"%u0055nion select", "union select"},        // IIS %u
		{"&#85;NION SELECT", "union select"},         // HTML 实体
		{"ＵＮＩＯＮ ＳＥＬＥＣＴ", "union select"},       // 全角 NFKC
		{"UNION/**/SELECT", "union select"},          // 块注释折叠
		{"/*!50000UNION*/ SELECT", "union select"},   // MySQL 可执行注释
		{"%3Cscript%3E", "<script>"},                 // 编码标签
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
		"ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2",   // 全角绕过
		"UNION/**/SELECT 1,2",        // 注释分隔绕过
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