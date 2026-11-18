package engine

import (
	"net/http"
	"net/url"
	"testing"
)

func mustCompile(t *testing.T, logic, conds, action string) CompiledRule {
	t.Helper()
	cr, err := CompileRule(RuleDef{ID: 1, Name: "test", Priority: 100, Logic: logic, Conditions: conds, Action: action})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	return cr
}

func input(ip, method, path, rawurl, country string, hdr http.Header, q url.Values) *RuleInput {
	if hdr == nil {
		hdr = http.Header{}
	}
	if q == nil {
		q = url.Values{}
	}
	return &RuleInput{ClientIP: ip, Method: method, Path: path, URL: rawurl, Header: hdr, Query: q, Country: country}
}

func TestCompileRejectsInvalid(t *testing.T) {
	cases := []string{
		`[]`,                                  // 无条件
		`not json`,                            // 非法 JSON
		`[{"field":"bogus","op":"eq","value":"x"}]`,   // 未知字段
		`[{"field":"path","op":"bogus","value":"x"}]`, // 未知操作符
		`[{"field":"path","op":"regex","value":"("}]`, // 非法正则
		`[{"field":"ip","op":"cidr","value":"999.1.1.1/8"}]`, // 非法 CIDR
		`[{"field":"header","op":"eq","value":"x"}]`,  // header 缺名称
		`[{"field":"path","op":"contains","value":""}]`, // contains 空值
	}
	for _, c := range cases {
		if _, err := CompileRule(RuleDef{Conditions: c, Action: "block"}); err == nil {
			t.Errorf("应拒绝非法条件: %s", c)
		}
	}
}

func TestMatchOperators(t *testing.T) {
	in := input("10.1.2.3", "post", "/api/upload", "/api/upload?file=a.txt", "cn",
		http.Header{"X-Token": {"abc123"}, "User-Agent": {"curl/8.0"}},
		url.Values{"file": {"a.txt"}, "id": {"7"}})

	tests := []struct {
		cond string
		want bool
	}{
		{`[{"field":"ip","op":"cidr","value":"10.0.0.0/8"}]`, true},
		{`[{"field":"ip","op":"cidr","value":"192.168.0.0/16"}]`, false},
		{`[{"field":"ip","op":"eq","value":"10.1.2.3"}]`, true},
		{`[{"field":"ip","op":"in","value":"10.1.2.3,10.1.2.4"}]`, true},
		{`[{"field":"path","op":"prefix","value":"/api"}]`, true},
		{`[{"field":"path","op":"suffix","value":".php"}]`, false},
		{`[{"field":"url","op":"contains","value":"file="}]`, true},
		{`[{"field":"method","op":"eq","value":"POST"}]`, true},
		{`[{"field":"method","op":"in","value":"get,post"}]`, true},
		{`[{"field":"country","op":"eq","value":"CN"}]`, true},
		{`[{"field":"country","op":"in","value":"us,cn,jp"}]`, true},
		{`[{"field":"header","op":"eq","name":"X-Token","value":"abc123"}]`, true},
		{`[{"field":"header","op":"contains","name":"User-Agent","value":"curl"}]`, true},
		{`[{"field":"header","op":"eq","name":"X-Missing","value":""}]`, true},
		{`[{"field":"param","op":"eq","name":"id","value":"7"}]`, true},
		{`[{"field":"param","op":"regex","name":"file","value":"\\.txt$"}]`, true},
		{`[{"field":"path","op":"regex","value":"^/api/(upload|download)$"}]`, true},
		{`[{"field":"path","op":"ne","value":"/api/upload"}]`, false},
	}
	for _, tc := range tests {
		cr := mustCompile(t, "and", tc.cond, "block")
		if got := cr.Match(in); got != tc.want {
			t.Errorf("%s => %v, 期望 %v", tc.cond, got, tc.want)
		}
	}
}

func TestMatchLogicAndOr(t *testing.T) {
	in := input("10.1.2.3", "GET", "/admin", "/admin", "US", nil, nil)
	andConds := `[{"field":"path","op":"prefix","value":"/admin"},{"field":"country","op":"eq","value":"CN"}]`
	andRule := mustCompile(t, "and", andConds, "block")
	if andRule.Match(in) {
		t.Error("and：国家不符应不命中")
	}
	orRule := mustCompile(t, "or", andConds, "block")
	if !orRule.Match(in) {
		t.Error("or：路径符合应命中")
	}
}

func TestMatchRulePriority(t *testing.T) {
	low := mustCompile(t, "and", `[{"field":"path","op":"prefix","value":"/"}]`, "log")
	low.ID, low.Priority = 1, 200
	high := mustCompile(t, "and", `[{"field":"path","op":"prefix","value":"/"}]`, "block")
	high.ID, high.Priority = 2, 50
	rules := []CompiledRule{low, high} // 未排序，MatchRule 取切片首个命中
	in := input("1.1.1.1", "GET", "/", "/", "", nil, nil)
	if got := MatchRule(rules, in); got == nil || got.ID != 1 {
		t.Error("MatchRule 应返回切片中首个命中规则（调用方负责按优先级排序）")
	}
}

func TestEmptyConditionsNeverMatch(t *testing.T) {
	cr := CompiledRule{Logic: "and", Action: "block"}
	if cr.Match(input("1.1.1.1", "GET", "/", "/", "", nil, nil)) {
		t.Error("无条件规则不应命中，避免误配全局拦截")
	}
}