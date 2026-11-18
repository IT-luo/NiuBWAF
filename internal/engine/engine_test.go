package engine

import (
	"net/http"
	"testing"
)

func TestDetect(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		method  string
		url     string
		body    string
		blocked bool
	}{
		{"normal", "GET", "/index.html?id=123", "", false},
		{"sqli", "GET", "/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", "", true},
		{"xss", "GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "", true},
		{"cmdi", "GET", "/ping?host=;cat%20/etc/passwd", "", true},
		{"traversal", "GET", "/download?file=../../../../etc/passwd", "", true},
		{"post-sqli", "POST", "/login", "username=admin'--&password=x", true},
	}
	for _, c := range cases {
		h := http.Header{}
		h.Set("Host", "test.local")
		h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		h.Set("Accept", "text/html")
		if c.body != "" {
			h.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res := e.Detect("balanced", nil, &RequestInfo{
			ClientIP: "1.2.3.4", ServerIP: "127.0.0.1",
			Method: c.method, URL: c.url, Proto: "HTTP/1.1",
			Headers: h, Body: []byte(c.body),
		})
		if res.Blocked != c.blocked {
			t.Errorf("%s: blocked=%v want=%v (rule=%d msg=%s)", c.name, res.Blocked, c.blocked, res.RuleID, res.Msg)
		} else {
			t.Logf("%s: blocked=%v rule=%d msg=%s", c.name, res.Blocked, res.RuleID, res.Msg)
		}
	}
}

func TestParanoiaLevels(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Host", "test.local")
	h.Set("User-Agent", "Mozilla/5.0")
	h.Set("Accept", "text/html")
	info := &RequestInfo{
		ClientIP: "1.2.3.4", ServerIP: "127.0.0.1",
		Method: "GET", URL: "/?q=%27%20is%20null%20%27", Proto: "HTTP/1.1", Headers: h,
	}
	if res := e.Detect("balanced", nil, info); res.Blocked {
		t.Errorf("PL2 载荷在平衡模式不应拦截: rule=%d msg=%s", res.RuleID, res.Msg)
	}
	if res := e.Detect("strict", nil, info); !res.Blocked {
		t.Errorf("PL2 载荷在严格模式应拦截（942110+942120）")
	}
}

func TestExclusions(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Host", "test.local")
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	h.Set("Accept", "text/html")
	mk := func(url string) *RequestInfo {
		return &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "127.0.0.1", Method: "GET", URL: url, Proto: "HTTP/1.1", Headers: h}
	}
	sqli := "/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
	other := "/other?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
	if res := e.Detect("balanced", nil, mk(sqli)); !res.Blocked {
		t.Fatal("基线：SQLi 应被拦截")
	}
	rules := []int{942100, 942190, 942270, 942360}
	mkExcl := func(prefix, param string) []Exclusion {
		out := make([]Exclusion, len(rules))
		for i, id := range rules {
			out[i] = Exclusion{RuleID: id, URLPrefix: prefix, Param: param}
		}
		return out
	}
	cases := []struct {
		name   string
		excl   []Exclusion
		outURL string
	}{
		{"全局豁免", mkExcl("", ""), ""},
		{"URL前缀豁免", mkExcl("/product", ""), other},
		{"参数级豁免", mkExcl("", "id"), "/product?foo=1%20UNION%20SELECT%20username,password%20FROM%20users--"},
	}
	for _, c := range cases {
		if res := e.Detect("balanced", c.excl, mk(sqli)); res.Blocked {
			t.Errorf("%s: 豁免后仍拦截 rule=%d msg=%s", c.name, res.RuleID, res.Msg)
		}
		if c.outURL != "" {
			if res := e.Detect("balanced", c.excl, mk(c.outURL)); !res.Blocked {
				t.Errorf("%s: 豁免范围外的攻击仍应拦截", c.name)
			}
		}
	}
}
func TestConfirmCodeInj(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	yes := []struct{ uri, body string }{
		{"/x", "<?php eval($_POST[cmd]);?>"},
		{"/x", "(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"},
	}
	for _, c := range yes {
		if !e.confirmCodeInj(c.uri, []byte(c.body)) {
			t.Fatalf("应确认代码注入: %q %q", c.uri, c.body)
		}
	}
	no := []struct{ uri, body string }{
		{"/list?page=2&sort=name", "quarterly revenue summary and meeting notes"},
		{"/", ""},
	}
	for _, c := range no {
		if e.confirmCodeInj(c.uri, []byte(c.body)) {
			t.Fatalf("不应确认代码注入: %q %q", c.uri, c.body)
		}
	}
}

func TestSoleDetectionRule(t *testing.T) {
	if got := soleDetectionRule(nil); got != 0 {
		t.Fatalf("空匹配应返回 0, got %d", got)
	}
}
