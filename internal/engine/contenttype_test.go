package engine

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func plainReq(body string) *RequestInfo {
	h := http.Header{}
	h.Set("Host", "test.local")
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	h.Set("Accept", "*/*")
	h.Set("Content-Type", "text/plain")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	return &RequestInfo{
		ClientIP: "1.2.3.4", ServerIP: "127.0.0.1",
		Method: "POST", URL: "/api/ingest", Proto: "HTTP/1.1",
		Headers: h, Body: []byte(body),
	}
}

func TestParseContentTypes(t *testing.T) {
	got := ParseContentTypes(" Text/Plain ,application/octet-stream,text/plain, json")
	// "json" 无斜杠属非法项应丢弃，重复项去重，结果按字典序
	want := []string{"application/octet-stream", "text/plain"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ParseContentTypes = %v, want %v", got, want)
	}
	for _, bad := range []string{`text/plain| |x"`, `text/ plain`, `text/'plain`, `application/json; charset=utf-8`, `/json`, `json/`, `a//b`} {
		if out := ParseContentTypes(bad); len(out) != 0 {
			t.Fatalf("非法项 %q 应被丢弃, got %v", bad, out)
		}
	}
	// CRS 默认类型不应重复追加
	if out := ParseContentTypes("application/json,multipart/form-data"); len(out) != 0 {
		t.Fatalf("CRS 默认类型应被去重, got %v", out)
	}
	if out := ParseContentTypes(""); len(out) != 0 {
		t.Fatalf("空配置应返回 nil, got %v", out)
	}
	if out := ParseContentTypes(strings.Repeat("application/vnd.x, ", 60)); len(out) != 1 {
		t.Fatalf("重复合法项应去重为 1 项, got %d 项", len(out))
	}
}

func TestAllowedContentTypesOverridesCRS920420(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	res := e.Detect("balanced", nil, plainReq("hello world"))
	if !res.Blocked || res.RuleID != 920420 {
		t.Fatalf("默认应被 920420 拦截 text/plain 请求体, got blocked=%v rule=%d msg=%s", res.Blocked, res.RuleID, res.Msg)
	}

	if err := e.SetContentTypes(ParseContentTypes("text/plain")); err != nil {
		t.Fatalf("SetContentTypes 失败: %v", err)
	}
	if res := e.Detect("balanced", nil, plainReq("hello world")); res.Blocked {
		t.Fatalf("追加 text/plain 后应放行, got rule=%d msg=%s", res.RuleID, res.Msg)
	}
	if res := e.Detect("strict", nil, plainReq("hello world")); res.Blocked {
		t.Fatalf("strict 模式同样应放行, got rule=%d msg=%s", res.RuleID, res.Msg)
	}
	// 放行 text/plain 后，请求体命令注入仍须被自定义规则拦截
	if res := e.Detect("balanced", nil, plainReq("ok;cat /etc/passwd")); !res.Blocked {
		t.Fatal("text/plain 请求体中的命令注入仍应被拦截")
	}
	// 幂等：相同配置不应重建失败或改变行为
	if err := e.SetContentTypes(ParseContentTypes("text/plain")); err != nil {
		t.Fatalf("重复设置失败: %v", err)
	}
	if res := e.Detect("balanced", nil, plainReq("hello world")); res.Blocked {
		t.Fatalf("重复设置后仍应放行, got rule=%d", res.RuleID)
	}
	// 表单编码检测不受影响
	h := http.Header{}
	h.Set("Host", "test.local")
	h.Set("User-Agent", "Mozilla/5.0")
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	sqli := e.Detect("balanced", nil, &RequestInfo{
		ClientIP: "1.2.3.4", ServerIP: "127.0.0.1", Method: "POST", URL: "/login", Proto: "HTTP/1.1",
		Headers: h, Body: []byte("username=admin'--&password=x"),
	})
	if !sqli.Blocked {
		t.Fatal("表单 SQLi 应继续被拦截")
	}

	// 清空恢复 CRS 默认白名单
	if err := e.SetContentTypes(nil); err != nil {
		t.Fatalf("清空白名单失败: %v", err)
	}
	if res := e.Detect("balanced", nil, plainReq("hello world")); !res.Blocked || res.RuleID != 920420 {
		t.Fatalf("清空后应恢复 920420 拦截, got blocked=%v rule=%d", res.Blocked, res.RuleID)
	}
	// 重建后豁免引擎（variants）仍应携带当前白名单并可移除规则
	if res := e.Detect("balanced", []Exclusion{{RuleID: 920420}}, plainReq("hello world")); res.Blocked {
		t.Fatalf("豁免 920420 后应放行, got rule=%d msg=%s", res.RuleID, res.Msg)
	}
}
