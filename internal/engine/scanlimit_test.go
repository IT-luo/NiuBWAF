package engine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

const mpBoundary = "----niuBboundary7d4a1b2c3e"

// multipartPayload 构造真实形态的 multipart 请求体：一个表单字段 + 一个大文件分片
func multipartPayload(fileSize int, firstField string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n%s\r\n", mpBoundary, firstField)
	fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n", mpBoundary)
	b.Write(bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01, 0x0a, 0x3b, 0x22, 0x27}, fileSize/8))
	fmt.Fprintf(&b, "\r\n--%s--\r\n", mpBoundary)
	return b.Bytes()
}

func hdr(ct string, n int) map[string][]string {
	return map[string][]string{
		"Host":           {"bench.local"},
		"Content-Type":   {ct},
		"Content-Length": {fmt.Sprintf("%d", n)},
	}
}

// 大体积请求体只送检前缀，且截断不得触发解析类误报（200002/200003）
func TestOversizeBodyTruncatedNoFalsePositive(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("引擎初始化失败: %v", err)
	}
	e.SetScanLimit(128 << 10)
	mpCT := "multipart/form-data; boundary=" + mpBoundary

	// 1) 3MB 文件上传：只送检前 128KB，必须放行（此前被 200003 误拦 400）
	big := multipartPayload(3<<20, "hello")
	res := e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/upload", Proto: "HTTP/1.1", Headers: hdr(mpCT, len(big)), Body: big})
	if res.Blocked {
		t.Errorf("大文件上传不应被拦截: rule=%d msg=%s", res.RuleID, res.Msg)
	}

	// 2) 截断后仍要能检出前缀里的攻击载荷
	atk := multipartPayload(3<<20, "' UNION SELECT username,password FROM users-- -")
	res2 := e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/upload", Proto: "HTTP/1.1", Headers: hdr(mpCT, len(atk)), Body: atk})
	if !res2.Blocked {
		t.Error("前缀中的 SQL 注入应被拦截")
	}

	// 3) 未截断的畸形 multipart（缺少闭合边界）仍须严格校验拦截
	small := []byte(fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nx\r\n", mpBoundary))
	res3 := e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/upload", Proto: "HTTP/1.1", Headers: hdr(mpCT, len(small)), Body: small})
	if !res3.Blocked {
		t.Error("未截断的畸形 multipart 应被严格校验拦截")
	}

	// 4) 超大 urlencoded（截断落在 % 转义中间）不应误报
	ue := []byte("a=" + strings.Repeat("A", (300<<10)-1) + "%")
	res4 := e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/upload", Proto: "HTTP/1.1", Headers: hdr("application/x-www-form-urlencoded", len(ue)), Body: ue})
	if res4.Blocked {
		t.Errorf("截断的 urlencoded 不应被拦截: rule=%d msg=%s", res4.RuleID, res4.Msg)
	}

	// 5) 超大 urlencoded 前缀中的 SQL 注入仍要拦截
	ue2 := []byte("a=' UNION SELECT 1,2,3-- -&pad=" + strings.Repeat("A", 300<<10))
	res5 := e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/upload", Proto: "HTTP/1.1", Headers: hdr("application/x-www-form-urlencoded", len(ue2)), Body: ue2})
	if !res5.Blocked {
		t.Error("urlencoded 前缀中的 SQL 注入应被拦截")
	}

	// 6) 超大 JSON（截断后非法）不应误报，且前缀攻击仍可检出
	js := []byte(`{"k":"` + strings.Repeat("A", 300<<10) + `"}`)
	res6 := e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/api", Proto: "HTTP/1.1", Headers: hdr("application/json", len(js)), Body: js})
	if res6.Blocked {
		t.Errorf("截断的 JSON 不应被拦截: rule=%d msg=%s", res6.RuleID, res6.Msg)
	}
	js2 := []byte(`{"q":"<script>alert(document.cookie)</script>","pad":"` + strings.Repeat("A", 300<<10) + `"}`)
	res7 := e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/api", Proto: "HTTP/1.1", Headers: hdr("application/json", len(js2)), Body: js2})
	if !res7.Blocked {
		t.Error("JSON 前缀中的 XSS 应被拦截")
	}
}

// 送检上限必须真正约束检测成本：超大请求体的检测耗时不得随体积线性增长
func TestScanLimitBoundsCost(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("引擎初始化失败: %v", err)
	}
	e.SetScanLimit(128 << 10)
	detect := func(size int) time.Duration {
		body := bytes.Repeat([]byte("A"), size)
		st := time.Now()
		e.Detect("balanced", nil, &RequestInfo{ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/upload", Proto: "HTTP/1.1",
			Headers: hdr("application/x-www-form-urlencoded", len(body)), Body: body})
		return time.Since(st)
	}
	small := detect(128 << 10)
	huge := detect(8 << 20)
	t.Logf("128KB=%v 8MB=%v", small, huge)
	// 未截断时 8MB 约需 36 秒 CPU；截断后应与 128KB 同量级
	if huge > 5*time.Second {
		t.Errorf("8MB 请求体检测耗时 %v 超过 5s，送检上限未生效", huge)
	}
	if huge > small*8+time.Second {
		t.Errorf("8MB(%v) 相对 128KB(%v) 耗时异常，检测成本仍随体积增长", huge, small)
	}
}

func TestSetScanLimitValidation(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("引擎初始化失败: %v", err)
	}
	for _, v := range []int{0, -1} {
		e.SetScanLimit(v)
		if got := e.ScanLimit(); got != defaultScanLimit {
			t.Errorf("非法送检上限 %d 应回落默认值, got %d", v, got)
		}
	}
	e.SetScanLimit(64 << 10)
	if got := e.ScanLimit(); got != 64<<10 {
		t.Errorf("应生效 64KB, got %d", got)
	}
	e.SetScanLimit(4 << 20)
	if got := e.ScanLimit(); got != maxScanLimit {
		t.Errorf("超过硬上限应被钳制到 %d, got %d", maxScanLimit, got)
	}
}
