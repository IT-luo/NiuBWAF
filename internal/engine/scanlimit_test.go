package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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

func TestBodyMustFitScanLimit(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	e.SetScanLimit(128 << 10)
	mpCT := "multipart/form-data; boundary=" + mpBoundary
	for _, tt := range []struct {
		name, ct string
		body     []byte
		want     int
	}{
		{"multipart under limit", mpCT, multipartPayload(1<<10, "hello"), 0},
		{"multipart over limit", mpCT, multipartPayload(3<<20, "hello"), 413},
		{"multipart malformed", mpCT, []byte(fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nx\r\n", mpBoundary)), 400},
		{"form over limit", "application/x-www-form-urlencoded", []byte("a=" + strings.Repeat("A", 300<<10)), 413},
		{"JSON over limit", "application/json", []byte(`{"k":"` + strings.Repeat("A", 300<<10) + `"}`), 413},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := e.Detect("balanced", nil, &RequestInfo{
				ClientIP: "1.2.3.4", ServerIP: "5.6.7.8", Method: "POST", URL: "/upload", Proto: "HTTP/1.1",
				Headers: hdr(tt.ct, len(tt.body)), Body: tt.body,
			})
			if res.Status != tt.want || res.Blocked != (tt.want != 0) {
				t.Fatalf("检测结果 = %+v, 期望状态 %d", res, tt.want)
			}
		})
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
	// 未截断时 8MB 约需 36 秒 CPU；超限时应在扫描前拒绝
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

func TestArgumentLimitsAreEnforced(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	params := make(url.Values, 1001)
	for i := range 1001 {
		params.Set("arg"+strconv.Itoa(i), "ok")
	}
	raw := params.Encode()
	t.Run("query", func(t *testing.T) {
		r := &RequestInfo{
			ClientIP: "192.0.2.1", Method: "GET", URL: "/items?" + raw, Proto: "HTTP/1.1",
			Headers: http.Header{"Host": {"bench.local"}},
		}
		if got := e.Detect("balanced", nil, r); got.Status != http.StatusBadRequest || got.RuleID != 100010 {
			t.Fatalf("查询参数限额结果 = %+v", got)
		}
	})
	t.Run("form", func(t *testing.T) {
		r := &RequestInfo{
			ClientIP: "192.0.2.1", Method: "POST", URL: "/items", Proto: "HTTP/1.1",
			Headers: hdr("application/x-www-form-urlencoded", len(raw)), Body: []byte(raw),
		}
		if got := e.Detect("balanced", nil, r); got.Status != http.StatusBadRequest || got.RuleID != 100011 {
			t.Fatalf("请求体参数限额结果 = %+v", got)
		}
	})
	t.Run("structured JSON", func(t *testing.T) {
		fields := make(map[string]string, len(params))
		for key := range params {
			fields[key] = "ok"
		}
		body, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		r := &RequestInfo{
			ClientIP: "192.0.2.1", Method: "POST", URL: "/items", Proto: "HTTP/1.1",
			Headers: hdr("application/vnd.items+json; charset=utf-8", len(body)), Body: body,
		}
		if got := e.Detect("balanced", nil, r); got.Status != http.StatusBadRequest || got.RuleID != 100011 {
			t.Fatalf("结构化 JSON 参数限额结果 = %+v", got)
		}
	})
}
