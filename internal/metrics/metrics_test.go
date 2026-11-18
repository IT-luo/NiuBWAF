package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounterVecRender(t *testing.T) {
	r := New()
	r.IncRequest("a.com", "allowed")
	r.IncRequest("a.com", "allowed")
	r.IncRequest("a.com", "blocked")
	r.IncAttack("waf")
	out := r.Render()
	if !strings.Contains(out, "# TYPE niubwaf_requests_total counter") {
		t.Fatalf("缺少 requests TYPE: %s", out)
	}
	if !strings.Contains(out, `niubwaf_requests_total{result="allowed",site="a.com"} 2`) {
		t.Errorf("allowed 计数应为 2: %s", out)
	}
	if !strings.Contains(out, `niubwaf_requests_total{result="blocked",site="a.com"} 1`) {
		t.Errorf("blocked 计数应为 1: %s", out)
	}
	if !strings.Contains(out, `niubwaf_attacks_total{action="waf"} 1`) {
		t.Errorf("attack 计数错误: %s", out)
	}
}

func TestHistogramCumulative(t *testing.T) {
	r := New()
	r.ObserveDuration(0.001) // <=0.005
	r.ObserveDuration(0.02)  // <=0.025
	r.ObserveDuration(3)     // <=5
	out := r.Render()
	// 累积桶：0.005 含 1，0.025 含 2，5 含 3，+Inf 含 3
	for _, want := range []string{
		`niubwaf_request_duration_seconds_bucket{le="0.005"} 1`,
		`niubwaf_request_duration_seconds_bucket{le="0.025"} 2`,
		`niubwaf_request_duration_seconds_bucket{le="5"} 3`,
		`niubwaf_request_duration_seconds_bucket{le="+Inf"} 3`,
		`niubwaf_request_duration_seconds_count 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("缺少 %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, "niubwaf_request_duration_seconds_sum 3.021") {
		t.Errorf("sum 应为 3.021: %s", out)
	}
}

func TestUpstreamReplaceRemovesStale(t *testing.T) {
	r := New()
	r.SetUpstreams([]UpstreamSample{{Site: "a.com", URL: "http://u1", Up: true}, {Site: "a.com", URL: "http://u2", Up: false}})
	out := r.Render()
	if !strings.Contains(out, `niubwaf_upstream_up{site="a.com",url="http://u1"} 1`) || !strings.Contains(out, `niubwaf_upstream_up{site="a.com",url="http://u2"} 0`) {
		t.Fatalf("上游 gauge 初始渲染错误: %s", out)
	}
	// u2 消失后应被清除
	r.SetUpstreams([]UpstreamSample{{Site: "a.com", URL: "http://u1", Up: false}})
	out = r.Render()
	if strings.Contains(out, "http://u2") {
		t.Errorf("旧上游序列应被替换清除: %s", out)
	}
	if !strings.Contains(out, `niubwaf_upstream_up{site="a.com",url="http://u1"} 0`) {
		t.Errorf("上游状态应更新为 0: %s", out)
	}
}

func TestGaugesAndBytes(t *testing.T) {
	r := New()
	r.SetRepBanned(7)
	r.AddResponseBytes(100)
	r.AddResponseBytes(50)
	r.AddResponseBytes(-5) // 负值忽略
	out := r.Render()
	if !strings.Contains(out, "niubwaf_reputation_banned 7") {
		t.Errorf("信誉封禁 gauge 错误: %s", out)
	}
	if !strings.Contains(out, "niubwaf_response_bytes_total 150") {
		t.Errorf("响应字节累计应为 150: %s", out)
	}
	if !strings.Contains(out, "niubwaf_build_info{version=\"1.0\",goversion=") {
		t.Errorf("缺少 build_info: %s", out)
	}
}

func TestLabelEscaping(t *testing.T) {
	got := encodeLabels([]string{"site"}, []string{`a"b\c` + "\n"})
	want := `{site="a\"b\\c\n"}`
	if got != want {
		t.Errorf("标签转义错误: got %q want %q", got, want)
	}
	if encodeLabels(nil, nil) != "" {
		t.Error("无标签应返回空串")
	}
}

func TestHandlerContentType(t *testing.T) {
	r := New()
	r.IncRequest("x.com", "allowed")
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type 错误: %s", ct)
	}
	if !strings.Contains(rec.Body.String(), "niubwaf_requests_total") {
		t.Error("Handler 应输出指标体")
	}
}

func TestConcurrentInc(t *testing.T) {
	r := New()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 1000; j++ {
				r.IncRequest("c.com", "allowed")
				r.ObserveDuration(0.01)
				r.IncAttack("cc")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	out := r.Render()
	if !strings.Contains(out, `niubwaf_requests_total{result="allowed",site="c.com"} 8000`) {
		t.Errorf("并发计数应为 8000: %s", out)
	}
	if !strings.Contains(out, "niubwaf_request_duration_seconds_count 8000") {
		t.Errorf("并发时延计数应为 8000: %s", out)
	}
}