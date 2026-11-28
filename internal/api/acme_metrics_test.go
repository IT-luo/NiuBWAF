package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"niubwaf/internal/store"
)

func metricsTestAPI(t *testing.T) *API {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &API{Store: st}
}

func TestMetricsTokenAuth(t *testing.T) {
	a := metricsTestAPI(t)
	a.Store.SetSetting("metrics_token", "s3cret")
	// 正确 Bearer（远端也允许）
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.RemoteAddr = "198.51.100.7:5000"
	r.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	a.metricsHandler(rec, r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "niubwaf_requests_total") {
		t.Fatalf("正确令牌应放行并输出指标: code=%d", rec.Code)
	}
	// 错误令牌
	r2 := httptest.NewRequest("GET", "/metrics", nil)
	r2.Header.Set("Authorization", "Bearer wrong")
	rec2 := httptest.NewRecorder()
	a.metricsHandler(rec2, r2)
	if rec2.Code != 401 {
		t.Errorf("错误令牌应 401, got %d", rec2.Code)
	}
	// 缺失令牌
	rec3 := httptest.NewRecorder()
	a.metricsHandler(rec3, httptest.NewRequest("GET", "/metrics", nil))
	if rec3.Code != 401 {
		t.Errorf("缺失令牌应 401, got %d", rec3.Code)
	}
}

func TestMetricsLoopbackOnlyWhenNoToken(t *testing.T) {
	a := metricsTestAPI(t)
	// 环回地址放行
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	a.metricsHandler(rec, r)
	if rec.Code != 200 {
		t.Fatalf("无令牌时本机应放行: code=%d", rec.Code)
	}
	// IPv6 环回
	r6 := httptest.NewRequest("GET", "/metrics", nil)
	r6.RemoteAddr = "[::1]:5000"
	rec6 := httptest.NewRecorder()
	a.metricsHandler(rec6, r6)
	if rec6.Code != 200 {
		t.Errorf("无令牌时 ::1 应放行: code=%d", rec6.Code)
	}
	// 非环回拒绝
	rRemote := httptest.NewRequest("GET", "/metrics", nil)
	rRemote.RemoteAddr = "198.51.100.7:5000"
	recRemote := httptest.NewRecorder()
	a.metricsHandler(recRemote, rRemote)
	if recRemote.Code != 403 {
		t.Errorf("无令牌时远端应 403, got %d", recRemote.Code)
	}
}

func TestMetricsRouteWired(t *testing.T) {
	a := metricsTestAPI(t)
	a.Store.SetSetting("metrics_token", "tok")
	console := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("console")) })
	h := a.Handler(console)
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "niubwaf_") {
		t.Fatalf("/metrics 应路由到指标处理器: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("指标 Content-Type 应为 text/plain: %s", rec.Header().Get("Content-Type"))
	}
}
