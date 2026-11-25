package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/store"
)

type capturedAlert struct {
	path    string
	payload map[string]any
}

func newAlertTestProxy(t *testing.T) *Proxy {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "alert.db"))
	if err != nil {
		t.Fatalf("open alert test store: %v", err)
	}
	t.Cleanup(st.Close)
	return &Proxy{Store: st}
}

func setAlertSetting(t *testing.T, p *Proxy, key, value string) {
	t.Helper()
	if err := p.Store.SetSetting(key, value); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

func newAlertCaptureServer(t *testing.T, statuses map[string]int) (*httptest.Server, <-chan capturedAlert) {
	t.Helper()
	requests := make(chan capturedAlert, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requests <- capturedAlert{path: r.URL.Path, payload: payload}
		status := statuses[r.URL.Path]
		if status == 0 {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func nextAlert(t *testing.T, requests <-chan capturedAlert) capturedAlert {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert request")
		return capturedAlert{}
	}
}

func alertTextContent(t *testing.T, payload map[string]any) string {
	t.Helper()
	if payload["msgtype"] != "text" {
		t.Fatalf("msgtype = %#v, want text", payload["msgtype"])
	}
	text, ok := payload["text"].(map[string]any)
	if !ok {
		t.Fatalf("text payload = %#v", payload["text"])
	}
	content, _ := text["content"].(string)
	return content
}

func TestProxyNotifyPayload(t *testing.T) {
	server, requests := newAlertCaptureServer(t, nil)
	p := newAlertTestProxy(t)
	setAlertSetting(t, p, "alert_enabled", "on")
	setAlertSetting(t, p, "alert_webhook", server.URL+"/webhook")
	setAlertSetting(t, p, "alert_dingtalk", server.URL+"/dingtalk")
	setAlertSetting(t, p, "alert_wecom", server.URL+"/wecom")

	message := "磁盘空间不足"
	fields := map[string]any{
		"severity": "critical",
		"free_mb":  128,
		"event":    "must-not-override",
		"message":  "must-not-override",
		"ts":       "must-not-override",
	}
	delivered, err := p.Notify(context.Background(), "monitor.disk_space", message, fields)
	if err != nil || !delivered {
		t.Fatalf("Notify = (%v, %v), want (true, nil)", delivered, err)
	}

	byPath := map[string]map[string]any{}
	for range 3 {
		request := nextAlert(t, requests)
		byPath[request.path] = request.payload
	}
	webhook := byPath["/webhook"]
	if webhook == nil || webhook["event"] != "monitor.disk_space" || webhook["message"] != message {
		t.Fatalf("webhook fixed fields = %#v", webhook)
	}
	if webhook["severity"] != "critical" || webhook["free_mb"] != float64(128) {
		t.Fatalf("webhook merged fields = %#v", webhook)
	}
	if ts, _ := webhook["ts"].(string); ts == "" || ts == "must-not-override" {
		t.Fatalf("webhook ts = %#v", webhook["ts"])
	}
	for _, path := range []string{"/dingtalk", "/wecom"} {
		if content := alertTextContent(t, byPath[path]); content != message {
			t.Fatalf("%s content = %q, want %q", path, content, message)
		}
	}
}

func TestAlertFailureHidesWebhookCredentials(t *testing.T) {
	p := newAlertTestProxy(t)
	setAlertSetting(t, p, "alert_webhook", "http://127.0.0.1:1/hook?token=TEST_WEBHOOK_TOKEN")
	result := p.AlertTest()["webhook"]
	if !strings.HasPrefix(result, "失败:") || strings.Contains(result, "TEST_WEBHOOK_TOKEN") {
		t.Fatal("alert test failed to redact the webhook URL")
	}
}

func TestProxyNotifyNoAvailableChannel(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		p := newAlertTestProxy(t)
		setAlertSetting(t, p, "alert_enabled", "on")
		delivered, err := p.Notify(context.Background(), "monitor.test", "test", nil)
		if delivered || err != nil {
			t.Fatalf("Notify = (%v, %v), want (false, nil)", delivered, err)
		}
	})

	t.Run("alerts disabled", func(t *testing.T) {
		server, requests := newAlertCaptureServer(t, nil)
		p := newAlertTestProxy(t)
		setAlertSetting(t, p, "alert_webhook", server.URL)
		delivered, err := p.Notify(context.Background(), "monitor.test", "test", nil)
		if delivered || err != nil {
			t.Fatalf("Notify = (%v, %v), want (false, nil)", delivered, err)
		}
		select {
		case request := <-requests:
			t.Fatalf("disabled alerts sent request: %+v", request)
		default:
		}
	})
}

func TestProxyNotifyPartialAndTotalFailure(t *testing.T) {
	server, requests := newAlertCaptureServer(t, map[string]int{"/bad": http.StatusInternalServerError})
	p := newAlertTestProxy(t)
	setAlertSetting(t, p, "alert_enabled", "on")
	setAlertSetting(t, p, "alert_webhook", server.URL+"/bad")
	setAlertSetting(t, p, "alert_dingtalk", server.URL+"/ok")

	delivered, err := p.Notify(context.Background(), "monitor.test", "partial", nil)
	if !delivered || err != nil {
		t.Fatalf("partial success Notify = (%v, %v), want (true, nil)", delivered, err)
	}
	for range 2 {
		_ = nextAlert(t, requests)
	}

	setAlertSetting(t, p, "alert_dingtalk", server.URL+"/bad")
	setAlertSetting(t, p, "alert_wecom", server.URL+"/bad")
	delivered, err = p.Notify(context.Background(), "monitor.test", "failed", nil)
	if delivered || err == nil {
		t.Fatalf("total failure Notify = (%v, %v), want (false, error)", delivered, err)
	}
	for _, channel := range []string{"webhook", "dingtalk", "wecom"} {
		if !strings.Contains(err.Error(), channel) {
			t.Errorf("total failure error %q does not identify %s", err, channel)
		}
	}
	for range 3 {
		_ = nextAlert(t, requests)
	}
}

func TestLegacyAlertCompatibility(t *testing.T) {
	server, requests := newAlertCaptureServer(t, map[string]int{"/bad": http.StatusInternalServerError})
	p := newAlertTestProxy(t)
	setAlertSetting(t, p, "alert_webhook", server.URL+"/webhook")
	setAlertSetting(t, p, "alert_dingtalk", server.URL+"/dingtalk")
	setAlertSetting(t, p, "alert_wecom", server.URL+"/wecom")

	message := "攻击激增测试"
	p.dispatchAlert(message, 17, 60, 5)
	byPath := map[string]map[string]any{}
	for range 3 {
		request := nextAlert(t, requests)
		byPath[request.path] = request.payload
	}
	webhook := byPath["/webhook"]
	if webhook["event"] != "attack_spike" || webhook["message"] != message ||
		webhook["count"] != float64(17) || webhook["window"] != float64(60) || webhook["threshold"] != float64(5) {
		t.Fatalf("attack webhook payload = %#v", webhook)
	}
	if ts, _ := webhook["ts"].(string); ts == "" {
		t.Fatalf("attack webhook ts = %#v", webhook["ts"])
	}
	for _, path := range []string{"/dingtalk", "/wecom"} {
		if content := alertTextContent(t, byPath[path]); content != message {
			t.Fatalf("attack %s content = %q", path, content)
		}
	}

	setAlertSetting(t, p, "alert_dingtalk", "")
	setAlertSetting(t, p, "alert_wecom", server.URL+"/bad")
	results := p.AlertTest()
	if results["webhook"] != "成功" || results["dingtalk"] != "未配置" || !strings.HasPrefix(results["wecom"], "失败: ") {
		t.Fatalf("AlertTest results = %#v", results)
	}
	testWebhook := nextAlert(t, requests)
	if testWebhook.path != "/webhook" || testWebhook.payload["event"] != "test" ||
		!strings.Contains(testWebhook.payload["message"].(string), "告警测试") || testWebhook.payload["ts"] == "" {
		t.Fatalf("AlertTest webhook = %+v", testWebhook)
	}
	testWecom := nextAlert(t, requests)
	if testWecom.path != "/bad" || !strings.Contains(alertTextContent(t, testWecom.payload), "告警测试") {
		t.Fatalf("AlertTest wecom = %+v", testWecom)
	}
}
