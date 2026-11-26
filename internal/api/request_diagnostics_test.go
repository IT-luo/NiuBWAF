package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"niubwaf/internal/proxy"
)

func TestHistoricalRequestDiagnosticsUseFinalEventWithoutRawData(t *testing.T) {
	a := fullTestAPI(t)
	const id = "0123456789ab"
	for _, status := range []int{413, 200} {
		if _, err := a.Store.DB.Exec(`INSERT INTO attack_logs(domain, method, url, action, status, msg, req_id)
			VALUES('history.test', 'POST', '/?token=example-private-credential', 'waf', ?, 'example-private-credential', ?)`, status, id); err != nil {
			t.Fatal(err)
		}
	}
	res := httptest.NewRecorder()
	a.requestDiagnostics(res, httptest.NewRequest(http.MethodGet, "/api/request-diagnostics?id="+id, nil))
	if res.Code != http.StatusOK {
		t.Fatalf("历史请求诊断返回 %d", res.Code)
	}
	if strings.Contains(res.Body.String(), "example-private-credential") {
		t.Fatal("历史请求诊断泄露原始请求内容")
	}
	var d proxy.RequestDiagnostic
	if err := json.Unmarshal(res.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if !d.Historical || d.Status != 413 || d.Source != "waf" || d.Outcome != "blocked" || d.Domain != "history.test" || d.TS.IsZero() {
		t.Fatalf("历史请求诊断数据错误: %+v", d)
	}
}
