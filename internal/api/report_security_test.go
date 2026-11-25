package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"niubwaf/internal/store"
)

func TestReportEscapesStoredFields(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.CreateSite(&store.Site{
		Name:     "bad<img src=x onerror=alert(1)>",
		Domain:   "report.test",
		Upstream: "http://127.0.0.1/<script>alert(2)</script>",
		WAFMode:  "balanced",
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	New(st, nil).report(rec, httptest.NewRequest("GET", "/api/report", nil))
	body := rec.Body.String()
	for _, raw := range []string{"<img src=x onerror=alert(1)>", "<script>alert(2)</script>"} {
		if strings.Contains(body, raw) {
			t.Fatalf("报告包含未转义字段 %q", raw)
		}
	}
	for _, escaped := range []string{"&lt;img src=x onerror=alert(1)&gt;", "&lt;script&gt;alert(2)&lt;/script&gt;"} {
		if !strings.Contains(body, escaped) {
			t.Fatalf("报告缺少转义文本 %q", escaped)
		}
	}
}
