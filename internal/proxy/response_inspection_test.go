package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"niubwaf/internal/metrics"
	"niubwaf/internal/store"
)

func TestResponseInspectionPreservesPayloadAndReportsCoverage(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(zw, "small test response")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	large := strings.Repeat("a", 20<<10)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gzip":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(compressed.Bytes())
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: test\n\n")
		default:
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, large)
		}
	}))
	defer origin.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "inspection.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.CreateSite(&store.Site{Name: "fixture", Domain: "inspect.test", Upstream: origin.URL, Enabled: true, WAFMode: "balanced", RespDetect: true}); err != nil {
		t.Fatal(err)
	}
	p := newBotTestProxy(t, st, origin.URL)
	for _, tc := range []struct{ route, expected, coverage string }{
		{"/gzip", compressed.String(), "complete"}, {"/events", "data: test\n\n", "stream"}, {"/large", large, "partial"},
	} {
		before := metrics.Default.ResponseInspectionCounts()[tc.coverage]
		req := httptest.NewRequest(http.MethodGet, "http://inspect.test"+tc.route, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != tc.expected {
			t.Fatalf("%s altered origin output: HTTP %d, %d bytes", tc.route, rec.Code, rec.Body.Len())
		}
		if got := metrics.Default.ResponseInspectionCounts()[tc.coverage]; got != before+1 {
			t.Fatalf("%s coverage %s: got %d, want %d", tc.route, tc.coverage, got, before+1)
		}
	}
}
