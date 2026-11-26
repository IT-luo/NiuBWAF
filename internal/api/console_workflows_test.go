package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"niubwaf/internal/store"
)

func TestConsoleIngressWorkflowAndRequestLookup(t *testing.T) {
	a := fullTestAPI(t)
	const domain = "acceptance.test"
	const entry = "http://" + domain + ":9080/"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-NiuB-Ingress-Verify") != "" {
			t.Error("verification credential reached the origin")
		}
		_, _ = w.Write([]byte("origin ready"))
	}))
	t.Cleanup(origin.Close)
	site := &store.Site{Name: "acceptance", Domain: domain, Upstream: origin.URL, Enabled: true, WAFMode: "balanced"}
	if err := a.Store.CreateSite(site); err != nil {
		t.Fatal(err)
	}
	a.Proxy.Reload()

	setTestAdminPass(a, "RootTest9")
	console := a.Handler(http.NotFoundHandler())
	cookie, _ := loginCookie(t, console, "RootTest9")
	csrf := csrfToken(t, console, cookie)
	management := func(method, path, body string, authorized bool) *httptest.ResponseRecorder {
		t.Helper()
		req := testJSONRequest(method, path, body)
		if authorized {
			req.AddCookie(cookie)
			req.Header.Set("X-NiuB-CSRF", csrf)
		}
		rec := httptest.NewRecorder()
		console.ServeHTTP(rec, req)
		return rec
	}
	endpoint := fmt.Sprintf("/api/sites/%d/ingress-verification", site.ID)
	const startBody = `{"scheme":"http","port":9080,"path":"/","source":"external"}`
	if rec := management(http.MethodPost, endpoint, startBody, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated challenge creation returned %d", rec.Code)
	}
	if permitConsoleRequest(roleViewer, http.MethodPost, endpoint) || !permitConsoleRequest(roleViewer, http.MethodGet, endpoint) {
		t.Fatal("viewer must be able to read results only")
	}
	start := management(http.MethodPost, endpoint, startBody, true)
	var challenge struct {
		Header string `json:"header"`
		Pass   string `json:"pass_token"`
		Block  string `json:"block_token"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &challenge); err != nil || start.Code != http.StatusOK || challenge.Header == "" || challenge.Pass == "" || challenge.Block == "" {
		t.Fatalf("cannot start ingress verification: HTTP %d, %v", start.Code, err)
	}
	probe := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, entry, nil)
		req.Header.Set(challenge.Header, token)
		rec := httptest.NewRecorder()
		a.Proxy.ServeHTTP(rec, req)
		return rec
	}
	pass := probe(challenge.Pass)
	if pass.Code != http.StatusOK || pass.Body.String() != "origin ready" {
		t.Fatalf("normal request did not reach the origin: HTTP %d", pass.Code)
	}
	block := probe(challenge.Block)
	if block.Code != http.StatusForbidden || block.Header().Get("X-NiuB-WAF") != "blocked" {
		t.Fatalf("test block returned HTTP %d", block.Code)
	}
	for _, path := range []string{endpoint, "/api/sites"} {
		rec := management(http.MethodGet, path, "", true)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, `"verified":true`) || strings.Contains(body, challenge.Pass) || strings.Contains(body, challenge.Block) {
			t.Fatalf("unexpected verification report from %s: HTTP %d", path, rec.Code)
		}
	}
	requestID := pass.Header().Get("X-NiuB-WAF-Req-ID")
	tracePath := "/api/request-diagnostics?id=" + requestID
	if rec := management(http.MethodGet, tracePath, "", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated diagnostics returned %d", rec.Code)
	}
	trace := management(http.MethodGet, tracePath, "", true)
	var diag struct {
		RequestID      string `json:"req_id"`
		Source         string `json:"source"`
		UpstreamStatus int    `json:"upstream_status"`
	}
	if err := json.Unmarshal(trace.Body.Bytes(), &diag); err != nil || trace.Code != http.StatusOK || requestID == "" || diag.RequestID != requestID || diag.Source != "origin" || diag.UpstreamStatus != http.StatusOK {
		t.Fatalf("unexpected request trace: HTTP %d, %s", trace.Code, trace.Body)
	}
}
