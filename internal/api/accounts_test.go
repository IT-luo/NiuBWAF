package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestConsoleViewerPermissionsAndRevocation(t *testing.T) {
	a := hardenAPI(t)
	setTestAdminPass(a, "RootTest9")
	h := a.Handler(http.NotFoundHandler())
	root, _ := loginCookie(t, h, "RootTest9")
	rootCSRF := csrfToken(t, h, root)
	request := func(method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		req := testJSONRequest(method, path, body)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		req.Header.Set("X-NiuB-CSRF", csrf)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	res := request("POST", "/api/accounts", `{"username":"reviewer","role":"viewer","password":"TempTest9"}`, root, rootCSRF)
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "TempTest9") {
		t.Fatalf("creating a viewer returned %d", res.Code)
	}
	res = request("POST", "/api/login", `{"username":"reviewer","password":"TempTest9"}`, nil, "")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"must_change":true`) {
		t.Fatalf("first login returned %d", res.Code)
	}
	viewer := adminCookie(t, res)
	token := csrfToken(t, h, viewer)
	if got := request("GET", "/api/logs", "", viewer, token).Code; got != http.StatusForbidden {
		t.Fatalf("viewer with temporary password got log status %d", got)
	}
	res = request("PUT", "/api/password", `{"old":"TempTest9","new":"ChangedTest8"}`, viewer, token)
	if res.Code != http.StatusOK {
		t.Fatalf("viewer password change returned %d", res.Code)
	}
	viewer = adminCookie(t, res)
	token = csrfToken(t, h, viewer)
	if got := request("PUT", "/api/settings", `{"semantic_mode":"off"}`, viewer, token).Code; got != http.StatusForbidden {
		t.Fatalf("viewer write returned %d", got)
	}
	if got := request("GET", "/api/ips", "", viewer, token).Code; got != http.StatusOK {
		t.Fatalf("viewer read returned %d", got)
	}
	if got := request("PUT", "/api/accounts/reviewer", `{"enabled":false}`, root, rootCSRF).Code; got != http.StatusOK {
		t.Fatalf("admin disabling account returned %d", got)
	}
	if got := request("GET", "/api/me", "", viewer, token).Code; got != http.StatusUnauthorized {
		t.Fatalf("disabled account retained access, got %d", got)
	}
}

func TestAuditFeedBearerAndCursor(t *testing.T) {
	a := hardenAPI(t)
	setTestAdminPass(a, "RootTest9")
	h := a.Handler(http.NotFoundHandler())
	root, _ := loginCookie(t, h, "RootTest9")
	const token = "unit-test-audit-feed-token-1"
	setup := testJSONRequest("PUT", "/api/audit/feed", `{"token":"`+token+`"}`)
	setup.AddCookie(root)
	setup.Header.Set("X-NiuB-CSRF", csrfToken(t, h, root))
	cfg := httptest.NewRecorder()
	h.ServeHTTP(cfg, setup)
	if cfg.Code != http.StatusOK || strings.Contains(cfg.Body.String(), token) {
		t.Fatalf("audit setting returned %d", cfg.Code)
	}
	run := func(after, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/audit/events?limit=1&after_id="+after, nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if res := run("0", ""); res.Code != http.StatusUnauthorized {
		t.Fatalf("unqualified feed returned %d", res.Code)
	}
	first := run("0", token)
	var item struct{ ID int64 }
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &item) != nil || item.ID < 1 {
		t.Fatalf("unexpected first audit item: %d %s", first.Code, first.Body)
	}
	cursor := first.Header().Get("X-NiuB-Audit-Next-ID")
	if cursor != strconv.FormatInt(item.ID, 10) {
		t.Fatalf("cursor %s does not match first item %d", cursor, item.ID)
	}
	second := run(cursor, token)
	var next struct{ ID int64 }
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &next) != nil || next.ID <= item.ID {
		t.Fatalf("cursor did not advance: %d %s", second.Code, second.Body)
	}
}
