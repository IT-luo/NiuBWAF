package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"niubwaf/internal/certmgr"
)

func TestManagedCertificateAccountAPIPrivacy(t *testing.T) {
	a := fullTestAPI(t)
	a.Certificates = certmgr.New(a.Store.DB, t.TempDir(), a.Proxy.Reload, nil)
	request := adminJSONRequests(t, a)
	if permitConsoleRequest(roleOperator, http.MethodGet, "/api/certificates") ||
		permitConsoleRequest(roleViewer, http.MethodPut, "/api/certificates/accounts") {
		t.Fatal("only administrators may access managed certificates")
	}
	unauthed := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(unauthed, httptest.NewRequest(http.MethodGet, "/api/certificates", nil))
	if unauthed.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list returned %d", unauthed.Code)
	}
	credential := map[string]any{"name": "Test DNS", "provider": "alidns", "key": "CANARY_DNS_KEY", "secret": "CANARY_DNS_SECRET"}
	saved := request(http.MethodPut, "/api/certificates/accounts", credential)
	listed := request(http.MethodGet, "/api/certificates", nil)
	for _, rec := range []*httptest.ResponseRecorder{saved, listed} {
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || strings.Contains(rec.Body.String(), "CANARY_DNS") {
			t.Fatalf("unsafe account response: status=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
		}
	}
	if !strings.Contains(listed.Body.String(), "Test DNS") {
		t.Fatal("account metadata missing")
	}
	order := map[string]any{"account_id": 1, "domains": []string{"example.com", "*.example.com"}, "email": "admin@example.com", "staging": true}
	if rec := request(http.MethodPost, "/api/certificates", order); rec.Code != http.StatusBadRequest {
		t.Fatalf("request without CA terms acceptance returned %d", rec.Code)
	}
	order["accept_terms"] = true
	if rec := request(http.MethodPost, "/api/certificates", order); rec.Code != http.StatusAccepted {
		t.Fatalf("queue request returned %d: %s", rec.Code, rec.Body.String())
	}
}
