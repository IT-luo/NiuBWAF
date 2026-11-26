package api

import (
	"bufio"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/store"
)

func TestConsoleEventStreamClosesOnRevocation(t *testing.T) {
	a := fullTestAPI(t)
	session, _ := a.issueConsoleSession(consoleIdentity{Username: rootAccount, Role: roleAdmin})
	srv := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "niub_admin", Value: session})
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream HTTP status %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "hello") {
		t.Fatal("missing stream handshake")
	}
	a.revokeConsoleSessions(rootAccount)
	for scanner.Scan() {
		if scanner.Text() != "" {
			t.Fatal("revoked stream sent additional data")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("revoked stream did not close cleanly: %v", err)
	}
}

func TestConsoleUpstreamRedactionAndReplacement(t *testing.T) {
	a := fullTestAPI(t)
	const stored = "https://fixture:legacy@upstream.example.test/service?old=marker"
	const shown = "https://upstream.example.test/service"
	site := &store.Site{Name: "fixture", Domain: "site.example.test", Upstream: stored, WAFMode: "balanced"}
	if err := a.Store.CreateSite(site); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.route(rec, httptest.NewRequest(http.MethodGet, "/api/sites", nil))
	if v := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(v, shown) || !strings.Contains(v, `"upstream_redacted":true`) || strings.Contains(v, "legacy") || strings.Contains(v, "marker") {
		t.Fatal("site list did not redact the legacy upstream")
	}
	const body = `{"name":"fixture","domain":"site.example.test","upstream":"` + shown + `","waf_mode":"balanced"`
	for _, test := range []struct{ suffix, want string }{
		{"}", stored}, {`,"replace_upstream":true}`, shown},
	} {
		rec = httptest.NewRecorder()
		a.saveSite(rec, testJSONRequest(http.MethodPut, "/api/sites", body+test.suffix), site.ID)
		got, err := a.Store.GetSite(site.ID)
		if rec.Code != http.StatusOK || err != nil || got.Upstream != test.want {
			t.Fatalf("unexpected update result: HTTP %d, %v", rec.Code, err)
		}
	}
	rec = httptest.NewRecorder()
	a.saveSite(rec, testJSONRequest(http.MethodPost, "/api/sites", strings.Replace(body+"}", shown, stored, 1)), 0)
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "legacy") {
		t.Fatal("credential-bearing upstream should be rejected without echoing it")
	}
}

func TestExportCSVProtectsMethodColumn(t *testing.T) {
	a := fullTestAPI(t)
	if _, err := a.Store.DB.Exec(`INSERT INTO attack_logs(site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id)
		VALUES(0,'site.example.test','192.0.2.1','','+1','/','custom',0,'fixture','HIGH',403,'fixture')`); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.exportCSV(rec, httptest.NewRequest(http.MethodGet, "/api/logs/export", nil))
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(rec.Body.String(), "\uFEFF"))).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][5] != "'+1" {
		t.Fatalf("method was not exported as text: %v", err)
	}
}
