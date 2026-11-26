package api

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

func sharedSessionWorkers(t *testing.T) (*API, *API) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "shared.db")
	scope := store.RandToken()
	open := func() *API {
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Close)
		a := New(st, &proxy.Proxy{Hub: proxy.NewHub()})
		a.ConsoleSessionScope = scope
		return a
	}
	a := open()
	setTestAdminPass(a, "TestPassword123")
	return a, open()
}

func TestSharedConsoleSessionHandoffAndPasswordChange(t *testing.T) {
	old, replacement := sharedSessionWorkers(t)
	oldHandler := old.Handler(http.NotFoundHandler())
	replacementHandler := replacement.Handler(http.NotFoundHandler())
	cookie, _ := loginCookie(t, oldHandler, "TestPassword123")
	csrf := csrfToken(t, oldHandler, cookie)
	if got := csrfToken(t, replacementHandler, cookie); got != csrf {
		t.Fatal("CSRF token changed between generations")
	}
	var digest []byte
	if err := replacement.Store.DB.QueryRow(`SELECT token FROM console_sessions`).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if len(digest) != 32 || bytes.Equal(digest, []byte(cookie.Value)) {
		t.Fatal("database did not store a digest of the session cookie")
	}
	request := func(handler http.Handler, method, url, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		req := testJSONRequest(method, url, body)
		req.AddCookie(cookie)
		req.Header.Set("X-NiuB-CSRF", csrf)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	restart := New(replacement.Store, nil)
	restart.ConsoleSessionScope = store.RandToken()
	if rec := request(restart.Handler(http.NotFoundHandler()), "GET", "/api/me", "", cookie, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cold start accepted a cookie from an earlier supervisor: %d", rec.Code)
	}
	rec := request(replacementHandler, "PUT", "/api/password", `{"old":"TestPassword123","new":"Replacement123"}`, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("password change on replacement: %d %s", rec.Code, rec.Body.String())
	}
	newCookie := adminCookie(t, rec)
	if rec := request(oldHandler, "GET", "/api/me", "", cookie, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old generation still accepts revoked cookie: %d", rec.Code)
	}
	loginCookie(t, oldHandler, "Replacement123")
	csrf = csrfToken(t, replacementHandler, newCookie)
	if rec := request(oldHandler, "POST", "/api/logout", "", newCookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("logout on older generation: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request(replacementHandler, "GET", "/api/me", "", newCookie, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replacement still accepts logged-out cookie: %d", rec.Code)
	}
}

func TestSharedConsoleEventStreamChecksRevocation(t *testing.T) {
	old, replacement := sharedSessionWorkers(t)
	oldHandler := old.Handler(http.NotFoundHandler())
	cookie, _ := loginCookie(t, oldHandler, "TestPassword123")
	replacementHandler := replacement.Handler(http.NotFoundHandler())
	csrf := csrfToken(t, replacementHandler, cookie)
	server := httptest.NewServer(oldHandler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("initial stream status: %d", res.StatusCode)
	}
	scanner := bufio.NewScanner(res.Body)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "hello") {
		t.Fatal("missing stream handshake")
	}
	logout := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logout.AddCookie(cookie)
	logout.Header.Set("X-NiuB-CSRF", csrf)
	rec := httptest.NewRecorder()
	replacementHandler.ServeHTTP(rec, logout)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout on replacement failed: %d", rec.Code)
	}
	old.Proxy.Hub.Broadcast(map[string]string{"type": "after-logout"})
	for scanner.Scan() {
		if scanner.Text() != "" {
			t.Fatalf("revoked stream sent %q", scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("revoked stream did not close: %v", err)
	}
}

func TestSharedSessionCannotUseOutdatedAccount(t *testing.T) {
	old, replacement := sharedSessionWorkers(t)
	account := store.ConsoleAccount{Username: "fixture", Role: roleAdmin, Enabled: true, PasswordHash: store.HashPass("FixturePassword123")}
	if err := old.Store.CreateConsoleAccount(account); err != nil {
		t.Fatal(err)
	}
	identity := consoleIdentity{Username: account.Username, Role: account.Role}
	cookie, err := old.createConsoleSession(identity, account.PasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	account.Role = roleViewer
	if err := replacement.Store.UpdateConsoleAccount(account); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Store.ConsoleSession(old.ConsoleSessionScope, cookie); err == nil {
		t.Fatal("session from before the role change is active")
	}
	if _, err := old.createConsoleSession(identity, account.PasswordHash); err == nil {
		t.Fatal("older worker could issue a session for the previous role")
	}
}
