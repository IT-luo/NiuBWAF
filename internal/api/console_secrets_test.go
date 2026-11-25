package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func adminJSONRequests(t *testing.T, a *API) func(string, string, any) *httptest.ResponseRecorder {
	t.Helper()
	setTestAdminPass(a, "LocalAdmin9")
	h := a.Handler(http.NotFoundHandler())
	ck, _ := loginCookie(t, h, "LocalAdmin9")
	csrf := csrfToken(t, h, ck)
	return func(method, path string, body any) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := testJSONRequest(method, path, string(data))
		r.AddCookie(ck)
		r.Header.Set("X-NiuB-CSRF", csrf)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
}

func localCertificate(t *testing.T) (cert, key string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"site.example"}}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))),
		strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
}

func TestAdminSiteTLSWriteOnly(t *testing.T) {
	a := fullTestAPI(t)
	request := adminJSONRequests(t, a)
	cert, key := localCertificate(t)
	newCert, newKey := localCertificate(t)
	body := map[string]any{"name": "Site", "domain": "site.example", "upstream": "http://127.0.0.1:1",
		"cert_pem": cert + "\n" + key, "key_pem": key, "auth_pass": "SitePassword9"}
	assertSafe := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("site response status=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
		}
		for _, secret := range []string{`"cert_pem"`, `"key_pem"`, `"auth_pass"`, "PRIVATE KEY", "SitePassword9"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("site response includes %q", secret)
			}
		}
	}
	created := request(http.MethodPost, "/api/sites", body)
	assertSafe(created)
	var result consoleSite
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || !result.TLSConfigured || result.ID <= 0 {
		t.Fatalf("invalid create response: %v", err)
	}
	lst := request(http.MethodGet, "/api/sites", nil)
	assertSafe(lst)
	if !strings.Contains(lst.Body.String(), `"tls_configured":true`) {
		t.Fatal("site list omitted TLS configuration status")
	}

	path := "/api/sites/" + strconv.FormatInt(result.ID, 10)
	delete(body, "auth_pass")
	delete(body, "cert_pem")
	delete(body, "key_pem")
	body["name"] = "Edited"
	assertSafe(request(http.MethodPut, path, body))
	current, err := a.Store.GetSite(result.ID)
	if err != nil || current.Name != "Edited" || current.KeyPEM != key || current.AuthPass == "" {
		t.Fatalf("regular update did not preserve credentials: %v", err)
	}
	body["cert_pem"], body["key_pem"] = newCert, key
	if rec := request(http.MethodPut, path, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched pair accepted: %d", rec.Code)
	}
	body["key_pem"] = newKey
	assertSafe(request(http.MethodPut, path, body))
	current, err = a.Store.GetSite(result.ID)
	if err != nil || current.KeyPEM != newKey || current.CertPEM != newCert {
		t.Fatalf("TLS certificate did not rotate: %v", err)
	}
	delete(body, "cert_pem")
	delete(body, "key_pem")
	body["clear_tls"] = true
	cleared := request(http.MethodPut, path, body)
	assertSafe(cleared)
	current, err = a.Store.GetSite(result.ID)
	if err != nil || current.KeyPEM != "" || current.CertPEM != "" || !strings.Contains(cleared.Body.String(), `"tls_configured":false`) {
		t.Fatalf("explicit TLS removal failed: %v", err)
	}
}

func TestAdminSettingsSecretsWriteOnly(t *testing.T) {
	a := fullTestAPI(t)
	request := adminJSONRequests(t, a)
	secrets := map[string]string{
		"metrics_token": "TEST_METRICS_TOKEN", "intel_api_key": "TEST_INTEL_KEY",
		"intel_api_url":  "https://example.test/ip/{ip}?token=TEST_INTEL_URL_TOKEN",
		"alert_webhook":  "http://127.0.0.1:1/hook?token=TEST_WEBHOOK_TOKEN",
		"alert_dingtalk": "https://example.test/hook?token=TEST_DINGTALK_TOKEN",
		"alert_wecom":    "https://example.test/hook?token=TEST_WECOM_TOKEN",
	}
	if rec := request(http.MethodPut, "/api/settings", secrets); rec.Code != http.StatusOK {
		t.Fatalf("could not save settings: %d", rec.Code)
	}
	if rec := request(http.MethodPut, "/api/settings", map[string]string{"log_retention_days": "60"}); rec.Code != http.StatusOK {
		t.Fatalf("could not update unrelated setting: %d", rec.Code)
	}
	rec := request(http.MethodGet, "/api/settings", nil)
	var result map[string]string
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
		t.Fatalf("invalid settings response: %d", rec.Code)
	}
	for key, value := range secrets {
		if _, ok := result[key]; ok || strings.Contains(rec.Body.String(), value) {
			t.Fatalf("settings exposed %s", key)
		}
		if result[key+"_configured"] != "true" || a.Store.GetSetting(key) != value {
			t.Fatalf("invalid state for %s", key)
		}
	}
	if rec := request(http.MethodPut, "/api/settings", map[string]string{
		"metrics_token": "", "alert_window": "invalid",
	}); rec.Code != http.StatusBadRequest || a.Store.GetSetting("metrics_token") != secrets["metrics_token"] {
		t.Fatal("rejected settings update changed the metrics token")
	}
	if rec := request(http.MethodPut, "/api/settings", map[string]string{"metrics_token": ""}); rec.Code != http.StatusOK {
		t.Fatalf("could not remove token: %d", rec.Code)
	}
	if rec := request(http.MethodGet, "/api/settings", nil); !strings.Contains(rec.Body.String(), `"metrics_token_configured":"false"`) {
		t.Fatal("metrics token status did not reflect removal")
	}
}
