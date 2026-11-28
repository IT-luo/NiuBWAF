package certmgr

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

func testCertificate(t *testing.T, serial int64, domains []string, expires time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(serial), DNSNames: domains,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expires,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestManagedCertificateRenewalUpdatesBoundSNI(t *testing.T) {
	t.Setenv("NIUBWAF_ADMIN_PASSWORD", "TestingOnly9")
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng, err := engine.New()
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.New(st, eng, proxy.NewGeoIP(dir), proxy.NewIDCMatcher(dir), proxy.NewTorList(dir), "test-only")
	t.Cleanup(p.PauseBackgroundJobs)
	m := New(st.DB, dir, p.Reload, nil)
	for _, domain := range []string{"www.example.com", "api.example.com", "uncovered.test"} {
		s := store.Site{Name: domain, Domain: domain, Upstream: "http://127.0.0.1:1", Enabled: true}
		if err := st.CreateSite(&s); err != nil {
			t.Fatal(err)
		}
	}
	const testSecret = "credential-must-not-be-disclosed"
	if err := m.SaveAccount(Account{Name: "Example DNS", Provider: "alidns"}, "test-key", testSecret); err != nil {
		t.Fatal(err)
	}
	accounts, err := m.Accounts()
	metadata, _ := json.Marshal(accounts)
	var encrypted []byte
	if err != nil || len(accounts) != 1 || bytes.Contains(metadata, []byte(testSecret)) {
		t.Fatal("unexpected account metadata")
	}
	if err := st.DB.QueryRow("SELECT credentials FROM dns_certificate_accounts").Scan(&encrypted); err != nil ||
		bytes.Contains(encrypted, []byte(testSecret)) {
		t.Fatal("DNS credentials were not saved encrypted")
	}
	serial := int64(1)
	fail := false
	m.issue = func(_ context.Context, c Certificate, provider string, cred credentials, der []byte) ([]byte, []byte, error) {
		if provider != "alidns" || cred.Secret != testSecret || len(der) == 0 {
			t.Fatal("incorrect DNS provider credentials or missing ACME account key")
		}
		if fail {
			return nil, nil, errors.New("provider rejected " + testSecret)
		}
		cert, key := testCertificate(t, serial, c.Domains, time.Now().Add(time.Duration(60+serial)*24*time.Hour))
		return cert, key, nil
	}
	process := func() {
		t.Helper()
		if worked, err := m.processNext(context.Background()); err != nil || !worked {
			t.Fatalf("task worked=%v err=%v", worked, err)
		}
	}
	if err := m.Queue(Certificate{AccountID: accounts[0].ID, Domains: []string{"example.com", "*.example.com"}, Email: "admin@example.com"}); err != nil {
		t.Fatal(err)
	}
	process()
	certs, err := m.Certificates()
	if err != nil || len(certs) != 1 || certs[0].Status != "ready" {
		t.Fatalf("certificate not ready: %+v (%v)", certs, err)
	}
	id := certs[0].ID
	sites, err := st.ListSites()
	if err != nil || len(sites) != 3 {
		t.Fatalf("test sites: %v", err)
	}
	var bound []store.Site
	for _, s := range sites {
		err := m.Bind(s.ID, id)
		if s.Domain == "uncovered.test" {
			if err == nil {
				t.Fatal("certificate bound to an uncovered domain")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		bound = append(bound, s)
	}
	tlsConfig := p.TLSConfig()
	checkSerial := func(expected int64) {
		t.Helper()
		for _, site := range bound {
			current, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: site.Domain})
			if err != nil || current == nil || current.Leaf == nil || current.Leaf.SerialNumber.Int64() != expected {
				t.Fatalf("SNI %s did not return certificate %d: %v", site.Domain, expected, err)
			}
		}
	}
	checkSerial(1)
	otherWorker, err := store.Open(filepath.Join(dir, "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer otherWorker.Close()
	// Force the stored renewal deadline to pass; the same worker path performs rotation.
	if _, err := st.DB.Exec("UPDATE managed_certificates SET next_attempt=0 WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	serial = 2
	process()
	checkSerial(2)
	if changed, err := otherWorker.RefreshSharedSettings(); err != nil || !changed {
		t.Fatalf("renewal was not visible to the other worker: changed=%v err=%v", changed, err)
	}
	// Exercise a complete new handshake using the TLS configuration created
	// before renewal, as the long-running listener does.
	var activePEM string
	if err := st.DB.QueryRow("SELECT cert_pem FROM managed_certificates WHERE id=?", id).Scan(&activePEM); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(activePEM)) {
		t.Fatal("could not load test root")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	server := tls.Server(left, tlsConfig)
	client := tls.Client(right, &tls.Config{ServerName: "www.example.com", RootCAs: roots})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.HandshakeContext(ctx) }()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 2 {
		t.Fatal("new TLS handshake did not use the renewed certificate")
	}
	fail = true
	if _, err := st.DB.Exec("UPDATE managed_certificates SET next_attempt=0 WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	process()
	checkSerial(2)
	certs, err = m.Certificates()
	if err != nil || certs[0].Status != "failed" || !strings.Contains(certs[0].LastError, "[已隐藏]") ||
		strings.Contains(certs[0].LastError, testSecret) {
		t.Fatalf("bad failure status: %+v (%v)", certs, err)
	}
	// Returning the current certificate after a transient failure proves the
	// provider recovered, but a short remaining lifetime calls for an earlier retry.
	expiresSoon := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	if _, err := st.DB.Exec("UPDATE managed_certificates SET next_attempt=0,expires_at=? WHERE id=?", expiresSoon.Unix(), id); err != nil {
		t.Fatal(err)
	}
	m.issue = func(_ context.Context, c Certificate, _ string, _ credentials, _ []byte) ([]byte, []byte, error) {
		cert, key := testCertificate(t, serial, c.Domains, expiresSoon)
		return cert, key, nil
	}
	process()
	var renewAt int64
	if err := st.DB.QueryRow("SELECT next_attempt FROM managed_certificates WHERE id=?", id).Scan(&renewAt); err != nil {
		t.Fatal(err)
	}
	if renewAt >= expiresSoon.Unix() || renewAt <= time.Now().Unix() {
		t.Errorf("renewal retry at %v is outside the remaining lifetime", time.Unix(renewAt, 0))
	}
	certs, err = m.Certificates()
	if err != nil || certs[0].Status != "ready" || certs[0].LastError != "" {
		t.Fatalf("successful renewal check did not clear the failure: %+v (%v)", certs, err)
	}
}

func TestDNSProviderConstructors(t *testing.T) {
	for _, provider := range []string{"alidns", "cloudflare", "tencentcloud"} {
		if instance, err := dnsProvider(provider, credentials{Key: "test-key", Secret: "test-secret"}); err != nil || instance == nil {
			t.Errorf("%s constructor failed: %v", provider, err)
		}
	}
}

func TestCanonicalDomainsAcceptsWildcardAndRejectsIP(t *testing.T) {
	domains, err := canonicalDomains([]string{" example.com ", "*.EXAMPLE.COM.", "example.com"})
	if err != nil || strings.Join(domains, ",") != "*.example.com,example.com" {
		t.Fatalf("incorrect canonical domains: %v (%v)", domains, err)
	}
	for _, domain := range []string{"127.0.0.1", "*.*.example.com", "https://example.com"} {
		if _, err := canonicalDomains([]string{domain}); err == nil {
			t.Errorf("unsupported domain accepted: %s", domain)
		}
	}
}
