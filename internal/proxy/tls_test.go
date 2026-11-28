package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestExpiredManagedCertificateFallsBackToManual(t *testing.T) {
	p := &Proxy{}
	manual := &tls.Certificate{}
	p.certs = map[string]*tls.Certificate{"a.example.com": manual}
	p.managedCerts = map[string]*tls.Certificate{
		"a.example.com": {Leaf: &x509.Certificate{NotAfter: time.Now().Add(-time.Second)}},
	}
	got, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil || got != manual {
		t.Fatalf("expired managed certificate shadowed the manual certificate: %v", err)
	}
}

func TestTLSConfigSiteCertPriority(t *testing.T) {
	p := &Proxy{}
	siteCert := &tls.Certificate{}
	p.certs = map[string]*tls.Certificate{"a.example.com": siteCert}
	got, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil || got != siteCert {
		t.Fatalf("应优先返回站点证书: got=%v err=%v", got, err)
	}
}
