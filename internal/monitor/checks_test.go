package monitor

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/store"
)

func TestCertificateSourcesAndPEMOrder(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	siteCert := testCertificateBundle(t, now, now.Add(2*24*time.Hour), "site.example")
	if !strings.HasPrefix(string(siteCert), "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("test bundle must put the private key before CERTIFICATE")
	}
	if err := st.CreateSite(&store.Site{
		Name: "site", Domain: "site.example", Upstream: "http://127.0.0.1:8080", CertPEM: string(siteCert),
	}); err != nil {
		t.Fatal(err)
	}
	writeMonitorFile(t, filepath.Join(dir, "default_cert.pem"), testCertificateBundle(t, now, now.Add(5*24*time.Hour), "default.example"))
	writeMonitorFile(t, filepath.Join(dir, "admin_cert.pem"), testCertificateBundle(t, now, now.Add(30*24*time.Hour), "admin.example"))
	writeMonitorFile(t, filepath.Join(dir, "acme", "cached.example"), testCertificateBundle(t, now, now.Add(-time.Hour), "cached.example"))

	m := newTestMonitor(t, baseMonitorConfig(st, dir, &now))
	recordHealthyBackup(t, m)
	const legacyKey = "cert:acme:cached.example"
	m.alerts[legacyKey] = &alertState{Finding: Finding{Key: legacyKey, Kind: kindCertificateExpiry}}
	m.Run(context.Background())
	snapshot := m.Snapshot()
	if got := len(findingsByKind(snapshot, kindCertificateExpiry)); got != 2 {
		t.Fatalf("expected site/default findings only, got %+v", snapshot.Findings)
	}
	for _, key := range []string{"cert:site:1", "cert:default"} {
		finding, ok := findingByKey(snapshot, key)
		if !ok || !finding.First.Equal(now) || !finding.LastNotified.IsZero() {
			t.Errorf("missing or incorrect %s: %+v", key, finding)
		}
	}
	if _, ok := findingByKey(snapshot, legacyKey); ok {
		t.Fatal("retired certificate alert should be removed")
	}
	if _, ok := findingByKey(snapshot, "cert:admin"); ok {
		t.Fatal("healthy admin certificate produced a finding")
	}
}

func TestManagedProductionCertificatesAreMonitored(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	site := &store.Site{Name: "site", Domain: "active.example", Upstream: "http://127.0.0.1:8080"}
	if err := st.CreateSite(site); err != nil {
		t.Fatal(err)
	}

	addCertificate := func(domain string, staging bool, expires time.Time, status string) int64 {
		t.Helper()
		_, certPEM := pem.Decode(testCertificateBundle(t, now, expires, domain))
		result, err := st.DB.Exec(`INSERT INTO managed_certificates(account_id, domains, email, staging, account_key, cert_pem, expires_at, status)
			VALUES(1, ?, 'test@example.com', ?, X'', ?, ?, ?)`, domain, staging, string(certPEM), expires.Unix(), status)
		if err != nil {
			t.Fatal(err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	expiredID := addCertificate(site.Domain, false, now.Add(-time.Minute), "ready")
	if _, err := st.DB.Exec(`INSERT INTO managed_certificate_sites(site_id, certificate_id, domain) VALUES(?, ?, ?)`,
		site.ID, expiredID, site.Domain); err != nil {
		t.Fatal(err)
	}
	warningID := addCertificate("unbound.example", false, now.Add(2*24*time.Hour), "failed")
	addCertificate("staging.example", true, now.Add(-time.Minute), "ready")
	addCertificate("healthy.example", false, now.Add(30*24*time.Hour), "ready")

	m := newTestMonitor(t, baseMonitorConfig(st, dir, &now))
	recordHealthyBackup(t, m)
	m.Run(context.Background())
	snapshot := m.Snapshot()
	for id, severity := range map[int64]string{expiredID: SeverityCritical, warningID: SeverityWarning} {
		key := fmt.Sprintf("cert:managed:%d", id)
		if finding, ok := findingByKey(snapshot, key); !ok || finding.Severity != severity {
			t.Errorf("expected %s to be %s, got %+v", key, severity, finding)
		}
	}
	if got := findingsByKind(snapshot, kindCertificateExpiry); len(got) != 2 {
		t.Fatalf("expected findings for expired and expiring production certificates, got %+v", got)
	}

	renewed := now.Add(30 * 24 * time.Hour)
	_, certPEM := pem.Decode(testCertificateBundle(t, now, renewed, site.Domain))
	if _, err := st.DB.Exec(`UPDATE managed_certificates SET cert_pem=?, expires_at=? WHERE id=?`,
		string(certPEM), renewed.Unix(), expiredID); err != nil {
		t.Fatal(err)
	}
	m.Run(context.Background())
	if got := findingsByKind(m.Snapshot(), kindCertificateExpiry); len(got) != 1 || got[0].Key != fmt.Sprintf("cert:managed:%d", warningID) {
		t.Fatalf("renewal should resolve only the matching certificate finding, got %+v", got)
	}
}

func TestUpstreamDebounceRecoveryAndRecurrence(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	notifier := newFakeNotifier()
	cfg := baseMonitorConfig(st, dir, &now)
	cfg.Notifier = notifier
	up := false
	cfg.UpstreamSource = UpstreamSourceFunc(func(context.Context) ([]UpstreamStatus, error) {
		return []UpstreamStatus{{SiteID: 7, Domain: "site.example", Targets: []TargetStatus{{URL: "http://127.0.0.1:8080", Up: up}}}}, nil
	})
	if err := st.SetSetting("alert_enabled", "on"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("inspect_upstream_failures", "3"); err != nil {
		t.Fatal(err)
	}
	m := newTestMonitor(t, cfg)
	recordHealthyBackup(t, m)
	firstObserved := now

	for i := 0; i < 2; i++ {
		m.Run(context.Background())
		if got := len(findingsByKind(m.Snapshot(), kindUpstreamDown)); got != 0 {
			t.Fatalf("upstream finding appeared before debounce at run %d", i+1)
		}
		now = now.Add(time.Minute)
	}
	m.Run(context.Background())
	finding := findingsByKind(m.Snapshot(), kindUpstreamDown)
	if len(finding) != 1 || !finding[0].First.Equal(firstObserved) || len(notifier.Calls()) != 1 {
		t.Fatalf("upstream did not activate on third failure: %+v", finding)
	}
	now = now.Add(time.Minute)
	m.Run(context.Background())
	if len(notifier.Calls()) != 1 {
		t.Fatal("upstream repeat ignored per-key cooldown")
	}

	up = true
	now = now.Add(time.Minute)
	m.Run(context.Background())
	if got := len(findingsByKind(m.Snapshot(), kindUpstreamDown)); got != 0 {
		t.Fatal("healthy snapshot did not recover upstream finding")
	}
	up = false
	for i := 0; i < 3; i++ {
		now = now.Add(time.Minute)
		m.Run(context.Background())
	}
	if got := len(notifier.Calls()); got != 2 {
		t.Fatalf("recovered upstream recurrence reused old cooldown: calls=%d", got)
	}
}

func TestDiskDebounceAndReadErrors(t *testing.T) {
	tests := []struct {
		name  string
		usage DiskUsage
	}{
		{"low percent", DiskUsage{TotalBytes: 100 * 1024 * 1024 * 1024, AvailableBytes: 5 * 1024 * 1024 * 1024}},
		{"low absolute space", DiskUsage{TotalBytes: 4 * 1024 * 1024 * 1024, AvailableBytes: 512 * 1024 * 1024}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			st := openMonitorStore(t, dir)
			now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
			cfg := baseMonitorConfig(st, dir, &now)
			cfg.DiskUsage = func(string) (DiskUsage, error) { return test.usage, nil }
			m := newTestMonitor(t, cfg)
			recordHealthyBackup(t, m)
			m.Run(context.Background())
			if got := len(findingsByKind(m.Snapshot(), kindDiskSpace)); got != 0 {
				t.Fatal("disk finding appeared before consecutive abnormal samples")
			}
			m.Run(context.Background())
			if got := len(findingsByKind(m.Snapshot(), kindDiskSpace)); got != 1 {
				t.Fatalf("disk finding missing after second sample: %+v", m.Snapshot())
			}
		})
	}

	for _, test := range []struct {
		name  string
		usage DiskUsage
		err   error
	}{
		{name: "zero total", usage: DiskUsage{}},
		{name: "system call failure", err: errors.New("stat failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			st := openMonitorStore(t, dir)
			now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
			cfg := baseMonitorConfig(st, dir, &now)
			usage := DiskUsage{TotalBytes: 4 * 1024 * 1024 * 1024, AvailableBytes: 512 * 1024 * 1024}
			var readErr error
			cfg.DiskUsage = func(string) (DiskUsage, error) { return usage, readErr }
			m := newTestMonitor(t, cfg)
			recordHealthyBackup(t, m)
			m.Run(context.Background())
			m.Run(context.Background())
			if got := len(findingsByKind(m.Snapshot(), kindDiskSpace)); got != 1 {
				t.Fatal("test setup did not activate disk finding")
			}
			usage, readErr = test.usage, test.err
			m.Run(context.Background())
			snapshot := m.Snapshot()
			if got := len(findingsByKind(snapshot, kindDiskSpace)); got != 0 {
				t.Fatalf("disk read problem retained a health finding: %+v", snapshot.Findings)
			}
			if len(snapshot.Errors) != 1 || snapshot.Errors[0].Source != "disk" {
				t.Fatalf("disk read problem missing check error: %+v", snapshot.Errors)
			}
		})
	}
}

func TestBackupFailureAgeAndFileFallback(t *testing.T) {
	t.Run("recorded result", func(t *testing.T) {
		dir := t.TempDir()
		st := openMonitorStore(t, dir)
		now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
		m := newTestMonitor(t, baseMonitorConfig(st, dir, &now))
		m.Run(context.Background())
		if got := len(findingsByKind(m.Snapshot(), kindBackupStale)); got != 1 {
			t.Fatal("missing backup history should be stale")
		}

		if err := m.RecordBackupResult("", errors.New("disk full")); err != nil {
			t.Fatal(err)
		}
		m.Run(context.Background())
		snapshot := m.Snapshot()
		if got := len(findingsByKind(snapshot, kindBackupFailed)); got != 1 {
			t.Fatalf("actual backup failure missing: %+v", snapshot.Findings)
		}
		if got := len(findingsByKind(snapshot, kindBackupStale)); got != 0 {
			t.Fatal("backup failure should not also emit a duplicate stale finding")
		}

		if err := m.RecordBackupResult("niubwaf-good.db", nil); err != nil {
			t.Fatal(err)
		}
		m.Run(context.Background())
		if got := len(findingsByKind(m.Snapshot(), kindBackupFailed)); got != 0 {
			t.Fatal("successful backup did not recover failure")
		}
		now = now.Add(27 * time.Hour)
		m.Run(context.Background())
		if got := len(findingsByKind(m.Snapshot(), kindBackupStale)); got != 1 {
			t.Fatalf("old successful backup should be stale: %+v", m.Snapshot().Findings)
		}
	})

	t.Run("existing backup file", func(t *testing.T) {
		dir := t.TempDir()
		st := openMonitorStore(t, dir)
		now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
		path := filepath.Join(dir, "backups", "niubwaf-existing.db")
		writeMonitorFile(t, path, []byte("sqlite"))
		mtime := now.Add(-2 * time.Hour)
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		m := newTestMonitor(t, baseMonitorConfig(st, dir, &now))
		m.Run(context.Background())
		if got := len(findingsByKind(m.Snapshot(), kindBackupStale)); got != 0 {
			t.Fatalf("recent existing backup was ignored: %+v", m.Snapshot().Findings)
		}
		now = now.Add(25 * time.Hour)
		m.Run(context.Background())
		if got := len(findingsByKind(m.Snapshot(), kindBackupStale)); got != 1 {
			t.Fatal("existing backup file did not age out")
		}
	})
}

func TestGeoLoadedDataAgeOnly(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	items := []GeoData{
		{Kind: "mmdb", Path: "old-country.mmdb", BuildTime: now.Add(-31 * 24 * time.Hour)},
		{Kind: "xdb", Path: "old-region.xdb", ModTime: now.Add(-91 * 24 * time.Hour)},
		{Kind: "geoip", Path: "fresh-build.mmdb", BuildTime: now.Add(-24 * time.Hour), ModTime: now.Add(-365 * 24 * time.Hour)},
	}
	cfg := baseMonitorConfig(st, dir, &now)
	cfg.GeoSource = GeoSourceFunc(func(context.Context) ([]GeoData, error) { return items, nil })
	m := newTestMonitor(t, cfg)
	recordHealthyBackup(t, m)
	m.Run(context.Background())
	snapshot := m.Snapshot()
	if len(findingsByKind(snapshot, kindGeoIPStale)) != 1 || len(findingsByKind(snapshot, kindIP2RegionStale)) != 1 {
		t.Fatalf("loaded stale geo data not detected correctly: %+v", snapshot.Findings)
	}
	if _, ok := findingByKey(snapshot, "geo:GeoIP:fresh-build.mmdb"); ok {
		t.Fatal("modtime should not override a fresh MMDB build time")
	}

	items = nil
	writeMonitorFile(t, filepath.Join(dir, "geoip.mmdb"), []byte("not loaded"))
	writeMonitorFile(t, filepath.Join(dir, "ip2region.xdb"), []byte("not loaded"))
	m.Run(context.Background())
	snapshot = m.Snapshot()
	if len(findingsByKind(snapshot, kindGeoIPStale)) != 0 || len(findingsByKind(snapshot, kindIP2RegionStale)) != 0 {
		t.Fatal("optional unloaded geo files produced findings")
	}
	if len(snapshot.Errors) != 0 {
		t.Fatalf("optional unloaded geo files produced errors: %+v", snapshot.Errors)
	}
}

func TestPlatformDiskUsage(t *testing.T) {
	usage, err := platformDiskUsage(t.TempDir())
	if err != nil {
		t.Fatalf("platform disk usage: %v", err)
	}
	if usage.TotalBytes == 0 {
		t.Fatal("platform disk usage returned total=0")
	}
}
