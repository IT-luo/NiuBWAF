package monitor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"niubwaf/internal/store"
)

type recordedNotification struct {
	event   string
	message string
	fields  map[string]any
}

type fakeNotifier struct {
	mu        sync.Mutex
	delivered bool
	err       error
	calls     []recordedNotification
}

func newFakeNotifier() *fakeNotifier { return &fakeNotifier{delivered: true} }

func (f *fakeNotifier) Notify(_ context.Context, event, message string, fields map[string]any) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedNotification{event: event, message: message, fields: cloneFields(fields)})
	return f.delivered, f.err
}

func (f *fakeNotifier) Calls() []recordedNotification {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedNotification, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeNotifier) SetResult(delivered bool, err error) {
	f.mu.Lock()
	f.delivered, f.err = delivered, err
	f.mu.Unlock()
}

func openMonitorStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	t.Setenv("NIUBWAF_ADMIN_PASSWORD", "MonitorTestPass123")
	st, err := store.Open(filepath.Join(dir, "niubwaf.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func baseMonitorConfig(st *store.Store, dir string, now *time.Time) Config {
	return Config{
		Store: st, DataDir: dir, Now: func() time.Time { return *now },
		DiskUsage: func(string) (DiskUsage, error) {
			return DiskUsage{TotalBytes: 1000 * 1024 * 1024 * 1024, AvailableBytes: 900 * 1024 * 1024 * 1024}, nil
		},
	}
}

func newTestMonitor(t *testing.T, cfg Config) *Monitor {
	t.Helper()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	return m
}

func recordHealthyBackup(t *testing.T, m *Monitor) {
	t.Helper()
	if err := m.RecordBackupResult("niubwaf-test.db", nil); err != nil {
		t.Fatalf("record backup: %v", err)
	}
}

func testCertificateBundle(t *testing.T, now, notAfter time.Time, commonName string) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour),
		NotAfter: notAfter, DNSNames: []string{commonName},
	}
	template.Subject.CommonName = commonName
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(keyPEM, certPEM...)
}

func writeMonitorFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestSnapshotEmptyCollectionsAreNonNil(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	m := newTestMonitor(t, baseMonitorConfig(st, dir, &now))
	recordHealthyBackup(t, m)
	initial := m.Snapshot()
	if initial.Findings == nil || initial.Errors == nil {
		t.Fatalf("initial snapshot must use empty arrays: %+v", initial)
	}
	m.Run(context.Background())
	snapshot := m.Snapshot()
	if snapshot.Findings == nil || snapshot.Errors == nil {
		t.Fatalf("completed snapshot must use empty arrays: %+v", snapshot)
	}
}

func findingByKey(snapshot Snapshot, key string) (Finding, bool) {
	for _, finding := range snapshot.Findings {
		if finding.Key == key {
			return finding, true
		}
	}
	return Finding{}, false
}

func findingsByKind(snapshot Snapshot, kind string) []Finding {
	var out []Finding
	for _, finding := range snapshot.Findings {
		if finding.Kind == kind {
			out = append(out, finding)
		}
	}
	return out
}

func TestCertificateNotificationLifecycle(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	notifier := newFakeNotifier()
	cfg := baseMonitorConfig(st, dir, &now)
	cfg.Notifier = notifier
	if err := st.SetSetting("alert_enabled", "on"); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "default_cert.pem")
	writeMonitorFile(t, certPath, testCertificateBundle(t, now, now.Add(time.Hour), "default.example"))
	m := newTestMonitor(t, cfg)
	recordHealthyBackup(t, m)

	m.Run(context.Background())
	finding, ok := findingByKey(m.Snapshot(), "cert:default")
	if !ok || finding.Severity != SeverityWarning {
		t.Fatalf("expected warning certificate finding, got %+v", m.Snapshot().Findings)
	}
	if !finding.First.Equal(now) || !finding.Last.Equal(now) || !finding.LastNotified.Equal(now) {
		t.Fatalf("unexpected finding timestamps: %+v", finding)
	}
	calls := notifier.Calls()
	if len(calls) != 1 || calls[0].event != "monitor.certificate_expiry" || calls[0].fields["key"] != "cert:default" {
		t.Fatalf("unexpected initial notifications: %+v", calls)
	}

	now = now.Add(time.Minute)
	m.Run(context.Background())
	if got := len(notifier.Calls()); got != 1 {
		t.Fatalf("cooldown should suppress repeat, got %d calls", got)
	}

	now = now.Add(2 * time.Hour)
	m.Run(context.Background())
	finding, _ = findingByKey(m.Snapshot(), "cert:default")
	if finding.Severity != SeverityCritical || len(notifier.Calls()) != 2 {
		t.Fatalf("severity escalation must notify immediately: %+v, calls=%d", finding, len(notifier.Calls()))
	}

	restarted := newTestMonitor(t, cfg)
	restarted.Run(context.Background())
	if got := len(notifier.Calls()); got != 2 {
		t.Fatalf("restart repeated a notification inside cooldown: %d", got)
	}
	persisted, ok := findingByKey(restarted.Snapshot(), "cert:default")
	if !ok || !persisted.First.Equal(finding.First) || !persisted.LastNotified.Equal(now) {
		t.Fatalf("restart lost finding state: %+v", persisted)
	}

	writeMonitorFile(t, certPath, testCertificateBundle(t, now, now.Add(90*24*time.Hour), "default.example"))
	restarted.Run(context.Background())
	if _, ok := findingByKey(restarted.Snapshot(), "cert:default"); ok {
		t.Fatal("healthy replacement certificate did not recover the finding")
	}

	now = now.Add(time.Minute)
	writeMonitorFile(t, certPath, testCertificateBundle(t, now, now.Add(30*time.Minute), "default.example"))
	restarted.Run(context.Background())
	recurred, ok := findingByKey(restarted.Snapshot(), "cert:default")
	if !ok || !recurred.First.Equal(now) || !recurred.LastNotified.Equal(now) || len(notifier.Calls()) != 3 {
		t.Fatalf("recurrence after recovery must notify immediately: %+v, calls=%d", recurred, len(notifier.Calls()))
	}
}

func TestAlertEnabledAndNoChannelDoNotSkipInspection(t *testing.T) {
	t.Run("alert enabled only controls delivery", func(t *testing.T) {
		dir := t.TempDir()
		st := openMonitorStore(t, dir)
		now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
		notifier := newFakeNotifier()
		cfg := baseMonitorConfig(st, dir, &now)
		cfg.Notifier = notifier
		writeMonitorFile(t, filepath.Join(dir, "default_cert.pem"), testCertificateBundle(t, now, now.Add(time.Hour), "default.example"))
		m := newTestMonitor(t, cfg)
		recordHealthyBackup(t, m)

		m.Run(context.Background())
		finding, ok := findingByKey(m.Snapshot(), "cert:default")
		if !ok || len(notifier.Calls()) != 0 || !finding.LastNotified.IsZero() {
			t.Fatalf("disabled alerts changed inspection state: %+v, calls=%d", finding, len(notifier.Calls()))
		}
		if err := st.SetSetting("alert_enabled", "on"); err != nil {
			t.Fatal(err)
		}
		m.Run(context.Background())
		finding, _ = findingByKey(m.Snapshot(), "cert:default")
		if len(notifier.Calls()) != 1 || finding.LastNotified.IsZero() {
			t.Fatalf("enabling alerts should deliver an existing finding: %+v", finding)
		}
	})

	t.Run("no channel never advances notification time", func(t *testing.T) {
		dir := t.TempDir()
		st := openMonitorStore(t, dir)
		now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
		notifier := newFakeNotifier()
		notifier.SetResult(false, nil)
		cfg := baseMonitorConfig(st, dir, &now)
		cfg.Notifier = notifier
		if err := st.SetSetting("alert_enabled", "on"); err != nil {
			t.Fatal(err)
		}
		writeMonitorFile(t, filepath.Join(dir, "default_cert.pem"), testCertificateBundle(t, now, now.Add(24*time.Hour), "default.example"))
		m := newTestMonitor(t, cfg)
		recordHealthyBackup(t, m)

		m.Run(context.Background())
		now = now.Add(7 * time.Hour)
		m.Run(context.Background())
		finding, _ := findingByKey(m.Snapshot(), "cert:default")
		if len(notifier.Calls()) != 2 || !finding.LastNotified.IsZero() {
			t.Fatalf("undelivered notifications advanced state: %+v, calls=%d", finding, len(notifier.Calls()))
		}
		notifier.SetResult(true, nil)
		m.Run(context.Background())
		finding, _ = findingByKey(m.Snapshot(), "cert:default")
		if len(notifier.Calls()) != 3 || !finding.LastNotified.Equal(now) {
			t.Fatalf("accepted notification was not recorded: %+v", finding)
		}
	})
}

func TestConcurrentRunIsSerialized(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cfg := baseMonitorConfig(st, dir, &now)
	var active, maximum, calls atomic.Int32
	cfg.DiskUsage = func(string) (DiskUsage, error) {
		current := active.Add(1)
		defer active.Add(-1)
		calls.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		return DiskUsage{TotalBytes: 1000, AvailableBytes: 900}, nil
	}
	m := newTestMonitor(t, cfg)
	recordHealthyBackup(t, m)

	const runners = 6
	var wg sync.WaitGroup
	wg.Add(runners)
	for i := 0; i < runners; i++ {
		go func() {
			defer wg.Done()
			m.Run(context.Background())
		}()
	}
	wg.Wait()
	if maximum.Load() != 1 || calls.Load() != runners {
		t.Fatalf("Run overlap detected: max=%d calls=%d", maximum.Load(), calls.Load())
	}
}

func TestSnapshotDeepCopy(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cfg := baseMonitorConfig(st, dir, &now)
	cfg.GeoSource = GeoSourceFunc(func(context.Context) ([]GeoData, error) {
		return nil, errors.New("geo unavailable")
	})
	writeMonitorFile(t, filepath.Join(dir, "default_cert.pem"), testCertificateBundle(t, now, now.Add(time.Hour), "default.example"))
	m := newTestMonitor(t, cfg)
	recordHealthyBackup(t, m)
	m.Run(context.Background())

	first := m.Snapshot()
	if len(first.Findings) == 0 || len(first.Errors) == 0 {
		t.Fatalf("test requires findings and errors: %+v", first)
	}
	originalMessage := first.Findings[0].Message
	originalError := first.Errors[0].Message
	first.Findings[0].Message = "mutated"
	first.Findings[0].First = time.Time{}
	first.Errors[0].Message = "mutated"
	second := m.Snapshot()
	if second.Findings[0].Message != originalMessage || second.Findings[0].First.IsZero() || second.Errors[0].Message != originalError {
		t.Fatalf("Snapshot returned shared state: %+v", second)
	}
}

func TestSnapshotNotBlockedByNotifier(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	cfg := baseMonitorConfig(st, dir, &now)
	cfg.Notifier = NotifierFunc(func(context.Context, string, string, map[string]any) (bool, error) {
		close(started)
		<-release
		return true, nil
	})
	if err := st.SetSetting("alert_enabled", "on"); err != nil {
		t.Fatal(err)
	}
	writeMonitorFile(t, filepath.Join(dir, "default_cert.pem"), testCertificateBundle(t, now, now.Add(time.Hour), "default.example"))
	m := newTestMonitor(t, cfg)
	recordHealthyBackup(t, m)
	runDone := make(chan struct{})
	go func() {
		m.Run(context.Background())
		close(runDone)
	}()
	<-started

	snapshotDone := make(chan struct{})
	go func() {
		_ = m.Snapshot()
		close(snapshotDone)
	}()
	var blocked bool
	select {
	case <-snapshotDone:
	case <-time.After(time.Second):
		blocked = true
	}
	close(release)
	<-runDone
	if blocked {
		t.Fatal("Snapshot blocked behind notification I/O")
	}
}

func TestInspectionSettingDefaultsAndRanges(t *testing.T) {
	dir := t.TempDir()
	st := openMonitorStore(t, dir)
	now := time.Now()
	m := newTestMonitor(t, baseMonitorConfig(st, dir, &now))
	settings := m.readSettings()
	if settings.interval != time.Minute || settings.certWarn != 14*24*time.Hour ||
		settings.upstreamFailures != 3 || settings.diskFreePercent != 10 || settings.diskFreeMB != 1024 ||
		settings.backupMaxAge != 26*time.Hour || settings.geoIPMaxAge != 30*24*time.Hour ||
		settings.ip2regionMaxAge != 90*24*time.Hour || settings.cooldown != 21600*time.Second {
		t.Fatalf("unexpected defaults: %+v", settings)
	}

	tests := []struct {
		key           string
		def, min, max int
	}{
		{"inspect_interval_sec", 60, 30, 3600},
		{"inspect_cert_warn_days", 14, 1, 90},
		{"inspect_upstream_failures", 3, 1, 20},
		{"inspect_disk_free_percent", 10, 1, 90},
		{"inspect_disk_free_mb", 1024, 0, 1048576},
		{"inspect_backup_max_age_hours", 26, 7, 8760},
		{"inspect_geoip_max_age_days", 30, 1, 3650},
		{"inspect_ip2region_max_age_days", 90, 1, 3650},
		{"inspect_cooldown_sec", 21600, 300, 604800},
	}
	for _, test := range tests {
		if got := settingInt(st, test.key, test.def, test.min, test.max); got != test.def {
			t.Errorf("%s default=%d, want %d", test.key, got, test.def)
		}
		st.SetSetting(test.key, strconv.Itoa(test.min-1))
		if got := settingInt(st, test.key, test.def, test.min, test.max); got != test.min {
			t.Errorf("%s minimum=%d, want %d", test.key, got, test.min)
		}
		st.SetSetting(test.key, strconv.Itoa(test.max+1))
		if got := settingInt(st, test.key, test.def, test.min, test.max); got != test.max {
			t.Errorf("%s maximum=%d, want %d", test.key, got, test.max)
		}
		st.SetSetting(test.key, "invalid")
		if got := settingInt(st, test.key, test.def, test.min, test.max); got != test.def {
			t.Errorf("%s invalid=%d, want default %d", test.key, got, test.def)
		}
		st.SetSetting(test.key, "")
	}
}
