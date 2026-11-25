// Package monitor inspects existing WAF state without probing upstreams or changing
// certificates, backups, or other managed resources.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"niubwaf/internal/store"
)

const (
	SeverityWarning  = "warning"
	SeverityCritical = "critical"

	alertStateSetting   = "inspect_alert_state"
	backupResultSetting = "inspect_backup_result"
)

// Finding is an active inspection finding. A zero LastNotified means that no
// notification channel has accepted the finding yet.
type Finding struct {
	Key          string    `json:"key"`
	Kind         string    `json:"kind"`
	Severity     string    `json:"severity"`
	Resource     string    `json:"resource"`
	Message      string    `json:"message"`
	First        time.Time `json:"first"`
	Last         time.Time `json:"last"`
	LastNotified time.Time `json:"last_notified,omitempty"`
}

// CheckError reports an inspection error separately from health findings.
type CheckError struct {
	Source   string    `json:"source"`
	Resource string    `json:"resource,omitempty"`
	Message  string    `json:"message"`
	Time     time.Time `json:"time"`
}

// Snapshot is an immutable-by-convention copy of the current inspection state.
type Snapshot struct {
	LastRun  time.Time    `json:"last_run"`
	Findings []Finding    `json:"findings"`
	Errors   []CheckError `json:"errors"`
}

// TargetStatus and UpstreamStatus deliberately mirror the small part of the
// proxy health snapshot consumed by Monitor. The source must not actively probe.
type TargetStatus struct {
	URL string `json:"url"`
	Up  bool   `json:"up"`
}

type UpstreamStatus struct {
	SiteID  int64          `json:"site_id"`
	Domain  string         `json:"domain"`
	Targets []TargetStatus `json:"targets"`
}

type UpstreamSource interface {
	UpstreamSnapshot(context.Context) ([]UpstreamStatus, error)
}

type UpstreamSourceFunc func(context.Context) ([]UpstreamStatus, error)

func (f UpstreamSourceFunc) UpstreamSnapshot(ctx context.Context) ([]UpstreamStatus, error) {
	return f(ctx)
}

// GeoData describes only a database that is already loaded. BuildTime takes
// precedence over ModTime when both are available. Kind is geoip/mmdb or
// ip2region/xdb.
type GeoData struct {
	Kind      string    `json:"kind"`
	Path      string    `json:"path"`
	BuildTime time.Time `json:"build_time,omitempty"`
	ModTime   time.Time `json:"mod_time,omitempty"`
}

type GeoSource interface {
	GeoSnapshot(context.Context) ([]GeoData, error)
}

type GeoSourceFunc func(context.Context) ([]GeoData, error)

func (f GeoSourceFunc) GeoSnapshot(ctx context.Context) ([]GeoData, error) {
	return f(ctx)
}

// Notifier returns delivered=true only when at least one channel accepted the
// notification. A false, nil result means no channel was available and does not
// advance LastNotified or the per-key cooldown.
type Notifier interface {
	Notify(ctx context.Context, event, message string, fields map[string]any) (delivered bool, err error)
}

type NotifierFunc func(context.Context, string, string, map[string]any) (bool, error)

func (f NotifierFunc) Notify(ctx context.Context, event, message string, fields map[string]any) (bool, error) {
	return f(ctx, event, message, fields)
}

// DiskUsage contains bytes visible to an unprivileged user.
type DiskUsage struct {
	TotalBytes     uint64
	AvailableBytes uint64
}

type DiskUsageFunc func(path string) (DiskUsage, error)

// Config wires the inspector to existing application state. DefaultCertFile and
// AdminCertFile default to their conventional names under DataDir. Now and
// DiskUsage are optional injection points, primarily useful in tests.
type Config struct {
	Store           *store.Store
	DataDir         string
	DefaultCertFile string
	AdminCertFile   string
	UpstreamSource  UpstreamSource
	GeoSource       GeoSource
	Notifier        Notifier
	DiskUsage       DiskUsageFunc
	Now             func() time.Time
}

type backupResult struct {
	Name            string    `json:"name,omitempty"`
	At              time.Time `json:"at"`
	Error           string    `json:"error,omitempty"`
	LastSuccessName string    `json:"last_success_name,omitempty"`
	LastSuccessAt   time.Time `json:"last_success_at,omitempty"`
}

// Monitor owns only inspection state. Run is serialized; Snapshot uses a
// separate short-lived lock and never wraps file, database, or notification I/O.
type Monitor struct {
	store           *store.Store
	dataDir         string
	defaultCertFile string
	adminCertFile   string
	upstreamSource  UpstreamSource
	geoSource       GeoSource
	notifier        Notifier
	diskUsage       DiskUsageFunc
	now             func() time.Time

	runMu     sync.Mutex
	startOnce sync.Once
	done      chan struct{}

	mu      sync.RWMutex
	alerts  map[string]*alertState
	pending map[string]*pendingState
	lastRun time.Time
	errors  []CheckError

	backupMu        sync.RWMutex
	backupPersistMu sync.Mutex
	backup          backupResult
}

func New(cfg Config) (*Monitor, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("monitor: Store is required")
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return nil, fmt.Errorf("monitor: DataDir is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.DiskUsage == nil {
		cfg.DiskUsage = platformDiskUsage
	}
	if cfg.DefaultCertFile == "" {
		cfg.DefaultCertFile = joinPath(cfg.DataDir, "default_cert.pem")
	}
	if cfg.AdminCertFile == "" {
		cfg.AdminCertFile = joinPath(cfg.DataDir, "admin_cert.pem")
	}
	m := &Monitor{
		store: cfg.Store, dataDir: cfg.DataDir,
		defaultCertFile: cfg.DefaultCertFile, adminCertFile: cfg.AdminCertFile,
		upstreamSource: cfg.UpstreamSource, geoSource: cfg.GeoSource,
		notifier: cfg.Notifier, diskUsage: cfg.DiskUsage, now: cfg.Now,
		done: make(chan struct{}), alerts: map[string]*alertState{}, pending: map[string]*pendingState{},
		errors: []CheckError{},
	}
	if raw := cfg.Store.GetSetting(alertStateSetting); raw != "" {
		if err := json.Unmarshal([]byte(raw), &m.alerts); err != nil {
			return nil, fmt.Errorf("monitor: decode %s: %w", alertStateSetting, err)
		}
		if m.alerts == nil {
			m.alerts = map[string]*alertState{}
		}
		for key, state := range m.alerts {
			if state == nil || key == "" || state.Finding.Key != key {
				return nil, fmt.Errorf("monitor: invalid %s entry %q", alertStateSetting, key)
			}
		}
	}
	if raw := cfg.Store.GetSetting(backupResultSetting); raw != "" {
		if err := json.Unmarshal([]byte(raw), &m.backup); err != nil {
			return nil, fmt.Errorf("monitor: decode %s: %w", backupResultSetting, err)
		}
		if m.backup.Error == "" && !m.backup.At.IsZero() && m.backup.LastSuccessAt.IsZero() {
			m.backup.LastSuccessAt = m.backup.At
			m.backup.LastSuccessName = m.backup.Name
		}
	}
	return m, nil
}

// Start launches one idempotent background loop. It returns immediately and the
// loop performs an initial Run before waiting inspect_interval_sec between runs.
func (m *Monitor) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		go func() {
			defer close(m.done)
			for {
				if ctx.Err() != nil {
					return
				}
				m.Run(ctx)
				timer := time.NewTimer(m.readSettings().interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	})
}

// Wait blocks until the background loop started by Start has exited.
func (m *Monitor) Wait() {
	<-m.done
}

// Run performs one complete inspection. Concurrent callers are serialized.
// Source and notification failures are exposed through Snapshot.Errors.
func (m *Monitor) Run(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	m.runMu.Lock()
	defer m.runMu.Unlock()

	now := m.now()
	settings := m.readSettings()
	collected := m.collect(ctx, now, settings)
	notifications, dirty := m.reconcile(now, settings, collected)

	if settings.alertEnabled && m.notifier != nil && ctx.Err() == nil {
		for _, notification := range notifications {
			delivered, err := m.notifier.Notify(ctx, notification.event(), notification.finding.Message, cloneFields(notification.fields))
			if err != nil {
				collected.errors = append(collected.errors, CheckError{
					Source: "notify", Resource: notification.finding.Key,
					Message: err.Error(), Time: now,
				})
				continue
			}
			if !delivered {
				continue
			}
			m.mu.Lock()
			if state := m.alerts[notification.finding.Key]; state != nil {
				state.Finding.LastNotified = now
				state.NotifiedSeverity = notification.finding.Severity
				dirty = true
			}
			m.mu.Unlock()
		}
	}
	if dirty {
		if err := m.persistAlerts(); err != nil {
			collected.errors = append(collected.errors, CheckError{Source: "state", Message: err.Error(), Time: now})
		}
	}

	sort.Slice(collected.errors, func(i, j int) bool {
		a, b := collected.errors[i], collected.errors[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.Message < b.Message
	})
	m.mu.Lock()
	m.lastRun = now
	m.errors = append([]CheckError(nil), collected.errors...)
	m.mu.Unlock()
}

// Snapshot returns a deep copy; callers may mutate any returned slice safely.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := Snapshot{
		LastRun: m.lastRun, Findings: make([]Finding, 0, len(m.alerts)),
		Errors: append(make([]CheckError, 0, len(m.errors)), m.errors...),
	}
	for _, state := range m.alerts {
		out.Findings = append(out.Findings, state.Finding)
	}
	sort.Slice(out.Findings, func(i, j int) bool { return out.Findings[i].Key < out.Findings[j].Key })
	return out
}

// RecordBackupResult records an actual API/automatic backup outcome; it never
// starts a backup. The result is persisted so a restart retains failures,
// successful backup age, and notification state.
func (m *Monitor) RecordBackupResult(name string, backupErr error) error {
	m.backupPersistMu.Lock()
	defer m.backupPersistMu.Unlock()

	now := m.now()
	m.backupMu.Lock()
	if backupErr != nil {
		m.backup.Name = name
		m.backup.At = now
		m.backup.Error = backupErr.Error()
	} else {
		m.backup.Name = name
		m.backup.At = now
		m.backup.Error = ""
		m.backup.LastSuccessName = name
		m.backup.LastSuccessAt = now
	}
	data, err := json.Marshal(m.backup)
	m.backupMu.Unlock()
	if err != nil {
		return err
	}
	return m.store.SetSetting(backupResultSetting, string(data))
}

func cloneFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}
