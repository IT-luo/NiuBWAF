package monitor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	kindCertificateExpiry = "certificate_expiry"
	kindUpstreamDown      = "upstream_down"
	kindDiskSpace         = "disk_space"
	kindBackupFailed      = "backup_failed"
	kindBackupStale       = "backup_stale"
	kindGeoIPStale        = "geoip_stale"
	kindIP2RegionStale    = "ip2region_stale"

	diskFailureThreshold = 2
)

type inspectionSettings struct {
	interval         time.Duration
	certWarn         time.Duration
	upstreamFailures int
	diskFreePercent  int
	diskFreeMB       int
	backupMaxAge     time.Duration
	geoIPMaxAge      time.Duration
	ip2regionMaxAge  time.Duration
	cooldown         time.Duration
	alertEnabled     bool
}

func (m *Monitor) readSettings() inspectionSettings {
	intervalSec := settingInt(m.store, "inspect_interval_sec", 60, 30, 3600)
	certWarnDays := settingInt(m.store, "inspect_cert_warn_days", 14, 1, 90)
	backupAgeHours := settingInt(m.store, "inspect_backup_max_age_hours", 26, 7, 8760)
	geoIPAgeDays := settingInt(m.store, "inspect_geoip_max_age_days", 30, 1, 3650)
	ip2regionAgeDays := settingInt(m.store, "inspect_ip2region_max_age_days", 90, 1, 3650)
	cooldownSec := settingInt(m.store, "inspect_cooldown_sec", 21600, 300, 604800)
	return inspectionSettings{
		interval:         time.Duration(intervalSec) * time.Second,
		certWarn:         time.Duration(certWarnDays) * 24 * time.Hour,
		upstreamFailures: settingInt(m.store, "inspect_upstream_failures", 3, 1, 20),
		diskFreePercent:  settingInt(m.store, "inspect_disk_free_percent", 10, 1, 90),
		diskFreeMB:       settingInt(m.store, "inspect_disk_free_mb", 1024, 0, 1048576),
		backupMaxAge:     time.Duration(backupAgeHours) * time.Hour,
		geoIPMaxAge:      time.Duration(geoIPAgeDays) * 24 * time.Hour,
		ip2regionMaxAge:  time.Duration(ip2regionAgeDays) * 24 * time.Hour,
		cooldown:         time.Duration(cooldownSec) * time.Second,
		alertEnabled:     m.store.GetSetting("alert_enabled") == "on",
	}
}

func settingInt(st interface{ GetSetting(string) string }, key string, def, min, max int) int {
	value := def
	if raw := strings.TrimSpace(st.GetSetting(key)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < min {
		value = min
	}
	if value > max {
		value = max
	}
	return value
}

func (m *Monitor) collect(ctx context.Context, now time.Time, settings inspectionSettings) *collection {
	collected := &collection{observations: map[string]observation{}, errors: []CheckError{}}
	m.collectCertificates(ctx, now, settings, collected)
	m.collectUpstreams(ctx, now, settings, collected)
	m.collectDisk(now, settings, collected)
	m.collectBackup(now, settings, collected)
	m.collectGeo(ctx, now, settings, collected)
	return collected
}

func (m *Monitor) collectCertificates(ctx context.Context, now time.Time, settings inspectionSettings, collected *collection) {
	// Resolve alerts persisted by versions that inspected the retired ACME cache.
	collected.covered = append(collected.covered, "cert:acme:")
	sites, err := m.store.ListSites()
	if err != nil {
		addCheckError(collected, now, "certificate", "sites", err)
	} else {
		collected.covered = append(collected.covered, "cert:site:")
		for _, site := range sites {
			if strings.TrimSpace(site.CertPEM) == "" {
				continue
			}
			key := fmt.Sprintf("cert:site:%d", site.ID)
			resource := fmt.Sprintf("site %s (%d)", site.Domain, site.ID)
			addPEMCertificate(collected, now, settings, key, resource, site.Domain, []byte(site.CertPEM), true)
		}
	}
	m.collectManagedCertificates(ctx, now, settings, collected)

	for _, item := range []struct {
		key      string
		resource string
		path     string
	}{
		{key: "cert:default", resource: "proxy default certificate", path: m.defaultCertFile},
		{key: "cert:admin", resource: "admin certificate", path: m.adminCertFile},
	} {
		data, err := os.ReadFile(item.path)
		if os.IsNotExist(err) {
			collected.covered = append(collected.covered, item.key)
			continue
		}
		if err != nil {
			addCheckError(collected, now, "certificate", item.path, err)
			continue
		}
		collected.covered = append(collected.covered, item.key)
		addPEMCertificate(collected, now, settings, item.key, item.resource+" "+item.path, item.path, data, true)
	}

}

func (m *Monitor) collectManagedCertificates(ctx context.Context, now time.Time, settings inspectionSettings, collected *collection) {
	const prefix = "cert:managed:"
	const source = "managed certificates"

	// Include issued production certificates even when unbound, expired, or awaiting renewal.
	rows, err := m.store.DB.QueryContext(ctx, `SELECT id, domains, cert_pem FROM managed_certificates
		WHERE staging=0 AND cert_pem<>''`)
	if err != nil {
		addCheckError(collected, now, "certificate", source, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var domains string
		var certPEM []byte
		if err := rows.Scan(&id, &domains, &certPEM); err != nil {
			addCheckError(collected, now, "certificate", source, err)
			return
		}
		key := prefix + strconv.FormatInt(id, 10)
		resource := fmt.Sprintf("managed certificate %s (%d)", domains, id)
		addPEMCertificate(collected, now, settings, key, resource, domains, certPEM, true)
	}
	if err := rows.Err(); err != nil {
		addCheckError(collected, now, "certificate", source, err)
		return
	}
	collected.covered = append(collected.covered, prefix)
}

func addPEMCertificate(collected *collection, now time.Time, settings inspectionSettings, key, resource, label string, data []byte, required bool) {
	expires, commonName, found, err := earliestCertificate(data)
	if err != nil {
		addCheckError(collected, now, "certificate", resource, err)
		return
	}
	if !found {
		if required {
			addCheckError(collected, now, "certificate", resource, fmt.Errorf("no CERTIFICATE PEM block found"))
		}
		return
	}
	remaining := expires.Sub(now)
	if remaining > settings.certWarn {
		return
	}
	severity := SeverityWarning
	message := ""
	if remaining <= 0 {
		severity = SeverityCritical
		message = fmt.Sprintf("证书已过期：%s，到期时间 %s", label, expires.UTC().Format(time.RFC3339))
	} else {
		days := int((remaining + 24*time.Hour - 1) / (24 * time.Hour))
		message = fmt.Sprintf("证书即将到期：%s，到期时间 %s（剩余 %d 天）", label, expires.UTC().Format(time.RFC3339), days)
	}
	if commonName != "" {
		message += "，名称 " + commonName
	}
	collected.observations[key] = observation{
		finding:  Finding{Key: key, Kind: kindCertificateExpiry, Severity: severity, Resource: resource, Message: message},
		required: 1,
		fields:   map[string]any{"expires_at": expires.UTC().Format(time.RFC3339), "warn_days": int(settings.certWarn / (24 * time.Hour))},
	}
}

// earliestCertificate deliberately scans every PEM block: manual
// bundles commonly place the private key before the first certificate.
func earliestCertificate(data []byte) (time.Time, string, bool, error) {
	var earliest time.Time
	commonName := ""
	found := false
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, "", false, fmt.Errorf("parse CERTIFICATE block: %w", err)
		}
		if !found || certificate.NotAfter.Before(earliest) {
			earliest = certificate.NotAfter
			commonName = certificate.Subject.CommonName
			if commonName == "" && len(certificate.DNSNames) > 0 {
				commonName = certificate.DNSNames[0]
			}
		}
		found = true
	}
	return earliest, commonName, found, nil
}

func (m *Monitor) collectUpstreams(ctx context.Context, now time.Time, settings inspectionSettings, collected *collection) {
	if m.upstreamSource == nil {
		return
	}
	statuses, err := m.upstreamSource.UpstreamSnapshot(ctx)
	if err != nil {
		addCheckError(collected, now, "upstream", "", err)
		return
	}
	collected.covered = append(collected.covered, "upstream:")
	for _, site := range statuses {
		for _, target := range site.Targets {
			if target.Up {
				continue
			}
			if strings.TrimSpace(target.URL) == "" {
				addCheckError(collected, now, "upstream", site.Domain, fmt.Errorf("down target has an empty URL"))
				continue
			}
			key := fmt.Sprintf("upstream:%d:%s:%s", site.SiteID, site.Domain, target.URL)
			resource := fmt.Sprintf("%s -> %s", site.Domain, target.URL)
			collected.observations[key] = observation{
				finding: Finding{
					Key: key, Kind: kindUpstreamDown, Severity: SeverityCritical, Resource: resource,
					Message: fmt.Sprintf("上游健康快照异常：%s（连续失败达到 %d 次）", resource, settings.upstreamFailures),
				},
				required: settings.upstreamFailures,
				fields:   map[string]any{"site_id": site.SiteID, "domain": site.Domain, "url": target.URL, "required_failures": settings.upstreamFailures},
			}
		}
	}
}

func (m *Monitor) collectDisk(now time.Time, settings inspectionSettings, collected *collection) {
	// A failed/empty measurement is unknown, not a low-space sample. Clear any
	// prior disk finding and expose only the check error for this run.
	collected.covered = append(collected.covered, "disk:")
	usage, err := m.diskUsage(m.dataDir)
	if err != nil {
		addCheckError(collected, now, "disk", m.dataDir, err)
		return
	}
	if usage.TotalBytes == 0 {
		addCheckError(collected, now, "disk", m.dataDir, fmt.Errorf("filesystem reported total=0"))
		return
	}
	freePercent := float64(usage.AvailableBytes) * 100 / float64(usage.TotalBytes)
	freeMB := usage.AvailableBytes / (1024 * 1024)
	lowPercent := freePercent < float64(settings.diskFreePercent)
	lowMB := freeMB < uint64(settings.diskFreeMB)
	if !lowPercent && !lowMB {
		return
	}
	key := "disk:data"
	collected.observations[key] = observation{
		finding: Finding{
			Key: key, Kind: kindDiskSpace, Severity: SeverityCritical, Resource: m.dataDir,
			Message: fmt.Sprintf("数据目录磁盘空间不足：可用 %.1f%% / %d MiB（阈值 %d%% / %d MiB）", freePercent, freeMB, settings.diskFreePercent, settings.diskFreeMB),
		},
		required: diskFailureThreshold,
		fields: map[string]any{
			"free_percent": freePercent, "free_mb": freeMB,
			"threshold_percent": settings.diskFreePercent, "threshold_mb": settings.diskFreeMB,
		},
	}
}

func (m *Monitor) collectBackup(now time.Time, settings inspectionSettings, collected *collection) {
	m.backupMu.RLock()
	result := m.backup
	m.backupMu.RUnlock()
	collected.covered = append(collected.covered, "backup:failed")
	if result.Error != "" {
		// A concrete failed attempt supersedes the age warning until a success.
		collected.covered = append(collected.covered, "backup:stale")
		key := "backup:failed"
		resource := "database backup"
		if result.Name != "" {
			resource += " " + filepath.Base(result.Name)
		}
		collected.observations[key] = observation{
			finding: Finding{
				Key: key, Kind: kindBackupFailed, Severity: SeverityCritical, Resource: resource,
				Message: fmt.Sprintf("数据库备份失败：%s（%s）", result.Error, result.At.UTC().Format(time.RFC3339)),
			},
			required: 1,
			fields:   map[string]any{"name": result.Name, "error": result.Error, "failed_at": result.At.UTC().Format(time.RFC3339)},
		}
		return
	}

	latest, latestName, err := latestBackupFile(filepath.Join(m.dataDir, "backups"))
	if err != nil && result.LastSuccessAt.IsZero() {
		addCheckError(collected, now, "backup", filepath.Join(m.dataDir, "backups"), err)
		return
	}
	if err != nil {
		addCheckError(collected, now, "backup", filepath.Join(m.dataDir, "backups"), err)
	}
	if latest.After(result.LastSuccessAt) {
		result.LastSuccessAt = latest
		result.LastSuccessName = latestName
	}
	collected.covered = append(collected.covered, "backup:stale")
	stale := result.LastSuccessAt.IsZero() || now.Sub(result.LastSuccessAt) > settings.backupMaxAge
	if !stale {
		return
	}
	key := "backup:stale"
	message := "数据库尚无成功备份记录"
	if !result.LastSuccessAt.IsZero() {
		message = fmt.Sprintf("数据库备份已过期：最近成功备份 %s（%s），允许最大间隔 %d 小时",
			result.LastSuccessName, result.LastSuccessAt.UTC().Format(time.RFC3339), int(settings.backupMaxAge/time.Hour))
	}
	collected.observations[key] = observation{
		finding:  Finding{Key: key, Kind: kindBackupStale, Severity: SeverityWarning, Resource: "database backup", Message: message},
		required: 1,
		fields: map[string]any{
			"name": result.LastSuccessName, "last_success_at": result.LastSuccessAt.UTC().Format(time.RFC3339),
			"max_age_hours": int(settings.backupMaxAge / time.Hour),
		},
	}
}

func latestBackupFile(dir string) (time.Time, string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return time.Time{}, "", nil
	}
	if err != nil {
		return time.Time{}, "", err
	}
	var latest time.Time
	latestName := ""
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "niubwaf-") || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return time.Time{}, "", err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if latest.IsZero() || info.ModTime().After(latest) {
			latest = info.ModTime()
			latestName = entry.Name()
		}
	}
	return latest, latestName, nil
}

func (m *Monitor) collectGeo(ctx context.Context, now time.Time, settings inspectionSettings, collected *collection) {
	if m.geoSource == nil {
		return
	}
	items, err := m.geoSource.GeoSnapshot(ctx)
	if err != nil {
		addCheckError(collected, now, "geo", "", err)
		return
	}
	collected.covered = append(collected.covered, "geo:")
	for _, item := range items {
		canonical, kind, maxAge := geoKind(item.Kind, settings)
		if canonical == "" {
			addCheckError(collected, now, "geo", item.Path, fmt.Errorf("unknown geo data kind %q", item.Kind))
			continue
		}
		if strings.TrimSpace(item.Path) == "" {
			addCheckError(collected, now, "geo", canonical, fmt.Errorf("loaded geo data has an empty path"))
			continue
		}
		dataTime := item.BuildTime
		if dataTime.IsZero() {
			dataTime = item.ModTime
		}
		if dataTime.IsZero() {
			addCheckError(collected, now, "geo", item.Path, fmt.Errorf("loaded geo data has neither build time nor modtime"))
			continue
		}
		age := now.Sub(dataTime)
		if age <= maxAge {
			continue
		}
		key := "geo:" + canonical + ":" + item.Path
		collected.observations[key] = observation{
			finding: Finding{
				Key: key, Kind: kind, Severity: SeverityWarning, Resource: item.Path,
				Message: fmt.Sprintf("%s 数据已过期：%s，数据时间 %s（已 %d 天，阈值 %d 天）",
					canonical, item.Path, dataTime.UTC().Format(time.RFC3339), int(age/(24*time.Hour)), int(maxAge/(24*time.Hour))),
			},
			required: 1,
			fields: map[string]any{
				"path": item.Path, "data_time": dataTime.UTC().Format(time.RFC3339),
				"age_days": int(age / (24 * time.Hour)), "max_age_days": int(maxAge / (24 * time.Hour)),
			},
		}
	}
}

func geoKind(kind string, settings inspectionSettings) (canonical, findingKind string, maxAge time.Duration) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "geoip", "mmdb":
		return "GeoIP", kindGeoIPStale, settings.geoIPMaxAge
	case "ip2region", "xdb":
		return "ip2region", kindIP2RegionStale, settings.ip2regionMaxAge
	default:
		return "", "", 0
	}
}

func addCheckError(collected *collection, now time.Time, source, resource string, err error) {
	collected.errors = append(collected.errors, CheckError{Source: source, Resource: resource, Message: err.Error(), Time: now})
}

func joinPath(parts ...string) string { return filepath.Join(parts...) }
