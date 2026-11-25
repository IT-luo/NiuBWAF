package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func configSyncExpectation(p *ConfigImportPreview) ConfigApplyExpectation {
	return ConfigApplyExpectation{
		PackageSHA256: p.PackageSHA256, TargetSHA256: p.TargetSHA256,
		PreviewSHA256: p.PreviewSHA256, ConfirmDeletes: configDeleteCount(p.Stats),
	}
}

func configSyncSite(t *testing.T, s *Store, domain, upstream string) Site {
	t.Helper()
	v := Site{Name: domain, Domain: domain, Upstream: upstream, Enabled: true, WAFMode: "balanced", DynamicMode: "off", BotMode: "off"}
	if err := s.CreateSite(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func configSyncRule(t *testing.T, s *Store, siteID int64, name string, priority int) CustomRule {
	t.Helper()
	v := CustomRule{SiteID: siteID, Name: name, Enabled: true, Priority: priority, Logic: "and", Conditions: `[{"field":"path","op":"prefix","value":"/admin"}]`, Action: "block"}
	if err := s.CreateRule(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestConfigSyncMergeAcrossDifferentIDsAndIdempotent(t *testing.T) {
	source, target := repTestStore(t), repTestStore(t)
	sourceSite := configSyncSite(t, source, "Example.COM.", "http://10.0.0.10:8080/base")
	configSyncRule(t, source, sourceSite.ID, "shared", 20)
	if err := source.AddExclusion(&Exclusion{SiteID: sourceSite.ID, RuleID: 941100, URLPrefix: "/api", Param: "q", Note: "source"}); err != nil {
		t.Fatal(err)
	}
	if err := source.AddIP("black", "2001:0db8::1", "v6", ""); err != nil {
		t.Fatal(err)
	}
	if err := source.SetSetting("semantic_mode", "block"); err != nil {
		t.Fatal(err)
	}

	// 先插入无关站点，确保同名站点和规则在两端使用不同数据库 ID。
	configSyncSite(t, target, "placeholder.test", "http://127.0.0.1")
	targetSite := configSyncSite(t, target, "example.com", "http://127.0.0.1:9000")
	targetSite.AuthPass = HashPass("target-password")
	targetSite.CertPEM, targetSite.KeyPEM = "target-cert", "target-key"
	if _, err := target.UpdateSite(&targetSite, true); err != nil {
		t.Fatal(err)
	}
	targetRule := configSyncRule(t, target, targetSite.ID, "shared", 90)
	configSyncRule(t, target, targetSite.ID, "target-only", 100)
	if err := target.AddExclusion(&Exclusion{SiteID: targetSite.ID, RuleID: 941100, URLPrefix: "/api", Param: "q", Note: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := target.AddIP("black", "2001:db8::1", "old", ""); err != nil {
		t.Fatal(err)
	}
	if err := target.AddIP("white", "192.0.2.8", "keep", ""); err != nil {
		t.Fatal(err)
	}

	pkg, err := source.ExportConfig("node-a")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := target.PreviewConfigImport(pkg, "merge")
	if err != nil {
		t.Fatal(err)
	}
	if got := preview.Stats["sites"]; got.Update != 1 || got.Skip != 1 {
		t.Fatalf("站点 merge 统计异常: %+v", got)
	}
	if got := preview.Stats["custom_rules"]; got.Update != 1 || got.Skip != 1 {
		t.Fatalf("规则 merge 统计异常: %+v", got)
	}
	if len(preview.Deletions) != 0 {
		t.Fatalf("merge 不应产生删除清单: %+v", preview.Deletions)
	}
	if _, err := target.ApplyConfigImport(pkg, "merge", configSyncExpectation(preview)); err != nil {
		t.Fatal(err)
	}

	gotSite, err := target.GetSite(targetSite.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotSite.Upstream != "http://10.0.0.10:8080/base" || gotSite.AuthPass != targetSite.AuthPass || gotSite.CertPEM != "target-cert" || gotSite.KeyPEM != "target-key" {
		t.Fatalf("跨 ID 更新未保留目标本地认证/证书")
	}
	rules, err := target.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	var shared, targetOnly *CustomRule
	for i := range rules {
		switch rules[i].Name {
		case "shared":
			shared = &rules[i]
		case "target-only":
			targetOnly = &rules[i]
		}
	}
	if shared == nil || shared.ID != targetRule.ID || shared.SiteID != targetSite.ID || shared.Priority != 20 {
		t.Fatalf("共享规则未按 domain+name 映射: %+v", shared)
	}
	if targetOnly == nil {
		t.Fatal("merge 删除了目标独有规则")
	}
	ips, _ := target.ListIPs("")
	if len(ips) != 2 {
		t.Fatalf("规范 IP 应合并且 merge 应保留目标独有名單, got %+v", ips)
	}
	if got := target.GetSetting("semantic_mode"); got != "block" {
		t.Fatalf("settings 缓存未刷新: %q", got)
	}

	second, err := target.PreviewConfigImport(pkg, "merge")
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"sites", "custom_rules", "exclusions", "ip_lists"} {
		stat := second.Stats[resource]
		if stat.Create != 0 || stat.Update != 0 || stat.Delete != 0 {
			t.Fatalf("二次 %s 预览应幂等: %+v", resource, stat)
		}
	}
	if _, err := target.ApplyConfigImport(pkg, "merge", configSyncExpectation(second)); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSyncReplaceDeletesOnlyListedPortableConfig(t *testing.T) {
	source, target := repTestStore(t), repTestStore(t)
	configSyncSite(t, source, "shared.test", "http://source")
	shared := configSyncSite(t, target, "shared.test", "http://old")
	shared.AuthPass, shared.CertPEM, shared.KeyPEM = HashPass("keep"), "local-cert", "local-key"
	if _, err := target.UpdateSite(&shared, true); err != nil {
		t.Fatal(err)
	}
	extra := configSyncSite(t, target, "extra.test", "http://extra")
	configSyncRule(t, target, extra.ID, "extra-rule", 1)
	if err := target.AddExclusion(&Exclusion{SiteID: extra.ID, RuleID: 932100, URLPrefix: "/extra"}); err != nil {
		t.Fatal(err)
	}
	if err := target.AddIP("black", "192.0.2.99", "delete", ""); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"admin_pass": "local-admin", "cookie_secret": "local-cookie", "metrics_token": "local-metrics",
		"intel_api_key": "local-intel", "alert_webhook": "https://local-alert", "acme_enabled": "on",
		"trusted_proxies": "127.0.0.1", "block_page": "target-only-safe-setting",
	} {
		if err := target.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}

	pkg, err := source.ExportConfig("replace-source")
	if err != nil {
		t.Fatal(err)
	}
	// 构造合法的精简包，验证 replace 也会删除目标独有的白名单设置。
	delete(pkg.Payload.Settings, "block_page")
	pkg.PayloadSHA256, err = configSHA256(pkg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := target.PreviewConfigImport(pkg, "replace")
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Deletions) == 0 || len(preview.Deletions) != configDeleteCount(preview.Stats) {
		t.Fatalf("replace 必须返回完整删除清单: %+v stats=%+v", preview.Deletions, preview.Stats)
	}
	joined, _ := json.Marshal(preview.Deletions)
	for _, key := range []string{"extra.test", "extra-rule", "black/192.0.2.99", "block_page"} {
		if !strings.Contains(string(joined), key) {
			t.Fatalf("删除清单缺少 %s: %s", key, joined)
		}
	}
	bad := configSyncExpectation(preview)
	bad.ConfirmDeletes--
	if _, err := target.ApplyConfigImport(pkg, "replace", bad); !errors.Is(err, ErrConfigDeleteConfirm) {
		t.Fatalf("错误删除确认应失败: %v", err)
	}
	if _, err := target.ApplyConfigImport(pkg, "replace", configSyncExpectation(preview)); err != nil {
		t.Fatal(err)
	}
	if _, err := target.GetSite(extra.ID); err == nil {
		t.Fatal("replace 未删除目标独有站点")
	}
	rules, _ := target.ListRules()
	exclusions, _ := target.ListExclusions()
	ips, _ := target.ListIPs("")
	if len(rules) != 0 || len(exclusions) != 0 || len(ips) != 0 {
		t.Fatalf("replace 子配置删除不完整: rules=%d exclusions=%d ips=%d", len(rules), len(exclusions), len(ips))
	}
	got, _ := target.GetSite(shared.ID)
	if got.AuthPass != shared.AuthPass || got.CertPEM != "local-cert" || got.KeyPEM != "local-key" {
		t.Fatal("replace 覆盖了目标认证哈希或证书私钥")
	}
	for k, want := range map[string]string{"admin_pass": "local-admin", "cookie_secret": "local-cookie", "metrics_token": "local-metrics", "intel_api_key": "local-intel", "alert_webhook": "https://local-alert", "acme_enabled": "on", "trusted_proxies": "127.0.0.1"} {
		if got := target.GetSetting(k); got != want {
			t.Fatalf("节点本地设置 %s 被修改", k)
		}
	}
	if got := target.GetSetting("block_page"); got != "" {
		t.Fatalf("目标独有可移植 setting 未删除: %q", got)
	}
}

func TestConfigSyncSecretsNeverExported(t *testing.T) {
	s := repTestStore(t)
	canaries := map[string]string{
		"admin_pass": "CANARY_ADMIN", "cookie_secret": "CANARY_COOKIE", "metrics_token": "CANARY_METRICS",
		"intel_api_key": "CANARY_INTEL_KEY", "intel_api_url": "https://CANARY_INTEL_URL",
		"alert_webhook": "https://CANARY_ALERT", "alert_dingtalk": "CANARY_DINGTALK",
		"alert_wecom": "CANARY_WECOM", "acme_email": "CANARY_ACME", "trusted_proxies": "CANARY_PROXIES",
	}
	for k, v := range canaries {
		if err := s.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	site := configSyncSite(t, s, "secret.test", "http://127.0.0.1")
	site.AuthPass, site.CertPEM, site.KeyPEM = "CANARY_AUTH_HASH", "CANARY_CERT", "CANARY_PRIVATE_KEY"
	if _, err := s.UpdateSite(&site, true); err != nil {
		t.Fatal(err)
	}
	pkg, err := s.ExportConfig("safe-label")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range canaries {
		if strings.Contains(string(raw), canary) {
			t.Fatalf("导出包泄露秘密 canary %q", canary)
		}
	}
	for _, canary := range []string{"CANARY_AUTH_HASH", "CANARY_CERT", "CANARY_PRIVATE_KEY"} {
		if strings.Contains(string(raw), canary) {
			t.Fatalf("导出包泄露站点秘密 %q", canary)
		}
	}
	for _, field := range []string{"auth_pass", "cert_pem", "key_pem", "admin_pass", "cookie_secret", "metrics_token", "intel_api_key", "alert_webhook", "acme_enabled", "trusted_proxies", "site_id", `"id"`} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("导出包不应包含字段 %s", field)
		}
	}
}

func TestConfigSyncRejectsUnsafeUpstreamAndUnknownConditionFields(t *testing.T) {
	for _, upstream := range []string{"http://user:password@example.com", "http://example.com/path?token=secret"} {
		t.Run(upstream, func(t *testing.T) {
			s := repTestStore(t)
			configSyncSite(t, s, "unsafe.test", upstream)
			if _, err := s.ExportConfig("node"); !errors.Is(err, ErrConfigInvalid) {
				t.Fatalf("含 userinfo/query 的上游应拒绝导出: %v", err)
			}
		})
	}
	s := repTestStore(t)
	if err := s.CreateRule(&CustomRule{Name: "unknown", Enabled: true, Logic: "and", Conditions: `[{"field":"path","op":"eq","value":"/","unknown":"CANARY"}]`, Action: "block"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExportConfig("node"); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("conditions 未知字段应拒绝: %v", err)
	}
}

func TestConfigSyncTamperVersionUnknownFieldsAndDigests(t *testing.T) {
	source, target := repTestStore(t), repTestStore(t)
	configSyncSite(t, source, "digest.test", "http://source")
	pkg, err := source.ExportConfig("node-a")
	if err != nil {
		t.Fatal(err)
	}

	tampered := *pkg
	tampered.Payload.Sites = append([]ConfigSite(nil), pkg.Payload.Sites...)
	tampered.Payload.Sites[0].Name = "tampered"
	if err := ValidateConfigPackage(&tampered); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("篡改 payload 应失败: %v", err)
	}
	wrongVersion := *pkg
	wrongVersion.FormatVersion++
	if err := ValidateConfigPackage(&wrongVersion); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("未知版本应失败: %v", err)
	}
	raw, _ := json.Marshal(pkg)
	var object map[string]any
	json.Unmarshal(raw, &object)
	object["unknown"] = true
	raw, _ = json.Marshal(object)
	if _, err := ParseConfigPackage(raw); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("未知顶层字段应失败: %v", err)
	}

	preview, err := target.PreviewConfigImport(pkg, "merge")
	if err != nil {
		t.Fatal(err)
	}
	badPackage := configSyncExpectation(preview)
	badPackage.PackageSHA256 = strings.Repeat("0", 64)
	if _, err := target.ApplyConfigImport(pkg, "merge", badPackage); !errors.Is(err, ErrConfigDigest) {
		t.Fatalf("错误 package 摘要应失败: %v", err)
	}
	badPreview := configSyncExpectation(preview)
	badPreview.PreviewSHA256 = strings.Repeat("0", 64)
	if _, err := target.ApplyConfigImport(pkg, "merge", badPreview); !errors.Is(err, ErrConfigDigest) {
		t.Fatalf("错误 preview 摘要应失败: %v", err)
	}
	badTarget := configSyncExpectation(preview)
	badTarget.TargetSHA256 = strings.Repeat("0", 64)
	if _, err := target.ApplyConfigImport(pkg, "merge", badTarget); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("错误 target 摘要应返回冲突: %v", err)
	}
}

func TestConfigSyncTargetChangeConflict(t *testing.T) {
	source, target := repTestStore(t), repTestStore(t)
	configSyncSite(t, source, "conflict.test", "http://source")
	pkg, err := source.ExportConfig("node")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := target.PreviewConfigImport(pkg, "merge")
	if err != nil {
		t.Fatal(err)
	}
	if err := target.SetSetting("acme_enabled", "on"); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ApplyConfigImport(pkg, "merge", configSyncExpectation(preview)); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("预览后本地设置变化应返回冲突: %v", err)
	}
	if _, err := target.GetSite(1); err == nil {
		t.Fatal("冲突时不应写入任何站点")
	}
}

func TestConfigSyncTransactionRollback(t *testing.T) {
	source, target := repTestStore(t), repTestStore(t)
	site := configSyncSite(t, source, "rollback.test", "http://source")
	configSyncRule(t, source, site.ID, "boom", 1)
	if err := source.SetSetting("geoip_mode", "block"); err != nil {
		t.Fatal(err)
	}
	pkg, err := source.ExportConfig("node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB.Exec(`CREATE TRIGGER config_sync_fail BEFORE INSERT ON custom_rules WHEN NEW.name='boom' BEGIN SELECT RAISE(ABORT,'forced rollback'); END`); err != nil {
		t.Fatal(err)
	}
	preview, err := target.PreviewConfigImport(pkg, "merge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.ApplyConfigImport(pkg, "merge", configSyncExpectation(preview)); err == nil {
		t.Fatal("规则写入失败应使 apply 失败")
	}
	sites, _ := target.ListSites()
	rules, _ := target.ListRules()
	if len(sites) != 0 || len(rules) != 0 {
		t.Fatalf("事务未完整回滚: sites=%d rules=%d", len(sites), len(rules))
	}
	if got := target.GetSetting("geoip_mode"); got != "" {
		t.Fatalf("回滚后 settings 缓存被污染: %q", got)
	}
	var value string
	if err := target.DB.QueryRow(`SELECT value FROM settings WHERE key='geoip_mode'`).Scan(&value); err == nil {
		t.Fatalf("回滚后 settings 表被污染: %q", value)
	}
}

func TestConfigSyncBoundedDiffRetainsReputationRefresh(t *testing.T) {
	target := repTestStore(t)
	pkg := &ConfigPackage{Kind: ConfigKind, FormatVersion: ConfigFormatVersion, CreatedAt: "2026-01-01T00:00:00Z", SourceLabel: "bounded"}
	pkg.Payload.Settings = map[string]string{"rep_threshold": "42"}
	pkg.Payload.Sites = make([]ConfigSite, 0, maxConfigDiffEntries+20)
	for i := 0; i < maxConfigDiffEntries+20; i++ {
		pkg.Payload.Sites = append(pkg.Payload.Sites, ConfigSite{Name: "site", Domain: fmt.Sprintf("site-%d.test", i), Upstream: "http://127.0.0.1", Enabled: true})
	}
	var err error
	pkg.PayloadSHA256, err = configSHA256(pkg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := target.PreviewConfigImport(pkg, "merge")
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Diff) != maxConfigDiffEntries || !preview.DiffTruncated {
		t.Fatalf("diff 未按上限截断: len=%d truncated=%v", len(preview.Diff), preview.DiffTruncated)
	}
	if !preview.ReputationChanged {
		t.Fatal("diff 截断不应丢失必要的信誉刷新标记")
	}
}

func TestConfigSyncRejectsNewBasicAuthSiteWithoutPassword(t *testing.T) {
	source, target := repTestStore(t), repTestStore(t)
	site := configSyncSite(t, source, "auth.test", "http://source")
	site.AuthUser, site.AuthPass = "admin", HashPass("source-password")
	if _, err := source.UpdateSite(&site, false); err != nil {
		t.Fatal(err)
	}
	pkg, err := source.ExportConfig("node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.PreviewConfigImport(pkg, "merge"); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("无目标口令的新 Basic Auth 站点应拒绝: %v", err)
	}
}
