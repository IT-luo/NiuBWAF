package store

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"niubwaf/internal/engine"
)

const (
	ConfigKind          = "niubwaf-config"
	ConfigFormatVersion = 1

	// MaxConfigPackageBytes 同时约束文件导入与 API 内嵌包，避免解析无限配置。
	MaxConfigPackageBytes = 4 << 20
	maxConfigSites        = 1024
	maxConfigRules        = 4096
	maxConfigExclusions   = 8192
	maxConfigIPs          = 8192
	maxConfigDiffEntries  = 256
)

var (
	ErrConfigInvalid       = errors.New("配置包无效")
	ErrConfigConflict      = errors.New("目标配置已在预览后变化")
	ErrConfigDigest        = errors.New("配置应用摘要不匹配")
	ErrConfigDeleteConfirm = errors.New("replace 删除确认数量不匹配")
	configExclusionParamRe = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]+$`)
	configPortableSettings = map[string]string{
		"block_page": "", "geoip_mode": "off", "geoip_countries": "",
		"log_retention_days": "30", "semantic_mode": "observe",
		"reputation_enabled": "on", "rep_window": "24", "rep_threshold": "30",
		"rep_ban_ttl": "60", "rep_max_ttl": "1440", "alert_enabled": "off",
		"alert_threshold": "50", "alert_window": "60", "alert_cooldown": "300",
		"body_inspect_kb": "2048", "body_scan_kb": "16", "allowed_content_types": "",
		"bot_verify_crawlers": "off", "bot_path_limit": "0",
		"inspect_interval_sec": "60", "inspect_cert_warn_days": "14", "inspect_upstream_failures": "3",
		"inspect_disk_free_percent": "10", "inspect_disk_free_mb": "1024", "inspect_backup_max_age_hours": "26",
		"inspect_geoip_max_age_days": "30", "inspect_ip2region_max_age_days": "90", "inspect_cooldown_sec": "21600",
	}
)

// ConfigPackage 是人工双节点迁移的完整性校验包。哈希不是加密或来源认证。
type ConfigPackage struct {
	Kind          string        `json:"kind"`
	FormatVersion int           `json:"format_version"`
	CreatedAt     string        `json:"created_at"`
	SourceLabel   string        `json:"source_label"`
	Payload       ConfigPayload `json:"payload"`
	PayloadSHA256 string        `json:"payload_sha256"`
}

// ConfigPayload 只包含可移植配置，绝不包含数据库 ID、口令哈希或证书私钥。
type ConfigPayload struct {
	Sites       []ConfigSite      `json:"sites"`
	Settings    map[string]string `json:"settings"`
	CustomRules []ConfigRule      `json:"custom_rules"`
	Exclusions  []ConfigExclusion `json:"exclusions"`
	IPLists     []ConfigIP        `json:"ip_lists"`
}

type ConfigSite struct {
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	Upstream     string `json:"upstream"`
	Enabled      bool   `json:"enabled"`
	WAFMode      string `json:"waf_mode"`
	AuthUser     string `json:"auth_user"`
	CCRate       int    `json:"cc_rate"`
	CCBurst      int    `json:"cc_burst"`
	Captcha      bool   `json:"captcha"`
	RespDetect   bool   `json:"resp_detect"`
	DynamicMode  string `json:"dynamic_mode"`
	BotMode      string `json:"bot_mode"`
	BotStrict    bool   `json:"bot_strict"`
	HTTPRedirect bool   `json:"http_redirect"`
}

type ConfigRule struct {
	SiteDomain  string `json:"site_domain"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
	Logic       string `json:"logic"`
	Conditions  string `json:"conditions"`
	Action      string `json:"action"`
	ActionParam string `json:"action_param"`
	Shadow      bool   `json:"shadow"`
	Note        string `json:"note"`
}

type ConfigExclusion struct {
	SiteDomain string `json:"site_domain"`
	RuleID     int    `json:"rule_id"`
	URLPrefix  string `json:"url_prefix"`
	Param      string `json:"param"`
	Note       string `json:"note"`
}

type ConfigIP struct {
	Kind      string `json:"kind"`
	IP        string `json:"ip"`
	Note      string `json:"note"`
	ExpiresAt string `json:"expires_at"`
}

type ConfigChangeStats struct {
	Create    int `json:"create"`
	Update    int `json:"update"`
	Skip      int `json:"skip"`
	Delete    int `json:"delete"`
	Unchanged int `json:"unchanged"`
}

// ConfigDiffEntry 只暴露自然键和变化字段名，不暴露旧值、新值或秘密。
type ConfigDiffEntry struct {
	Resource string   `json:"resource"`
	Action   string   `json:"action"`
	Key      string   `json:"key"`
	Fields   []string `json:"fields,omitempty"`
}

type ConfigDeletion struct {
	Resource string `json:"resource"`
	Key      string `json:"key"`
}

// ConfigImportPreview 的三个摘要必须原样带回 apply，形成显式的人工确认链。
type ConfigImportPreview struct {
	Mode              string                       `json:"mode"`
	PackageSHA256     string                       `json:"package_sha256"`
	TargetSHA256      string                       `json:"target_sha256"`
	PreviewSHA256     string                       `json:"preview_sha256"`
	Stats             map[string]ConfigChangeStats `json:"stats"`
	Diff              []ConfigDiffEntry            `json:"diff"`
	Deletions         []ConfigDeletion             `json:"deletions"`
	Warnings          []string                     `json:"warnings"`
	DiffTruncated     bool                         `json:"diff_truncated"`
	ReputationChanged bool                         `json:"-"`
}

type ConfigApplyExpectation struct {
	PackageSHA256  string `json:"package_sha256"`
	TargetSHA256   string `json:"target_sha256"`
	PreviewSHA256  string `json:"preview_sha256"`
	ConfirmDeletes int    `json:"confirm_deletes"`
}

type configTarget struct {
	Sites      []Site            `json:"sites"`
	Settings   map[string]string `json:"settings"`
	Rules      []CustomRule      `json:"custom_rules"`
	Exclusions []Exclusion       `json:"exclusions"`
	IPs        []IPEntry         `json:"ip_lists"`
}

type configQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
}

type configImportPlan struct {
	preview *ConfigImportPreview
	source  ConfigPayload
	target  ConfigPayload
	raw     *configTarget
}

func configInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrConfigInvalid, fmt.Sprintf(format, args...))
}

func configSHA256(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func configHashEqual(got, want string) bool {
	if len(got) != 64 || len(want) != 64 {
		return false
	}
	g, err1 := hex.DecodeString(got)
	w, err2 := hex.DecodeString(want)
	return err1 == nil && err2 == nil && subtle.ConstantTimeCompare(g, w) == 1
}

// ParseConfigPackage 严格解码包并验证完整性、版本、字段、数量和配置语义。
func ParseConfigPackage(data []byte) (*ConfigPackage, error) {
	if len(data) == 0 || len(data) > MaxConfigPackageBytes {
		return nil, configInvalid("包大小必须在 1 到 %d 字节之间", MaxConfigPackageBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var pkg ConfigPackage
	if err := dec.Decode(&pkg); err != nil {
		return nil, configInvalid("JSON 结构或未知字段错误")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, configInvalid("包只能包含一个 JSON 值")
	}
	if err := ValidateConfigPackage(&pkg); err != nil {
		return nil, err
	}
	return &pkg, nil
}

// ValidateConfigPackage 校验 API 已解码的包，并把可移植字段规范化。
func ValidateConfigPackage(pkg *ConfigPackage) error {
	if pkg == nil {
		return configInvalid("包不能为空")
	}
	if pkg.Kind != ConfigKind || pkg.FormatVersion != ConfigFormatVersion {
		return configInvalid("kind 或 format_version 不受支持")
	}
	if _, err := time.Parse(time.RFC3339, pkg.CreatedAt); err != nil {
		return configInvalid("created_at 必须为 RFC3339 时间")
	}
	pkg.SourceLabel = strings.TrimSpace(pkg.SourceLabel)
	if pkg.SourceLabel == "" || len(pkg.SourceLabel) > 128 || !utf8.ValidString(pkg.SourceLabel) || strings.ContainsAny(pkg.SourceLabel, "\r\n\x00") {
		return configInvalid("source_label 长度或字符无效")
	}
	payloadDigest, err := configSHA256(pkg.Payload)
	if err != nil || !configHashEqual(pkg.PayloadSHA256, payloadDigest) {
		return configInvalid("payload_sha256 完整性校验失败")
	}
	normalized, err := normalizeConfigPayload(pkg.Payload)
	if err != nil {
		return err
	}
	pkg.Payload = normalized
	pkg.PayloadSHA256, err = configSHA256(pkg.Payload)
	if err != nil {
		return configInvalid("payload 无法序列化")
	}
	if raw, err := json.Marshal(pkg); err != nil || len(raw) > MaxConfigPackageBytes {
		return configInvalid("规范化后的包超过大小限制")
	}
	return nil
}

// ConfigPackageDigest 返回整个规范化包的摘要，供 preview/apply 绑定。
func ConfigPackageDigest(pkg *ConfigPackage) (string, error) {
	if err := ValidateConfigPackage(pkg); err != nil {
		return "", err
	}
	return configSHA256(pkg)
}

// ExportConfig 从一致性读快照生成手工迁移包，不读取日志、流量、审计或信誉表。
func (s *Store) ExportConfig(sourceLabel string) (*ConfigPackage, error) {
	sourceLabel = strings.TrimSpace(sourceLabel)
	if sourceLabel == "" {
		sourceLabel = "manual"
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	target, err := readConfigTarget(tx)
	if err != nil {
		return nil, err
	}
	payload, err := portableConfigFromTarget(target, true)
	if err != nil {
		return nil, err
	}
	pkg := &ConfigPackage{
		Kind: ConfigKind, FormatVersion: ConfigFormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), SourceLabel: sourceLabel,
		Payload: payload,
	}
	pkg.PayloadSHA256, err = configSHA256(pkg.Payload)
	if err != nil {
		return nil, err
	}
	if err := ValidateConfigPackage(pkg); err != nil {
		return nil, err
	}
	if raw, err := json.Marshal(pkg); err != nil || len(raw) > MaxConfigPackageBytes {
		return nil, configInvalid("导出包超过大小限制")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pkg, nil
}

// PreviewConfigImport 在只读事务中生成有界 diff、完整删除清单和目标摘要。
func (s *Store) PreviewConfigImport(pkg *ConfigPackage, mode string) (*ConfigImportPreview, error) {
	if err := ValidateConfigPackage(pkg); err != nil {
		return nil, err
	}
	mode, err := normalizeConfigMode(mode)
	if err != nil {
		return nil, err
	}
	packageDigest, err := configSHA256(pkg)
	if err != nil {
		return nil, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	target, err := readConfigTarget(tx)
	if err != nil {
		return nil, err
	}
	targetDigest, err := configSHA256(target)
	if err != nil {
		return nil, err
	}
	plan, err := buildConfigImportPlan(pkg.Payload, target, mode)
	if err != nil {
		return nil, err
	}
	plan.preview.PackageSHA256 = packageDigest
	plan.preview.TargetSHA256 = targetDigest
	plan.preview.PreviewSHA256, err = configPreviewDigest(plan.preview)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return plan.preview, nil
}

// ApplyConfigImport 重新计算预览并在同一事务中应用；任何失败都会回滚。
func (s *Store) ApplyConfigImport(pkg *ConfigPackage, mode string, expected ConfigApplyExpectation) (*ConfigImportPreview, error) {
	if err := ValidateConfigPackage(pkg); err != nil {
		return nil, err
	}
	mode, err := normalizeConfigMode(mode)
	if err != nil {
		return nil, err
	}
	packageDigest, err := configSHA256(pkg)
	if err != nil {
		return nil, err
	}
	if !configHashEqual(expected.PackageSHA256, packageDigest) {
		return nil, ErrConfigDigest
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	target, err := readConfigTarget(tx)
	if err != nil {
		return nil, err
	}
	targetDigest, err := configSHA256(target)
	if err != nil {
		return nil, err
	}
	if !configHashEqual(expected.TargetSHA256, targetDigest) {
		return nil, ErrConfigConflict
	}
	plan, err := buildConfigImportPlan(pkg.Payload, target, mode)
	if err != nil {
		return nil, err
	}
	plan.preview.PackageSHA256 = packageDigest
	plan.preview.TargetSHA256 = targetDigest
	plan.preview.PreviewSHA256, err = configPreviewDigest(plan.preview)
	if err != nil {
		return nil, err
	}
	if !configHashEqual(expected.PreviewSHA256, plan.preview.PreviewSHA256) {
		return nil, ErrConfigDigest
	}
	deletes := configDeleteCount(plan.preview.Stats)
	if mode == "replace" && expected.ConfirmDeletes != deletes {
		return nil, ErrConfigDeleteConfirm
	}
	if mode == "merge" && expected.ConfirmDeletes != 0 {
		return nil, ErrConfigDeleteConfirm
	}
	if err := applyConfigPlan(tx, plan); err != nil {
		return nil, err
	}
	// 在提交前读取最终设置；提交后仅交换内存 map，不出现成功提交但缓存重载失败的窗口。
	newSettings, err := readAllConfigSettings(tx)
	if err != nil {
		return nil, err
	}
	// 提交与缓存交换期间持有 setMu：并发 SetSetting 即使在提交后先完成 DB 写入，
	// 也会随后更新同一把锁保护的新 map，不会被旧快照反向覆盖。
	s.setMu.Lock()
	if err := tx.Commit(); err != nil {
		s.setMu.Unlock()
		return nil, err
	}
	s.settings = newSettings
	s.settingsRevision++
	s.setMu.Unlock()
	return plan.preview, nil
}

func normalizeConfigMode(mode string) (string, error) {
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "replace" {
		return "", configInvalid("mode 必须为 merge 或 replace")
	}
	return mode, nil
}

func configPreviewDigest(p *ConfigImportPreview) (string, error) {
	copy := *p
	copy.PreviewSHA256 = ""
	return configSHA256(&copy)
}

func configDeleteCount(stats map[string]ConfigChangeStats) int {
	total := 0
	for _, kind := range []string{"sites", "settings", "custom_rules", "exclusions", "ip_lists"} {
		total += stats[kind].Delete
	}
	return total
}

func readConfigTarget(q configQueryer) (*configTarget, error) {
	t := &configTarget{Settings: map[string]string{}, Sites: []Site{}, Rules: []CustomRule{}, Exclusions: []Exclusion{}, IPs: []IPEntry{}}
	settings, err := readAllConfigSettings(q)
	if err != nil {
		return nil, err
	}
	t.Settings = settings
	rows, err := q.Query(`SELECT id,name,domain,upstream,enabled,waf_mode,auth_user,auth_pass,cc_rate,cc_burst,captcha,resp_detect,dynamic_mode,bot_mode,bot_strict,cert_pem,key_pem,http_redirect,created_at FROM sites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v Site
		if err := rows.Scan(&v.ID, &v.Name, &v.Domain, &v.Upstream, &v.Enabled, &v.WAFMode, &v.AuthUser, &v.AuthPass, &v.CCRate, &v.CCBurst, &v.Captcha, &v.RespDetect, &v.DynamicMode, &v.BotMode, &v.BotStrict, &v.CertPEM, &v.KeyPEM, &v.HTTPRedirect, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		t.Sites = append(t.Sites, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	rows, err = q.Query(`SELECT id,site_id,name,enabled,priority,logic,conditions,action,action_param,shadow,note,created_at FROM custom_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v CustomRule
		if err := rows.Scan(&v.ID, &v.SiteID, &v.Name, &v.Enabled, &v.Priority, &v.Logic, &v.Conditions, &v.Action, &v.ActionParam, &v.Shadow, &v.Note, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		t.Rules = append(t.Rules, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	rows, err = q.Query(`SELECT id,site_id,rule_id,url_prefix,param,note,created_at FROM exclusions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v Exclusion
		if err := rows.Scan(&v.ID, &v.SiteID, &v.RuleID, &v.URLPrefix, &v.Param, &v.Note, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		t.Exclusions = append(t.Exclusions, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	rows, err = q.Query(`SELECT id,kind,ip,note,expires_at,created_at FROM ip_lists ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v IPEntry
		if err := rows.Scan(&v.ID, &v.Kind, &v.IP, &v.Note, &v.ExpiresAt, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		t.IPs = append(t.IPs, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return t, nil
}

func readAllConfigSettings(q configQueryer) (map[string]string, error) {
	rows, err := q.Query(`SELECT key,value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k string
		var v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		if k == "admin_pass" && !v.Valid {
			return nil, fmt.Errorf("管理员密码记录为空值")
		}
		out[k] = v.String
	}
	return out, rows.Err()
}

func portableConfigFromTarget(t *configTarget, effectiveSettings bool) (ConfigPayload, error) {
	p := ConfigPayload{Sites: []ConfigSite{}, Settings: map[string]string{}, CustomRules: []ConfigRule{}, Exclusions: []ConfigExclusion{}, IPLists: []ConfigIP{}}
	siteDomains := map[int64]string{}
	for _, v := range t.Sites {
		domain, err := canonicalConfigDomain(v.Domain)
		if err != nil {
			return p, err
		}
		siteDomains[v.ID] = domain
		p.Sites = append(p.Sites, ConfigSite{
			Name: v.Name, Domain: domain, Upstream: v.Upstream, Enabled: v.Enabled,
			WAFMode: v.WAFMode, AuthUser: v.AuthUser, CCRate: v.CCRate, CCBurst: v.CCBurst,
			Captcha: v.Captcha, RespDetect: v.RespDetect, DynamicMode: v.DynamicMode,
			BotMode: v.BotMode, BotStrict: v.BotStrict, HTTPRedirect: v.HTTPRedirect,
		})
	}
	for k, def := range configPortableSettings {
		if effectiveSettings {
			p.Settings[k] = def
			if v, ok := t.Settings[k]; ok {
				p.Settings[k] = v
			}
		} else if v, ok := t.Settings[k]; ok {
			p.Settings[k] = v
		}
	}
	for _, v := range t.Rules {
		domain := ""
		if v.SiteID != 0 {
			var ok bool
			domain, ok = siteDomains[v.SiteID]
			if !ok {
				return p, configInvalid("目标自定义规则引用了不存在的站点")
			}
		}
		p.CustomRules = append(p.CustomRules, ConfigRule{SiteDomain: domain, Name: v.Name, Enabled: v.Enabled, Priority: v.Priority, Logic: v.Logic, Conditions: v.Conditions, Action: v.Action, ActionParam: v.ActionParam, Shadow: v.Shadow, Note: v.Note})
	}
	for _, v := range t.Exclusions {
		domain := ""
		if v.SiteID != 0 {
			var ok bool
			domain, ok = siteDomains[v.SiteID]
			if !ok {
				return p, configInvalid("目标豁免引用了不存在的站点")
			}
		}
		p.Exclusions = append(p.Exclusions, ConfigExclusion{SiteDomain: domain, RuleID: v.RuleID, URLPrefix: v.URLPrefix, Param: v.Param, Note: v.Note})
	}
	for _, v := range t.IPs {
		p.IPLists = append(p.IPLists, ConfigIP{Kind: v.Kind, IP: v.IP, Note: v.Note, ExpiresAt: v.ExpiresAt})
	}
	return normalizeConfigPayload(p)
}

func normalizeConfigPayload(in ConfigPayload) (ConfigPayload, error) {
	out := ConfigPayload{Sites: []ConfigSite{}, Settings: map[string]string{}, CustomRules: []ConfigRule{}, Exclusions: []ConfigExclusion{}, IPLists: []ConfigIP{}}
	if len(in.Sites) > maxConfigSites || len(in.CustomRules) > maxConfigRules || len(in.Exclusions) > maxConfigExclusions || len(in.IPLists) > maxConfigIPs || len(in.Settings) > len(configPortableSettings) {
		return out, configInvalid("配置项数量超过限制")
	}
	seen := map[string]bool{}
	for _, item := range in.Sites {
		v, err := normalizeConfigSite(item)
		if err != nil {
			return out, err
		}
		if seen[v.Domain] {
			return out, configInvalid("站点 domain 重复: %s", v.Domain)
		}
		seen[v.Domain] = true
		out.Sites = append(out.Sites, v)
	}
	for k, raw := range in.Settings {
		if _, ok := configPortableSettings[k]; !ok {
			return out, configInvalid("settings 包含非白名单键: %s", k)
		}
		v, err := normalizeConfigSetting(k, raw)
		if err != nil {
			return out, err
		}
		out.Settings[k] = v
	}
	seen = map[string]bool{}
	for _, item := range in.CustomRules {
		v, err := normalizeConfigRule(item)
		if err != nil {
			return out, err
		}
		key := configRuleKey(v.SiteDomain, v.Name)
		if seen[key] {
			return out, configInvalid("自定义规则自然键重复")
		}
		seen[key] = true
		out.CustomRules = append(out.CustomRules, v)
	}
	seen = map[string]bool{}
	for _, item := range in.Exclusions {
		v, err := normalizeConfigExclusion(item)
		if err != nil {
			return out, err
		}
		key := configExclusionKey(v.SiteDomain, v.RuleID, v.URLPrefix, v.Param)
		if seen[key] {
			return out, configInvalid("豁免自然键重复")
		}
		seen[key] = true
		out.Exclusions = append(out.Exclusions, v)
	}
	seen = map[string]bool{}
	for _, item := range in.IPLists {
		v, err := normalizeConfigIP(item)
		if err != nil {
			return out, err
		}
		key := configIPKey(v.Kind, v.IP)
		if seen[key] {
			return out, configInvalid("IP 名单自然键重复")
		}
		seen[key] = true
		out.IPLists = append(out.IPLists, v)
	}
	for _, v := range out.CustomRules {
		if v.SiteDomain != "" && !configSiteExists(out.Sites, v.SiteDomain) {
			return out, configInvalid("自定义规则引用的站点不在包内: %s", v.SiteDomain)
		}
	}
	for _, v := range out.Exclusions {
		if v.SiteDomain != "" && !configSiteExists(out.Sites, v.SiteDomain) {
			return out, configInvalid("豁免引用的站点不在包内: %s", v.SiteDomain)
		}
	}
	sort.Slice(out.Sites, func(i, j int) bool { return out.Sites[i].Domain < out.Sites[j].Domain })
	sort.Slice(out.CustomRules, func(i, j int) bool {
		return configRuleKey(out.CustomRules[i].SiteDomain, out.CustomRules[i].Name) < configRuleKey(out.CustomRules[j].SiteDomain, out.CustomRules[j].Name)
	})
	sort.Slice(out.Exclusions, func(i, j int) bool {
		return configExclusionKey(out.Exclusions[i].SiteDomain, out.Exclusions[i].RuleID, out.Exclusions[i].URLPrefix, out.Exclusions[i].Param) < configExclusionKey(out.Exclusions[j].SiteDomain, out.Exclusions[j].RuleID, out.Exclusions[j].URLPrefix, out.Exclusions[j].Param)
	})
	sort.Slice(out.IPLists, func(i, j int) bool {
		return configIPKey(out.IPLists[i].Kind, out.IPLists[i].IP) < configIPKey(out.IPLists[j].Kind, out.IPLists[j].IP)
	})
	return out, nil
}

func normalizeConfigSite(v ConfigSite) (ConfigSite, error) {
	v.Name = strings.TrimSpace(v.Name)
	if v.Name == "" || len(v.Name) > 256 || !utf8.ValidString(v.Name) {
		return v, configInvalid("站点名称无效")
	}
	domain, err := canonicalConfigDomain(v.Domain)
	if err != nil {
		return v, err
	}
	v.Domain = domain
	v.Upstream, err = NormalizeUpstreams(v.Upstream)
	if err != nil {
		return v, configInvalid("站点 %s 的上游地址无效或含 userinfo/query", v.Domain)
	}
	if v.WAFMode == "" {
		v.WAFMode = "balanced"
	}
	if v.WAFMode != "balanced" && v.WAFMode != "strict" {
		return v, configInvalid("站点 %s 的 waf_mode 无效", v.Domain)
	}
	if v.DynamicMode == "" {
		v.DynamicMode = "off"
	}
	if v.DynamicMode != "off" && v.DynamicMode != "observe" && v.DynamicMode != "block" {
		return v, configInvalid("站点 %s 的 dynamic_mode 无效", v.Domain)
	}
	if v.BotMode == "" {
		v.BotMode = "off"
	}
	if v.BotMode != "off" && v.BotMode != "block" && v.BotMode != "captcha" && v.BotMode != "log" {
		return v, configInvalid("站点 %s 的 bot_mode 无效", v.Domain)
	}
	if len(v.AuthUser) > 256 || strings.ContainsAny(v.AuthUser, "\r\n\x00") || v.CCRate < 0 || v.CCRate > 1000000 || v.CCBurst < 0 || v.CCBurst > 1000000 {
		return v, configInvalid("站点 %s 的认证或限流字段无效", v.Domain)
	}
	return v, nil
}

func canonicalConfigDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || strings.ContainsAny(d, "/\\:@?#[]\r\n\t ") {
		return "", configInvalid("站点 domain 无效")
	}
	if ip := net.ParseIP(d); ip != nil {
		return ip.String(), nil
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", configInvalid("站点 domain 无效")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", configInvalid("站点 domain 无效")
			}
		}
	}
	return d, nil
}

func normalizeConfigRule(v ConfigRule) (ConfigRule, error) {
	var err error
	if v.SiteDomain != "" {
		v.SiteDomain, err = canonicalConfigDomain(v.SiteDomain)
		if err != nil {
			return v, err
		}
	}
	v.Name = strings.TrimSpace(v.Name)
	v.Note = strings.TrimSpace(v.Note)
	v.ActionParam = strings.TrimSpace(v.ActionParam)
	if v.Name == "" || len(v.Name) > 256 || len(v.Note) > 2048 || len(v.ActionParam) > 4096 || v.Priority < 0 || v.Priority > 100000 {
		return v, configInvalid("自定义规则字段长度或 priority 无效")
	}
	if v.Logic == "" {
		v.Logic = "and"
	}
	if v.Logic != "and" && v.Logic != "or" {
		return v, configInvalid("规则 %s 的 logic 无效", v.Name)
	}
	switch v.Action {
	case "allow", "block", "captcha", "log", engine.RuleActionRateLimit:
	case "redirect":
		if !validConfigRedirect(v.ActionParam) {
			return v, configInvalid("规则 %s 的 redirect 目标无效", v.Name)
		}
	default:
		return v, configInvalid("规则 %s 的 action 无效", v.Name)
	}
	conds, err := normalizeConfigConditions(v.Conditions)
	if err != nil {
		return v, configInvalid("规则 %s 的 conditions 无效或含未知字段", v.Name)
	}
	v.Conditions = conds
	if _, err := engine.CompileRule(engine.RuleDef{Name: v.Name, Priority: v.Priority, Logic: v.Logic, Conditions: v.Conditions, Action: v.Action, ActionParam: v.ActionParam, Shadow: v.Shadow}); err != nil {
		return v, configInvalid("规则 %s 未通过编译校验: %v", v.Name, err)
	}
	return v, nil
}

func normalizeConfigConditions(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return "", ErrConfigInvalid
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var conds []engine.RuleCondition
	if err := dec.Decode(&conds); err != nil {
		return "", ErrConfigInvalid
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return "", ErrConfigInvalid
	}
	b, err := json.Marshal(conds)
	if err != nil {
		return "", ErrConfigInvalid
	}
	return string(b), nil
}

func validConfigRedirect(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "/") {
		return !strings.HasPrefix(raw, "//") && !strings.HasPrefix(raw, "/\\")
	}
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

func normalizeConfigExclusion(v ConfigExclusion) (ConfigExclusion, error) {
	var err error
	if v.SiteDomain != "" {
		v.SiteDomain, err = canonicalConfigDomain(v.SiteDomain)
		if err != nil {
			return v, err
		}
	}
	v.URLPrefix = strings.TrimSpace(v.URLPrefix)
	v.Param = strings.TrimSpace(v.Param)
	v.Note = strings.TrimSpace(v.Note)
	if v.RuleID <= 0 || v.RuleID > 9999999 || len(v.URLPrefix) > 512 || len(v.Note) > 2048 || (v.Param != "" && !configExclusionParamRe.MatchString(v.Param)) {
		return v, configInvalid("豁免字段无效")
	}
	return v, nil
}

func normalizeConfigIP(v ConfigIP) (ConfigIP, error) {
	v.Kind = strings.TrimSpace(v.Kind)
	v.IP = strings.TrimSpace(v.IP)
	v.Note = strings.TrimSpace(v.Note)
	v.ExpiresAt = strings.TrimSpace(v.ExpiresAt)
	if v.Kind != "black" && v.Kind != "white" || len(v.Note) > 2048 {
		return v, configInvalid("IP 名单 kind 或 note 无效")
	}
	if strings.Contains(v.IP, "/") {
		_, network, err := net.ParseCIDR(v.IP)
		if err != nil {
			return v, configInvalid("IP/CIDR 无效")
		}
		v.IP = network.String()
	} else if ip := net.ParseIP(v.IP); ip != nil {
		v.IP = ip.String()
	} else {
		return v, configInvalid("IP/CIDR 无效")
	}
	if v.ExpiresAt != "" {
		tm, err := time.ParseInLocation("2006-01-02 15:04:05", v.ExpiresAt, time.Local)
		if err != nil {
			return v, configInvalid("IP 名单 expires_at 无效")
		}
		v.ExpiresAt = tm.Format("2006-01-02 15:04:05")
	}
	return v, nil
}

func normalizeConfigSetting(key, value string) (string, error) {
	if key != "block_page" {
		value = strings.TrimSpace(value)
	}
	if len(value) > 262144 || !utf8.ValidString(value) {
		return "", configInvalid("settings.%s 长度或编码无效", key)
	}
	enum := func(values ...string) (string, error) {
		for _, v := range values {
			if value == v {
				return value, nil
			}
		}
		return "", configInvalid("settings.%s 枚举值无效", key)
	}
	number := func(lo, hi int) (string, error) {
		n, err := strconv.Atoi(value)
		if err != nil || n < lo || n > hi {
			return "", configInvalid("settings.%s 数值超出范围", key)
		}
		return strconv.Itoa(n), nil
	}
	switch key {
	case "block_page":
		return value, nil
	case "geoip_mode":
		return enum("off", "block", "allow")
	case "semantic_mode":
		return enum("off", "observe", "block")
	case "reputation_enabled", "alert_enabled", "bot_verify_crawlers":
		return enum("on", "off")
	case "bot_path_limit":
		return number(0, 128)
	case "log_retention_days":
		return number(1, 3650)
	case "rep_window":
		return number(1, 168)
	case "rep_threshold":
		return number(1, 100000)
	case "rep_ban_ttl":
		return number(1, 10080)
	case "rep_max_ttl":
		return number(1, 43200)
	case "alert_threshold":
		return number(1, 1000000)
	case "alert_window":
		return number(10, 3600)
	case "alert_cooldown":
		return number(10, 86400)
	case "body_inspect_kb":
		return number(64, 102400)
	case "body_scan_kb":
		return number(16, 1024)
	case "inspect_interval_sec":
		return number(30, 3600)
	case "inspect_cert_warn_days":
		return number(1, 90)
	case "inspect_upstream_failures":
		return number(1, 20)
	case "inspect_disk_free_percent":
		return number(1, 90)
	case "inspect_disk_free_mb":
		return number(0, 1048576)
	case "inspect_backup_max_age_hours":
		return number(7, 8760)
	case "inspect_geoip_max_age_days", "inspect_ip2region_max_age_days":
		return number(1, 3650)
	case "inspect_cooldown_sec":
		return number(300, 604800)
	case "geoip_countries":
		parts := strings.Split(value, ",")
		seen := map[string]bool{}
		out := []string{}
		for _, p := range parts {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if len(p) != 2 || p[0] < 'A' || p[0] > 'Z' || p[1] < 'A' || p[1] > 'Z' || len(out) >= 256 {
				return "", configInvalid("settings.geoip_countries 无效")
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return strings.Join(out, ","), nil
	case "allowed_content_types":
		seen := map[string]bool{}
		out := []string{}
		for _, p := range strings.Split(value, ",") {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if !engine.ValidContentType(p) || len(out) >= 32 {
				return "", configInvalid("settings.allowed_content_types 无效")
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return strings.Join(out, ","), nil
	default:
		return "", configInvalid("settings 包含非白名单键")
	}
}

func configSiteExists(sites []ConfigSite, domain string) bool {
	for _, s := range sites {
		if s.Domain == domain {
			return true
		}
	}
	return false
}

func configRuleKey(domain, name string) string { return domain + "\x00" + name }
func configExclusionKey(domain string, ruleID int, prefix, param string) string {
	return domain + "\x00" + strconv.Itoa(ruleID) + "\x00" + prefix + "\x00" + param
}
func configIPKey(kind, ip string) string { return kind + "\x00" + ip }

func buildConfigImportPlan(source ConfigPayload, raw *configTarget, mode string) (*configImportPlan, error) {
	target, err := portableConfigFromTarget(raw, false)
	if err != nil {
		return nil, err
	}
	p := &ConfigImportPreview{
		Mode: mode, Stats: map[string]ConfigChangeStats{}, Diff: []ConfigDiffEntry{},
		Deletions: []ConfigDeletion{}, Warnings: []string{},
	}
	for _, kind := range []string{"sites", "settings", "custom_rules", "exclusions", "ip_lists"} {
		p.Stats[kind] = ConfigChangeStats{}
	}
	plan := &configImportPlan{preview: p, source: source, target: target, raw: raw}

	targetSites := map[string]ConfigSite{}
	rawSites := map[string]Site{}
	for _, v := range target.Sites {
		targetSites[v.Domain] = v
	}
	for _, v := range raw.Sites {
		domain, err := canonicalConfigDomain(v.Domain)
		if err != nil {
			return nil, err
		}
		rawSites[domain] = v
	}
	for _, v := range source.Sites {
		old, ok := targetSites[v.Domain]
		switch {
		case !ok:
			if v.AuthUser != "" {
				return nil, configInvalid("新建站点 %s 启用 Basic Auth，但包不携带口令；请先在目标设置口令", v.Domain)
			}
			plan.add("sites", "create", v.Domain, nil)
		case reflect.DeepEqual(old, v):
			plan.add("sites", "unchanged", v.Domain, nil)
		default:
			plan.add("sites", "update", v.Domain, configChangedFields(old, v))
		}
		if ok && v.AuthUser != "" && rawSites[v.Domain].AuthPass == "" {
			return nil, configInvalid("目标站点 %s 没有可保留的 Basic Auth 口令哈希", v.Domain)
		}
	}
	plan.remainingSites(targetSites, source.Sites, mode)

	targetSettings := target.Settings
	keys := make([]string, 0, len(source.Settings))
	for k := range source.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := source.Settings[k]
		old, ok := targetSettings[k]
		switch {
		case !ok:
			plan.add("settings", "create", k, nil)
		case old == v:
			plan.add("settings", "unchanged", k, nil)
		default:
			plan.add("settings", "update", k, []string{"value"})
		}
	}
	targetSettingKeys := make([]string, 0, len(targetSettings))
	for k := range targetSettings {
		targetSettingKeys = append(targetSettingKeys, k)
	}
	sort.Strings(targetSettingKeys)
	for _, k := range targetSettingKeys {
		if _, ok := source.Settings[k]; !ok {
			plan.remaining("settings", k, mode)
		}
	}

	targetRules := map[string]ConfigRule{}
	for _, v := range target.CustomRules {
		targetRules[configRuleKey(v.SiteDomain, v.Name)] = v
	}
	for _, v := range source.CustomRules {
		key := configRuleKey(v.SiteDomain, v.Name)
		old, ok := targetRules[key]
		display := configRuleDisplayKey(v.SiteDomain, v.Name)
		switch {
		case !ok:
			plan.add("custom_rules", "create", display, nil)
		case reflect.DeepEqual(old, v):
			plan.add("custom_rules", "unchanged", display, nil)
		default:
			plan.add("custom_rules", "update", display, configChangedFields(old, v))
		}
	}
	ruleKeys := make([]string, 0, len(targetRules))
	for k := range targetRules {
		ruleKeys = append(ruleKeys, k)
	}
	sort.Strings(ruleKeys)
	for _, key := range ruleKeys {
		v := targetRules[key]
		if _, ok := configSourceRule(source.CustomRules, key); !ok {
			plan.remaining("custom_rules", configRuleDisplayKey(v.SiteDomain, v.Name), mode)
		}
	}

	targetExclusions := map[string]ConfigExclusion{}
	for _, v := range target.Exclusions {
		targetExclusions[configExclusionKey(v.SiteDomain, v.RuleID, v.URLPrefix, v.Param)] = v
	}
	for _, v := range source.Exclusions {
		key := configExclusionKey(v.SiteDomain, v.RuleID, v.URLPrefix, v.Param)
		old, ok := targetExclusions[key]
		display := configExclusionDisplayKey(v)
		switch {
		case !ok:
			plan.add("exclusions", "create", display, nil)
		case reflect.DeepEqual(old, v):
			plan.add("exclusions", "unchanged", display, nil)
		default:
			plan.add("exclusions", "update", display, configChangedFields(old, v))
		}
	}
	exclusionKeys := make([]string, 0, len(targetExclusions))
	for k := range targetExclusions {
		exclusionKeys = append(exclusionKeys, k)
	}
	sort.Strings(exclusionKeys)
	for _, key := range exclusionKeys {
		v := targetExclusions[key]
		if _, ok := configSourceExclusion(source.Exclusions, key); !ok {
			plan.remaining("exclusions", configExclusionDisplayKey(v), mode)
		}
	}

	targetIPs := map[string]ConfigIP{}
	for _, v := range target.IPLists {
		targetIPs[configIPKey(v.Kind, v.IP)] = v
	}
	for _, v := range source.IPLists {
		key := configIPKey(v.Kind, v.IP)
		old, ok := targetIPs[key]
		display := v.Kind + "/" + v.IP
		switch {
		case !ok:
			plan.add("ip_lists", "create", display, nil)
		case reflect.DeepEqual(old, v):
			plan.add("ip_lists", "unchanged", display, nil)
		default:
			plan.add("ip_lists", "update", display, configChangedFields(old, v))
		}
	}
	ipKeys := make([]string, 0, len(targetIPs))
	for k := range targetIPs {
		ipKeys = append(ipKeys, k)
	}
	sort.Strings(ipKeys)
	for _, key := range ipKeys {
		v := targetIPs[key]
		if _, ok := configSourceIP(source.IPLists, key); !ok {
			plan.remaining("ip_lists", v.Kind+"/"+v.IP, mode)
		}
	}

	p.Warnings = append(p.Warnings,
		"payload_sha256 仅用于完整性校验，不提供加密或来源认证",
		"目标站点口令哈希、证书私钥及节点本地 settings 保持不变",
	)
	if mode == "replace" && len(p.Deletions) > 0 {
		p.Warnings = append(p.Warnings, "replace 将严格按 deletions 清单删除目标独有可移植配置")
	}
	if p.DiffTruncated {
		p.Warnings = append(p.Warnings, "diff 已按上限截断；统计与 deletions 清单仍完整")
	}
	return plan, nil
}

func (p *configImportPlan) add(resource, action, key string, fields []string) {
	stat := p.preview.Stats[resource]
	switch action {
	case "create":
		stat.Create++
	case "update":
		stat.Update++
	case "delete":
		stat.Delete++
	case "skip":
		stat.Skip++
	case "unchanged":
		stat.Unchanged++
	}
	p.preview.Stats[resource] = stat
	if action == "create" || action == "update" || action == "delete" {
		if resource == "ip_lists" || resource == "settings" && (key == "reputation_enabled" || strings.HasPrefix(key, "rep_")) {
			p.preview.ReputationChanged = true
		}
	}
	if action == "unchanged" {
		return
	}
	if action == "delete" {
		p.preview.Deletions = append(p.preview.Deletions, ConfigDeletion{Resource: resource, Key: key})
	}
	if len(p.preview.Diff) < maxConfigDiffEntries {
		p.preview.Diff = append(p.preview.Diff, ConfigDiffEntry{Resource: resource, Action: action, Key: key, Fields: fields})
	} else {
		p.preview.DiffTruncated = true
	}
}

func (p *configImportPlan) remaining(resource, key, mode string) {
	if mode == "replace" {
		p.add(resource, "delete", key, nil)
	} else {
		p.add(resource, "skip", key, nil)
	}
}

func (p *configImportPlan) remainingSites(target map[string]ConfigSite, source []ConfigSite, mode string) {
	keys := make([]string, 0, len(target))
	for k := range target {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !configSiteExists(source, k) {
			p.remaining("sites", k, mode)
		}
	}
}

func configChangedFields(a, b any) []string {
	ta, tb := reflect.ValueOf(a), reflect.ValueOf(b)
	if ta.Type() != tb.Type() {
		return nil
	}
	out := []string{}
	for i := 0; i < ta.NumField(); i++ {
		if !reflect.DeepEqual(ta.Field(i).Interface(), tb.Field(i).Interface()) {
			name := ta.Type().Field(i).Tag.Get("json")
			if j := strings.IndexByte(name, ','); j >= 0 {
				name = name[:j]
			}
			if name == "" {
				name = ta.Type().Field(i).Name
			}
			out = append(out, name)
		}
	}
	return out
}

func configRuleDisplayKey(domain, name string) string {
	if domain == "" {
		domain = "*"
	}
	return domain + "/" + name
}
func configExclusionDisplayKey(v ConfigExclusion) string {
	domain := v.SiteDomain
	if domain == "" {
		domain = "*"
	}
	return fmt.Sprintf("%s/rule:%d%s#%s", domain, v.RuleID, v.URLPrefix, v.Param)
}
func configSourceRule(items []ConfigRule, key string) (ConfigRule, bool) {
	for _, v := range items {
		if configRuleKey(v.SiteDomain, v.Name) == key {
			return v, true
		}
	}
	return ConfigRule{}, false
}
func configSourceExclusion(items []ConfigExclusion, key string) (ConfigExclusion, bool) {
	for _, v := range items {
		if configExclusionKey(v.SiteDomain, v.RuleID, v.URLPrefix, v.Param) == key {
			return v, true
		}
	}
	return ConfigExclusion{}, false
}
func configSourceIP(items []ConfigIP, key string) (ConfigIP, bool) {
	for _, v := range items {
		if configIPKey(v.Kind, v.IP) == key {
			return v, true
		}
	}
	return ConfigIP{}, false
}

func applyConfigPlan(tx *sql.Tx, plan *configImportPlan) error {
	siteIDs := map[string]int64{}
	rawSites := map[string]Site{}
	for _, v := range plan.raw.Sites {
		domain, err := canonicalConfigDomain(v.Domain)
		if err != nil {
			return err
		}
		siteIDs[domain] = v.ID
		rawSites[domain] = v
	}
	for _, v := range plan.source.Sites {
		if old, ok := rawSites[v.Domain]; ok {
			_, err := tx.Exec(`UPDATE sites SET name=?,domain=?,upstream=?,enabled=?,waf_mode=?,auth_user=?,cc_rate=?,cc_burst=?,captcha=?,resp_detect=?,dynamic_mode=?,bot_mode=?,bot_strict=?,http_redirect=? WHERE id=?`,
				v.Name, v.Domain, v.Upstream, v.Enabled, v.WAFMode, v.AuthUser, v.CCRate, v.CCBurst, v.Captcha, v.RespDetect, v.DynamicMode, v.BotMode, v.BotStrict, v.HTTPRedirect, old.ID)
			if err != nil {
				return fmt.Errorf("应用站点配置失败: %w", err)
			}
		} else {
			res, err := tx.Exec(`INSERT INTO sites(name,domain,upstream,enabled,waf_mode,auth_user,auth_pass,cc_rate,cc_burst,captcha,resp_detect,dynamic_mode,bot_mode,bot_strict,cert_pem,key_pem,http_redirect) VALUES(?,?,?,?,?,?,'',?,?,?,?,?,?,?,'','',?)`,
				v.Name, v.Domain, v.Upstream, v.Enabled, v.WAFMode, v.AuthUser, v.CCRate, v.CCBurst, v.Captcha, v.RespDetect, v.DynamicMode, v.BotMode, v.BotStrict, v.HTTPRedirect)
			if err != nil {
				return fmt.Errorf("创建导入站点失败: %w", err)
			}
			id, err := res.LastInsertId()
			if err != nil {
				return err
			}
			siteIDs[v.Domain] = id
		}
	}

	rawRules := map[string]CustomRule{}
	for _, v := range plan.raw.Rules {
		domain, err := configRawRuleDomain(v, plan.raw.Sites)
		if err != nil {
			return err
		}
		rawRules[configRuleKey(domain, strings.TrimSpace(v.Name))] = v
	}
	for _, v := range plan.source.CustomRules {
		siteID := siteIDs[v.SiteDomain]
		key := configRuleKey(v.SiteDomain, v.Name)
		if old, ok := rawRules[key]; ok {
			_, err := tx.Exec(`UPDATE custom_rules SET site_id=?,name=?,enabled=?,priority=?,logic=?,conditions=?,action=?,action_param=?,shadow=?,note=? WHERE id=?`, siteID, v.Name, v.Enabled, v.Priority, v.Logic, v.Conditions, v.Action, v.ActionParam, v.Shadow, v.Note, old.ID)
			if err != nil {
				return fmt.Errorf("应用自定义规则失败: %w", err)
			}
		} else {
			_, err := tx.Exec(`INSERT INTO custom_rules(site_id,name,enabled,priority,logic,conditions,action,action_param,shadow,note) VALUES(?,?,?,?,?,?,?,?,?,?)`, siteID, v.Name, v.Enabled, v.Priority, v.Logic, v.Conditions, v.Action, v.ActionParam, v.Shadow, v.Note)
			if err != nil {
				return fmt.Errorf("创建导入规则失败: %w", err)
			}
		}
	}

	rawExclusions := map[string]Exclusion{}
	for _, v := range plan.raw.Exclusions {
		domain, err := configRawExclusionDomain(v, plan.raw.Sites)
		if err != nil {
			return err
		}
		rawExclusions[configExclusionKey(domain, v.RuleID, v.URLPrefix, v.Param)] = v
	}
	for _, v := range plan.source.Exclusions {
		siteID := siteIDs[v.SiteDomain]
		key := configExclusionKey(v.SiteDomain, v.RuleID, v.URLPrefix, v.Param)
		if old, ok := rawExclusions[key]; ok {
			_, err := tx.Exec(`UPDATE exclusions SET site_id=?,rule_id=?,url_prefix=?,param=?,note=? WHERE id=?`, siteID, v.RuleID, v.URLPrefix, v.Param, v.Note, old.ID)
			if err != nil {
				return fmt.Errorf("应用豁免失败: %w", err)
			}
		} else {
			_, err := tx.Exec(`INSERT INTO exclusions(site_id,rule_id,url_prefix,param,note) VALUES(?,?,?,?,?)`, siteID, v.RuleID, v.URLPrefix, v.Param, v.Note)
			if err != nil {
				return fmt.Errorf("创建导入豁免失败: %w", err)
			}
		}
	}

	rawIPs := map[string]IPEntry{}
	for _, v := range plan.raw.IPs {
		normalized, err := normalizeConfigIP(ConfigIP{Kind: v.Kind, IP: v.IP, Note: v.Note, ExpiresAt: v.ExpiresAt})
		if err != nil {
			return err
		}
		rawIPs[configIPKey(normalized.Kind, normalized.IP)] = v
	}
	for _, v := range plan.source.IPLists {
		key := configIPKey(v.Kind, v.IP)
		if old, ok := rawIPs[key]; ok {
			_, err := tx.Exec(`UPDATE ip_lists SET kind=?,ip=?,note=?,expires_at=? WHERE id=?`, v.Kind, v.IP, v.Note, v.ExpiresAt, old.ID)
			if err != nil {
				return fmt.Errorf("应用 IP 名单失败: %w", err)
			}
		} else {
			_, err := tx.Exec(`INSERT INTO ip_lists(kind,ip,note,expires_at) VALUES(?,?,?,?)`, v.Kind, v.IP, v.Note, v.ExpiresAt)
			if err != nil {
				return fmt.Errorf("创建导入 IP 名单失败: %w", err)
			}
		}
	}

	for k, v := range plan.source.Settings {
		_, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, v)
		if err != nil {
			return fmt.Errorf("应用 settings 失败: %w", err)
		}
	}

	if plan.preview.Mode == "replace" {
		for key, old := range rawExclusions {
			if _, ok := configSourceExclusion(plan.source.Exclusions, key); !ok {
				if _, err := tx.Exec(`DELETE FROM exclusions WHERE id=?`, old.ID); err != nil {
					return err
				}
			}
		}
		for key, old := range rawRules {
			if _, ok := configSourceRule(plan.source.CustomRules, key); !ok {
				if _, err := tx.Exec(`DELETE FROM custom_rules WHERE id=?`, old.ID); err != nil {
					return err
				}
			}
		}
		for key, old := range rawIPs {
			if _, ok := configSourceIP(plan.source.IPLists, key); !ok {
				if _, err := tx.Exec(`DELETE FROM ip_lists WHERE id=?`, old.ID); err != nil {
					return err
				}
			}
		}
		for key, old := range rawSites {
			if !configSiteExists(plan.source.Sites, key) {
				if _, err := tx.Exec(`DELETE FROM sites WHERE id=?`, old.ID); err != nil {
					return err
				}
			}
		}
		for key := range plan.target.Settings {
			if _, ok := plan.source.Settings[key]; !ok {
				if _, err := tx.Exec(`DELETE FROM settings WHERE key=?`, key); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func configRawRuleDomain(v CustomRule, sites []Site) (string, error) {
	if v.SiteID == 0 {
		return "", nil
	}
	for _, site := range sites {
		if site.ID == v.SiteID {
			return canonicalConfigDomain(site.Domain)
		}
	}
	return "", configInvalid("目标规则引用了不存在的站点")
}
func configRawExclusionDomain(v Exclusion, sites []Site) (string, error) {
	if v.SiteID == 0 {
		return "", nil
	}
	for _, site := range sites {
		if site.ID == v.SiteID {
			return canonicalConfigDomain(site.Domain)
		}
	}
	return "", configInvalid("目标豁免引用了不存在的站点")
}
