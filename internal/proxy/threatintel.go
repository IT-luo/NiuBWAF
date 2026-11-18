package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"niubwaf/internal/store"
)

// 付费威胁情报框架（Phase 4）：可选接入商业情报 API，默认关闭、零密钥可运行。
// 情报仅作展示标签，不改变 A 期自动封禁判定（与 B 期 IDC/Tor 一致，避免误封合法云流量）。
// 待用户提供付费密钥后，generic provider 即插即用；后续可扩更多厂商。

const (
	threatTTL      = 24 * time.Hour // 命中缓存有效期
	threatErrTTL   = 5 * time.Minute // 查询失败短缓存，避免反复打失败端点
	threatCacheMax = 20000
	threatBodyCap  = 64 << 10
)

// ThreatResult 归一化后的威胁标签与评分（0–100）
type ThreatResult struct {
	Tags     []string `json:"tags"`
	Score    int      `json:"score"`
	Provider string   `json:"provider"`
}

// ThreatProvider 厂商接入抽象，便于将来扩展专用 provider
type ThreatProvider interface {
	Name() string
	Lookup(ip string) (ThreatResult, error)
}

// genericProvider 通用 JSON HTTP 情报源：URL 模板含 {ip} 占位符，密钥走 Bearer 头。
// 响应解析容忍多种常见字段命名，归一化为标签 + 评分。
type genericProvider struct {
	name   string
	key    string
	url    string
	client *http.Client
}

func (g *genericProvider) Name() string { return g.name }

func (g *genericProvider) Lookup(ip string) (ThreatResult, error) {
	endpoint := strings.ReplaceAll(g.url, "{ip}", ip)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ThreatResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	if g.key != "" {
		req.Header.Set("Authorization", "Bearer "+g.key)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return ThreatResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, threatBodyCap))
	if err != nil {
		return ThreatResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ThreatResult{}, &threatHTTPError{status: resp.StatusCode}
	}
	return parseThreatJSON(body, g.name), nil
}

type threatHTTPError struct{ status int }

func (e *threatHTTPError) Error() string { return "情报接口返回状态 " + http.StatusText(e.status) }

// threatBoolFlags 常见布尔威胁标记，true 即归一化为同名标签
var threatBoolFlags = []string{"proxy", "vpn", "tor", "botnet", "malicious", "scanner", "hosting", "relay", "spam", "attack", "crawler"}

// parseThreatJSON 容忍顶层或单层嵌套（security/threat/data/result）的布尔标记、tags 数组与评分字段
func parseThreatJSON(body []byte, provider string) ThreatResult {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ThreatResult{Provider: provider}
	}
	tagSet := map[string]bool{}
	score := 0
	var walk func(map[string]any)
	walk = func(o map[string]any) {
		for _, f := range threatBoolFlags {
			if b, ok := o[f].(bool); ok && b {
				tagSet[f] = true
			}
		}
		if arr, ok := o["tags"].([]any); ok {
			for _, t := range arr {
				if s, ok := t.(string); ok && s != "" {
					tagSet[strings.ToLower(strings.TrimSpace(s))] = true
				}
			}
		}
		for _, sk := range []string{"threat_score", "risk_score", "score", "risk", "threat_level"} {
			if v, ok := o[sk].(float64); ok {
				n := int(v)
				if v > 0 && v <= 1 {
					n = int(v * 100)
				}
				if n > score {
					score = n
				}
			}
		}
	}
	walk(m)
	for _, nest := range []string{"security", "threat", "data", "result"} {
		if sub, ok := m[nest].(map[string]any); ok {
			walk(sub)
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return ThreatResult{Tags: tags, Score: score, Provider: provider}
}

type threatEntry struct {
	res     ThreatResult
	expires time.Time
}

// ThreatIntel 带 TTL 缓存的情报查询管理器，配置实时读自设置（改动即时生效）
type ThreatIntel struct {
	store  *store.Store
	mu     sync.Mutex
	cache  map[string]threatEntry
	client *http.Client
}

func NewThreatIntel(st *store.Store) *ThreatIntel {
	return &ThreatIntel{store: st, cache: map[string]threatEntry{}, client: &http.Client{Timeout: 6 * time.Second}}
}

func (t *ThreatIntel) config() (provider, key, url string) {
	if t == nil || t.store == nil {
		return "off", "", ""
	}
	return t.store.GetSetting("intel_provider"), t.store.GetSetting("intel_api_key"), t.store.GetSetting("intel_api_url")
}

// Enabled 仅当 provider=generic 且密钥与地址齐备才启用，否则零网络调用
func (t *ThreatIntel) Enabled() bool {
	p, k, u := t.config()
	return p == "generic" && k != "" && u != ""
}

func (t *ThreatIntel) Lookup(ip string) ThreatResult {
	if !t.Enabled() {
		return ThreatResult{}
	}
	t.mu.Lock()
	if e, ok := t.cache[ip]; ok && time.Now().Before(e.expires) {
		t.mu.Unlock()
		return e.res
	}
	t.mu.Unlock()

	p, k, u := t.config()
	prov := &genericProvider{name: p, key: k, url: u, client: t.client}
	res, err := prov.Lookup(ip)
	ttl := threatTTL
	if err != nil {
		res = ThreatResult{Provider: p}
		ttl = threatErrTTL
	}
	res.Provider = p

	t.mu.Lock()
	t.cache[ip] = threatEntry{res: res, expires: time.Now().Add(ttl)}
	if len(t.cache) > threatCacheMax {
		t.pruneLocked()
	}
	t.mu.Unlock()
	return res
}

func (t *ThreatIntel) pruneLocked() {
	now := time.Now()
	for ip, e := range t.cache {
		if now.After(e.expires) {
			delete(t.cache, ip)
		}
	}
	if len(t.cache) > threatCacheMax {
		t.cache = map[string]threatEntry{}
	}
}

func (t *ThreatIntel) Status() map[string]any {
	p, k, u := t.config()
	t.mu.Lock()
	n := len(t.cache)
	t.mu.Unlock()
	return map[string]any{
		"enabled":    t.Enabled(),
		"provider":   p,
		"key_set":    k != "",
		"url_set":    u != "",
		"cache_size": n,
	}
}