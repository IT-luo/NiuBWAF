package proxy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed data/idc_cidrs.txt
var idcBaseline string

// idcEntry 一条云厂商 CIDR 归属
type idcEntry struct {
	ip       net.IP
	plen     int
	provider string
}

type idcNode struct {
	child    [2]*idcNode
	provider string
}

// IDCMatcher 以二进制前缀 trie 做最长匹配，识别 IP 是否属于云厂商/IDC 机房网段
type IDCMatcher struct {
	mu      sync.RWMutex
	root4   *idcNode
	root6   *idcNode
	count   int
	updated string
	source  string
	dataDir string
}

func NewIDCMatcher(dataDir string) *IDCMatcher {
	m := &IDCMatcher{dataDir: dataDir, source: "内置基线", updated: "内置快照"}
	entries := parseIDCLines(idcBaseline)
	m.root4, m.root6, m.count = buildIDCTries(entries)
	m.loadCache()
	go m.refreshLoop()
	return m
}

func parseIDCLines(text string) []idcEntry {
	var entries []idcEntry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidr, provider, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		if e, valid := parseCIDR(cidr, provider); valid {
			entries = append(entries, e)
		}
	}
	return entries
}

func parseCIDR(cidr, provider string) (idcEntry, bool) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return idcEntry{}, false
	}
	plen, _ := network.Mask.Size()
	return idcEntry{ip: network.IP, plen: plen, provider: provider}, true
}

func buildIDCTries(entries []idcEntry) (root4, root6 *idcNode, count int) {
	for _, e := range entries {
		if e.ip.To4() != nil {
			root4 = idcInsert(root4, e.ip, e.plen, e.provider)
		} else {
			root6 = idcInsert(root6, e.ip, e.plen, e.provider)
		}
		count++
	}
	return
}

func idcInsert(root *idcNode, ip net.IP, plen int, provider string) *idcNode {
	if root == nil {
		root = &idcNode{}
	}
	b := ip.To4()
	bits := 32
	if b == nil {
		b = ip.To16()
		bits = 128
	}
	if plen > bits {
		plen = bits
	}
	cur := root
	for i := 0; i < plen; i++ {
		bit := (b[i/8] >> (7 - uint(i%8))) & 1
		if cur.child[bit] == nil {
			cur.child[bit] = &idcNode{}
		}
		cur = cur.child[bit]
	}
	cur.provider = provider
	return root
}

func idcLookup(root *idcNode, ip net.IP) string {
	if root == nil {
		return ""
	}
	b := ip.To4()
	bits := 32
	if b == nil {
		b = ip.To16()
		bits = 128
	}
	cur := root
	best := cur.provider
	for i := 0; i < bits; i++ {
		bit := (b[i/8] >> (7 - uint(i%8))) & 1
		cur = cur.child[bit]
		if cur == nil {
			break
		}
		if cur.provider != "" {
			best = cur.provider
		}
	}
	return best
}

func (m *IDCMatcher) Match(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if parsed.To4() != nil {
		return idcLookup(m.root4, parsed)
	}
	return idcLookup(m.root6, parsed)
}

func (m *IDCMatcher) Status() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{"count": m.count, "updated": m.updated, "source": m.source}
}

func (m *IDCMatcher) refreshLoop() {
	m.Refresh()
	for range time.Tick(24 * time.Hour) {
		m.Refresh()
	}
}

// Refresh 拉取公开云厂商 CIDR 并重建 trie；失败时沿用现有数据
func (m *IDCMatcher) Refresh() {
	entries, err := m.fetch()
	if err != nil {
		log.Printf("IDC 情报刷新失败（沿用现有数据）: %v", err)
		return
	}
	root4, root6, count := buildIDCTries(entries)
	now := time.Now().Format("2006-01-02 15:04:05")
	m.mu.Lock()
	m.root4, m.root6, m.count = root4, root6, count
	m.updated, m.source = now, "在线更新"
	m.mu.Unlock()
	m.saveCache(entries)
	log.Printf("IDC 情报已更新：%d 条 CIDR", count)
}

func (m *IDCMatcher) fetch() ([]idcEntry, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var entries []idcEntry
	add := func(cidr, provider string) {
		if e, ok := parseCIDR(cidr, provider); ok {
			entries = append(entries, e)
		}
	}
	var aws struct {
		Prefixes []struct {
			IP string `json:"ip_prefix"`
		} `json:"prefixes"`
		IPv6 []struct {
			IP string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := httpGetJSON(client, "https://ip-ranges.amazonaws.com/ip-ranges.json", &aws); err == nil {
		for _, p := range aws.Prefixes {
			add(p.IP, "AWS")
		}
		for _, p := range aws.IPv6 {
			add(p.IP, "AWS")
		}
	}
	var gcp struct {
		Prefixes []struct {
			V4 string `json:"ipv4Prefix"`
			V6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := httpGetJSON(client, "https://www.gstatic.com/ipranges/cloud.json", &gcp); err == nil {
		for _, p := range gcp.Prefixes {
			add(p.V4, "GCP")
			add(p.V6, "GCP")
		}
	}
	if body, err := httpGetText(client, "https://www.cloudflare.com/ips-v4/"); err == nil {
		for _, line := range strings.Split(body, "\n") {
			add(line, "Cloudflare")
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("所有 IDC 数据源拉取失败")
	}
	return entries, nil
}

type idcCache struct {
	Updated string   `json:"updated"`
	Lines   []string `json:"lines"`
}

func (m *IDCMatcher) cachePath() string { return filepath.Join(m.dataDir, "idc_cache.json") }

func (m *IDCMatcher) loadCache() {
	data, err := os.ReadFile(m.cachePath())
	if err != nil {
		return
	}
	var c idcCache
	if json.Unmarshal(data, &c) != nil || len(c.Lines) == 0 {
		return
	}
	entries := parseIDCLines(strings.Join(c.Lines, "\n"))
	root4, root6, count := buildIDCTries(entries)
	m.mu.Lock()
	m.root4, m.root6, m.count = root4, root6, count
	m.updated, m.source = c.Updated, "磁盘缓存"
	m.mu.Unlock()
}

func (m *IDCMatcher) saveCache(entries []idcEntry) {
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		lines = append(lines, fmt.Sprintf("%s/%d|%s", e.ip.String(), e.plen, e.provider))
	}
	data, _ := json.Marshal(idcCache{Updated: time.Now().Format("2006-01-02 15:04:05"), Lines: lines})
	os.WriteFile(m.cachePath(), data, 0644)
}

func httpGetJSON(client *http.Client, url string, v any) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func httpGetText(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
