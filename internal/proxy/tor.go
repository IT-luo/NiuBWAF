package proxy

import (
	_ "embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed data/tor_exits.txt
var torBaseline string

// TorList 维护 Tor 出口节点集合，用于标记匿名出口流量
type TorList struct {
	mu      sync.RWMutex
	set     map[string]bool
	updated string
	source  string
	dataDir string
}

func NewTorList(dataDir string) *TorList {
	t := &TorList{dataDir: dataDir, source: "内置基线", updated: "内置快照"}
	t.set = parseTorLines(torBaseline)
	t.loadCache()
	go t.refreshLoop()
	return t
}

func parseTorLines(text string) map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			set[ip.String()] = true
		}
	}
	return set
}

func (t *TorList) Has(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.set[parsed.String()]
}

func (t *TorList) Status() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return map[string]any{"count": len(t.set), "updated": t.updated, "source": t.source}
}

func (t *TorList) refreshLoop() {
	t.Refresh()
	for range time.Tick(time.Hour) {
		t.Refresh()
	}
}

// Refresh 拉取 Tor 官方出口列表；失败或为空时沿用现有数据
func (t *TorList) Refresh() {
	client := &http.Client{Timeout: 30 * time.Second}
	body, err := httpGetText(client, "https://check.torproject.org/torbulkexitlist")
	if err != nil {
		log.Printf("Tor 出口列表刷新失败（沿用现有数据）: %v", err)
		return
	}
	set := parseTorLines(body)
	if len(set) == 0 {
		log.Printf("Tor 出口列表为空，沿用现有数据")
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	t.mu.Lock()
	t.set = set
	t.updated, t.source = now, "在线更新"
	t.mu.Unlock()
	t.saveCache(set)
	log.Printf("Tor 出口列表已更新：%d 个", len(set))
}

type torCache struct {
	Updated string   `json:"updated"`
	IPs     []string `json:"ips"`
}

func (t *TorList) cachePath() string { return filepath.Join(t.dataDir, "tor_cache.json") }

func (t *TorList) loadCache() {
	data, err := os.ReadFile(t.cachePath())
	if err != nil {
		return
	}
	var c torCache
	if json.Unmarshal(data, &c) != nil || len(c.IPs) == 0 {
		return
	}
	set := parseTorLines(strings.Join(c.IPs, "\n"))
	t.mu.Lock()
	t.set = set
	t.updated, t.source = c.Updated, "磁盘缓存"
	t.mu.Unlock()
}

func (t *TorList) saveCache(set map[string]bool) {
	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	data, _ := json.Marshal(torCache{Updated: time.Now().Format("2006-01-02 15:04:05"), IPs: ips})
	os.WriteFile(t.cachePath(), data, 0644)
}
