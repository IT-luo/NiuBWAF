package proxy

import (
	"encoding/json"
	"errors"
	"hash/maphash"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"
)

var crawlerFeeds = map[string]string{
	"googlebot": "https://developers.google.com/crawling/ipranges/common-crawlers.json",
	"bingbot":   "https://www.bing.com/toolbox/bingbot.json",
}

type crawlerRangeSnapshot struct {
	prefixes []netip.Prefix
	loaded   time.Time
}

type crawlerVerifier struct {
	mu         sync.RWMutex
	sources    map[string]crawlerRangeSnapshot
	client     *http.Client
	next       time.Time
	refreshing bool
}

func newCrawlerVerifier() *crawlerVerifier {
	return &crawlerVerifier{
		sources: map[string]crawlerRangeSnapshot{},
		client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func (c *crawlerVerifier) refreshIfDue() {
	c.mu.Lock()
	if c.refreshing || time.Now().Before(c.next) {
		c.mu.Unlock()
		return
	}
	c.refreshing = true
	c.mu.Unlock()
	go func() {
		next := 6 * time.Hour
		for name, address := range crawlerFeeds {
			prefixes, err := c.fetchRanges(address)
			if err != nil {
				next = 10 * time.Minute
				continue
			}
			c.mu.Lock()
			c.sources[name] = crawlerRangeSnapshot{prefixes: prefixes, loaded: time.Now()}
			c.mu.Unlock()
		}
		c.mu.Lock()
		c.refreshing = false
		c.next = time.Now().Add(next)
		c.mu.Unlock()
	}()
}

func (c *crawlerVerifier) fetchRanges(address string) ([]netip.Prefix, error) {
	resp, err := c.client.Get(address)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errCrawlerFeed
	}
	return parseCrawlerRanges(resp.Body)
}

var errCrawlerFeed = errors.New("无有效爬虫来源网段")

func parseCrawlerRanges(r io.Reader) ([]netip.Prefix, error) {
	var data struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		}
	}
	payload, err := io.ReadAll(io.LimitReader(r, 256<<10))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, err
	}
	if len(data.Prefixes) == 0 || len(data.Prefixes) > 4096 {
		return nil, errCrawlerFeed
	}
	var prefixes []netip.Prefix
	for _, item := range data.Prefixes {
		raw := item.IPv4
		if raw == "" {
			raw = item.IPv6
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || (prefix.Addr().Is4() && prefix.Bits() < 8) || (prefix.Addr().Is6() && prefix.Bits() < 16) {
			return nil, errCrawlerFeed
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func (c *crawlerVerifier) verified(name, ip string) (matches, available bool) {
	if c == nil {
		return false, false
	}
	c.mu.RLock()
	source := c.sources[name]
	c.mu.RUnlock()
	if len(source.prefixes) == 0 || time.Since(source.loaded) > 72*time.Hour {
		return false, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, true
	}
	for _, prefix := range source.prefixes {
		if prefix.Contains(addr.Unmap()) {
			return true, true
		}
	}
	return false, true
}

// VerifiedCrawlerSources lists providers with a usable source range snapshot.
func (p *Proxy) VerifiedCrawlerSources() []string {
	if p == nil || p.crawlers == nil {
		return nil
	}
	p.crawlers.mu.RLock()
	defer p.crawlers.mu.RUnlock()
	var names []string
	for name, source := range p.crawlers.sources {
		if len(source.prefixes) > 0 && time.Since(source.loaded) <= 72*time.Hour {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

type botClientKey struct {
	site int64
	ip   string
}

type botPathWindow struct {
	start int64
	paths map[uint64]struct{}
	over  bool
}

type botPathShard struct {
	mu      sync.Mutex
	clients map[botClientKey]*botPathWindow
}

type botPathTracker struct {
	shards [limiterShards]botPathShard
}

const botPathWindowSeconds = 10

var botPathSeed = maphash.MakeSeed()

// limitNewPath 指示该客户端是否超过窗口内的新路径额度，并标记首次超限。
func (t *botPathTracker) limitNewPath(siteID int64, ip, path string, limit int, now int64) (over, first bool) {
	shard := &t.shards[shardIndex(ip)]
	key := botClientKey{site: siteID, ip: ip}
	id := maphash.String(botPathSeed, path)
	window := now / botPathWindowSeconds
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.clients == nil {
		shard.clients = map[botClientKey]*botPathWindow{}
	}
	state := shard.clients[key]
	if state == nil || state.start != window {
		if len(shard.clients) >= 64 {
			for k, v := range shard.clients {
				if v.start != window {
					delete(shard.clients, k)
				}
			}
		}
		if len(shard.clients) >= 64 {
			return false, false
		}
		state = &botPathWindow{start: window, paths: map[uint64]struct{}{}}
		shard.clients[key] = state
	}
	if _, seen := state.paths[id]; seen {
		return false, false
	}
	if len(state.paths) < limit {
		state.paths[id] = struct{}{}
		return false, false
	}
	first = !state.over
	state.over = true
	return true, first
}
