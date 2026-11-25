package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
	"sync/atomic"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/store"
)

type cachedShadowRule struct {
	rule       engine.CompiledRule
	definition [sha256.Size]byte
	stats      *shadowRuleStats
}

type shadowRuleStats struct {
	evaluated atomic.Uint64
	matched   atomic.Uint64
	lastHit   atomic.Int64 // UnixNano；0 表示尚未命中
	since     time.Time
}

type shadowRuleKey struct {
	siteID int64
	ruleID int64
}

// ShadowRuleSnapshot 是一条影子规则在某个实际站点上的内存统计。
// 对全局规则而言，rule_site_id 为 0，site_id/domain 仍是真实处理请求的站点。
type ShadowRuleSnapshot struct {
	RuleID     int64  `json:"rule_id"`
	RuleSiteID int64  `json:"rule_site_id"`
	SiteID     int64  `json:"site_id"`
	Domain     string `json:"domain"`
	Name       string `json:"name"`
	Priority   int    `json:"priority"`
	Logic      string `json:"logic"`
	Action     string `json:"action"`
	Shadow     bool   `json:"shadow"`
	Evaluated  uint64 `json:"evaluated"`
	Matched    uint64 `json:"matched"`
	LastHit    string `json:"last_hit"`
	Since      string `json:"since"`
}

func shadowRuleDefinition(r store.CustomRule) [sha256.Size]byte {
	data, _ := json.Marshal(r)
	return sha256.Sum256(data)
}

func evaluateShadowRules(rules []cachedShadowRule, in *engine.RuleInput) {
	for i := range rules {
		stats := rules[i].stats
		stats.evaluated.Add(1)
		// 影子阶段只匹配并计数，不执行 allow/block/captcha/redirect/log，
		// 也不进入攻击日志、信誉、告警或攻击指标链路。
		if rules[i].rule.Match(in) {
			stats.matched.Add(1)
			stats.lastHit.Store(time.Now().UnixNano())
		}
	}
}

// ShadowSnapshot 返回当前已编译且启用的影子规则统计。规则修订、删除、禁用
// 或退出影子后不会出现在新缓存中；定义未变的 Reload 会复用原计数。
func (p *Proxy) ShadowSnapshot() []ShadowRuleSnapshot {
	p.mu.RLock()
	out := make([]ShadowRuleSnapshot, 0)
	for _, site := range p.sites {
		for i := range site.shadowRules {
			sr := &site.shadowRules[i]
			if sr.stats == nil {
				continue
			}
			// 先读 matched 再读 evaluated，避免并发命中时快照出现 matched>evaluated。
			matched := sr.stats.matched.Load()
			evaluated := sr.stats.evaluated.Load()
			lastHit := ""
			if ns := sr.stats.lastHit.Load(); ns != 0 {
				lastHit = time.Unix(0, ns).Format("2006-01-02 15:04:05")
			}
			out = append(out, ShadowRuleSnapshot{
				RuleID: sr.rule.ID, RuleSiteID: sr.rule.SiteID,
				SiteID: site.ID, Domain: site.Domain, Name: sr.rule.Name,
				Priority: sr.rule.Priority, Logic: sr.rule.Logic, Action: sr.rule.Action, Shadow: true,
				Evaluated: evaluated, Matched: matched, LastHit: lastHit,
				Since: sr.stats.since.Format("2006-01-02 15:04:05"),
			})
		}
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
