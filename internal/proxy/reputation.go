package proxy

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"niubwaf/internal/metrics"
	"niubwaf/internal/store"
)

// reputationLoop 周期聚合本地攻击历史，对高分 IP 自动封禁（白名单前置、TTL 递增、窗口衰减）
func (p *Proxy) reputationLoop(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	p.computeReputation(true)
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if ctx.Err() == nil {
				p.computeReputation(false)
			}
		}
	}
}

// RefreshReputation 供 API 在修改信誉设置后立即重算
func (p *Proxy) RefreshReputation() { p.computeReputation(true) }

// RefreshBans 从持久化记录重载生效中的自动封禁到内存判定层
func (p *Proxy) RefreshBans() {
	bans := p.Store.ActiveBans(time.Now().Format("2006-01-02 15:04:05"))
	p.mu.Lock()
	p.dynBlack = bans
	p.mu.Unlock()
	metrics.Default.SetRepBanned(len(bans))
}

func (p *Proxy) IsWhitelisted(ip string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.matchIP(ip, p.whiteNet, p.whiteIP)
}

func (p *Proxy) IsBlacklisted(ip string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.matchIP(ip, p.blackNet, p.blackIP)
}

func (p *Proxy) IsRepBanned(ip string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dynBlack[ip] > time.Now().Unix()
}

func (p *Proxy) computeReputation(force bool) {
	now := time.Now()
	nowStr := now.Format("2006-01-02 15:04:05")
	if p.Store.GetSetting("reputation_enabled") == "off" {
		p.mu.Lock()
		p.dynBlack = map[string]int64{}
		p.mu.Unlock()
		metrics.Default.SetRepBanned(0)
		return
	}
	windowHours := repSettingInt(p.Store, "rep_window", 24, 1, 168)
	threshold := repSettingInt(p.Store, "rep_threshold", 30, 1, 100000)
	baseTTL := repSettingInt(p.Store, "rep_ban_ttl", 60, 1, 10080)
	maxTTL := repSettingInt(p.Store, "rep_max_ttl", 1440, 1, 43200)
	windowStart := now.Add(-time.Duration(windowHours) * time.Hour).Format("2006-01-02 15:04:05")

	// 空闲跳过：无新增攻击日志时不必每分钟全量聚合；窗口滑动与过期清理由每 10 个空闲周期的强制重算兜底
	maxID := p.Store.MaxLogID()
	if !force && maxID == p.lastRepLogID.Load() && p.repIdle.Add(1) < 10 {
		return
	}
	p.lastRepLogID.Store(maxID)
	p.repIdle.Store(0)

	scores, err := p.Store.ScoreIPs(windowStart, threshold)
	if err != nil {
		log.Printf("信誉评分聚合失败: %v", err)
		return
	}
	for _, sc := range scores {
		p.mu.RLock()
		white := p.matchIP(sc.IP, p.whiteNet, p.whiteIP)
		p.mu.RUnlock()
		if white {
			continue
		}
		prev := p.Store.GetReputation(sc.IP)
		if prev != nil && prev.PardonedUntil > nowStr {
			continue
		}
		banCount, alreadyBanned := 0, false
		if prev != nil {
			banCount = prev.BanCount
			alreadyBanned = prev.BannedUntil > nowStr
		}
		var bannedUntil string
		if alreadyBanned {
			bannedUntil = prev.BannedUntil
		} else {
			ttl := baseTTL << uint(min(banCount, 5))
			if ttl > maxTTL {
				ttl = maxTTL
			}
			bannedUntil = now.Add(time.Duration(ttl) * time.Minute).Format("2006-01-02 15:04:05")
			banCount++
		}
		reason := fmt.Sprintf("近 %dh 攻击评分 %d（%d 次攻击）", windowHours, sc.Score, sc.Count)
		if err := p.Store.UpsertReputation(sc.IP, sc.Score, banCount, bannedUntil, reason); err != nil {
			log.Printf("写入信誉记录失败 %s: %v", sc.IP, err)
			continue
		}
		if !alreadyBanned {
			p.Store.Audit("system", "信誉自动封禁", fmt.Sprintf("%s 评分=%d 封禁至 %s（第 %d 次）", sc.IP, sc.Score, bannedUntil, banCount))
			p.Hub.Broadcast(map[string]any{"type": "reputation", "ts": nowStr, "ip": sc.IP, "score": sc.Score, "banned_until": bannedUntil})
		}
	}
	p.Store.PruneReputation(windowStart)
	p.RefreshBans()
}

func repSettingInt(st *store.Store, key string, def, lo, hi int) int {
	v := def
	if s := st.GetSetting(key); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			v = n
		}
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return v
}
