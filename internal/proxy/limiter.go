package proxy

import (
	"sync"
	"time"
)

// limiterShards 分片数，取 2 的幂便于取模分散热点
const limiterShards = 64

type bucket struct {
	tokens float64
	last   time.Time
}

type limiterShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// Limiter 分片令牌桶限流器：key 按 FNV-1a 哈希散列到独立分片，各自持锁，
// 避免单一全局互斥锁在高并发下成为串行化瓶颈。
type Limiter struct {
	shards [limiterShards]limiterShard
}

func NewLimiter() *Limiter {
	l := &Limiter{}
	for i := range l.shards {
		l.shards[i].buckets = map[string]*bucket{}
	}
	go l.gc()
	return l
}

func shardIndex(key string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h % limiterShards
}

// Allow 令牌桶限流：rate 每秒补充令牌数，burst 桶容量
func (l *Limiter) Allow(key string, rate, burst int) bool {
	if rate <= 0 {
		return true
	}
	if burst <= 0 {
		burst = rate
	}
	sh := &l.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := time.Now()
	b, ok := sh.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now}
		sh.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * float64(rate)
	b.last = now
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *Limiter) gc() {
	for range time.Tick(5 * time.Minute) {
		cutoff := time.Now().Add(-10 * time.Minute)
		for i := range l.shards {
			sh := &l.shards[i]
			sh.mu.Lock()
			for k, b := range sh.buckets {
				if b.last.Before(cutoff) {
					delete(sh.buckets, k)
				}
			}
			sh.mu.Unlock()
		}
	}
}
