package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestShardIndexSpread(t *testing.T) {
	used := map[uint32]int{}
	for i := 0; i < 4096; i++ {
		idx := shardIndex(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		if idx >= limiterShards {
			t.Fatalf("分片下标越界: %d", idx)
		}
		used[idx]++
		if idx != shardIndex(fmt.Sprintf("10.0.%d.%d", i/256, i%256)) {
			t.Fatal("同一 key 的分片下标必须稳定")
		}
	}
	if len(used) < limiterShards/2 {
		t.Fatalf("key 应分散到多数分片, 仅用到 %d/%d", len(used), limiterShards)
	}
}

func TestLimiterBurstAndRefill(t *testing.T) {
	l := NewLimiter()
	key := "1.2.3.4"
	for i := 0; i < 5; i++ {
		if !l.Allow(key, 100, 5) {
			t.Fatalf("桶内令牌应允许第 %d 次请求", i+1)
		}
	}
	if l.Allow(key, 100, 5) {
		t.Fatal("令牌耗尽后应拒绝")
	}
	time.Sleep(80 * time.Millisecond)
	if !l.Allow(key, 100, 5) {
		t.Fatal("按速率补充令牌后应重新放行")
	}
	if l.Allow("rate-zero", 0, 0) != true {
		t.Fatal("rate<=0 表示不限流，应放行")
	}
}

func TestLimiterPerKeyIsolation(t *testing.T) {
	l := NewLimiter()
	for i := 0; i < 3; i++ {
		l.Allow("key-a", 1, 3)
	}
	if l.Allow("key-a", 1, 3) {
		t.Fatal("key-a 令牌应已耗尽")
	}
	if !l.Allow("key-b", 1, 3) {
		t.Fatal("不同 key 不应互相消耗令牌")
	}
}

// TestLimiterConcurrent 验证分片改造在并发下的正确性（不同 key 互不干扰、同 key 仍受限）
func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter()
	var wg sync.WaitGroup
	count := func(fn func(g, i int) bool, total int) int64 {
		allowed, mu2 := int64(0), sync.Mutex{}
		for g := 0; g < 32; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				local := 0
				for i := 0; i < total/32; i++ {
					if fn(g, i) {
						local++
					}
				}
				mu2.Lock()
				allowed += int64(local)
				mu2.Unlock()
			}(g)
		}
		wg.Wait()
		return allowed
	}

	got := count(func(g, i int) bool {
		return l.Allow(fmt.Sprintf("ip-%d-%d", g, i), 10, 10)
	}, 16000)
	if got != 16000 {
		t.Fatalf("不同 key 首次请求应全部放行, got %d", got)
	}

	same := count(func(g, i int) bool {
		return l.Allow("shared-key", 50, 5)
	}, 16000)
	if same < 5 || same >= 16000 {
		t.Fatalf("同一 key 应受令牌桶约束, got %d", same)
	}
}
