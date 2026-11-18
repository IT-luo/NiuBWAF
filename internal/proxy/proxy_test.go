package proxy

import (
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func mkSite(urls ...string) *cachedSite {
	s := &cachedSite{}
	for _, raw := range urls {
		u, _ := url.Parse(raw)
		s.targets = append(s.targets, &upstreamTarget{u: u})
	}
	return s
}

func TestPickRoundRobin(t *testing.T) {
	s := mkSite("http://a:80", "http://b:80", "http://c:80")
	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		seen[s.pick().u.Host]++
	}
	for _, h := range []string{"a:80", "b:80", "c:80"} {
		if seen[h] != 3 {
			t.Fatalf("轮询不均: %v", seen)
		}
	}
}

func TestPickSkipsDown(t *testing.T) {
	s := mkSite("http://a:80", "http://b:80")
	atomic.StoreInt64(&s.targets[0].downUntil, time.Now().Unix()+60)
	for i := 0; i < 5; i++ {
		if got := s.pick().u.Host; got != "b:80" {
			t.Fatalf("应跳过故障上游, got %s", got)
		}
	}
	// 全部故障时仍返回一个尝试
	atomic.StoreInt64(&s.targets[1].downUntil, time.Now().Unix()+60)
	if s.pick() == nil {
		t.Fatal("全故障时不应返回 nil")
	}
	// 过期摘除自动恢复
	atomic.StoreInt64(&s.targets[0].downUntil, time.Now().Unix()-1)
	found := false
	for i := 0; i < 4; i++ {
		if s.pick().u.Host == "a:80" {
			found = true
		}
	}
	if !found {
		t.Fatal("摘除过期后应恢复选择")
	}
}