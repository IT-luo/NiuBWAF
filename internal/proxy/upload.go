package proxy

import (
	"bytes"
	"io"
	"sync"

	"niubwaf/internal/store"
)

const uploadBodyBudget int64 = 128 << 20

type uploadRoute struct {
	method string
	path   string
}

type uploadRouteKey struct {
	siteID int64
	route  uploadRoute
}

// 大请求的额度贯穿读取、检测和回源。重载站点配置时仍保留在途请求的额度。
type uploadBudget struct {
	mu     sync.Mutex
	routes map[uploadRouteKey]int
	active int
	bytes  int64
}

func (b *uploadBudget) acquire(key uploadRouteKey, policy store.UploadPolicy, size int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active >= store.MaxUploadConcurrency || b.bytes+size > uploadBodyBudget || b.routes[key] >= policy.MaxConcurrent {
		return false
	}
	if b.routes == nil {
		b.routes = make(map[uploadRouteKey]int)
	}
	b.active++
	b.bytes += size
	b.routes[key]++
	return true
}

func (b *uploadBudget) release(key uploadRouteKey, size int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active--
	b.bytes -= size
	if b.routes[key] == 1 {
		delete(b.routes, key)
	} else {
		b.routes[key]--
	}
}

func readUploadBody(reader io.Reader, size int64) ([]byte, error) {
	if size < 0 {
		return io.ReadAll(reader)
	}
	var buffer bytes.Buffer
	buffer.Grow(int(size) + bytes.MinRead)
	_, err := buffer.ReadFrom(reader)
	return buffer.Bytes(), err
}
