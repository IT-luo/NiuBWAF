package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func reqWith(remote, xff, xreal string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xreal != "" {
		r.Header.Set("X-Real-IP", xreal)
	}
	return r
}

func TestClientIPUntrustedIgnoresXFF(t *testing.T) {
	// 无可信代理：客户端伪造 XFF/X-Real-IP 一律忽略
	r := reqWith("203.0.113.9:5555", "1.2.3.4", "5.6.7.8")
	if got := ClientIP(r, nil); got != "203.0.113.9" {
		t.Fatalf("应忽略伪造 XFF, got %s", got)
	}
}

func TestClientIPTrustedRightmostUntrusted(t *testing.T) {
	trusted := ParseTrustedProxies("10.0.0.0/8")
	// 直连对端是可信代理；XFF 左侧为伪造值，应取右起第一个不可信 IP
	r := reqWith("10.1.2.3:443", "9.9.9.9, 198.51.100.7, 10.4.4.4", "")
	if got := ClientIP(r, trusted); got != "198.51.100.7" {
		t.Fatalf("应取右起首个不可信 IP, got %s", got)
	}
}

func TestClientIPTrustedAllTrustedFallsBack(t *testing.T) {
	trusted := ParseTrustedProxies("10.0.0.0/8, 192.168.1.5")
	r := reqWith("10.1.2.3:443", "10.9.9.9, 10.8.8.8", "192.168.1.5")
	if got := ClientIP(r, trusted); got != "10.1.2.3" {
		t.Fatalf("XFF 全可信时应回退 RemoteAddr, got %s", got)
	}
	r2 := reqWith("10.1.2.3:443", "10.9.9.9", "")
	if got := ClientIP(r2, trusted); got != "10.1.2.3" {
		t.Fatalf("无可用转发头时应回退 RemoteAddr, got %s", got)
	}
}

func TestClientIPXRealOnlyWhenTrusted(t *testing.T) {
	trusted := ParseTrustedProxies("10.0.0.0/8")
	r := reqWith("10.1.2.3:443", "", "198.51.100.20")
	if got := ClientIP(r, trusted); got != "198.51.100.20" {
		t.Fatalf("可信对端的 X-Real-IP 应采信, got %s", got)
	}
	r2 := reqWith("203.0.113.9:443", "", "198.51.100.20")
	if got := ClientIP(r2, trusted); got != "203.0.113.9" {
		t.Fatalf("不可信对端的 X-Real-IP 应忽略, got %s", got)
	}
	r.Header.Add("X-Real-IP", "198.51.100.21")
	if got := ClientIP(r, trusted); got != "10.1.2.3" {
		t.Fatalf("多个 X-Real-IP 字段应回退 RemoteAddr, got %s", got)
	}
}

func TestClientIPUsesAllXFFFieldsInOrder(t *testing.T) {
	trusted := ParseTrustedProxies("10.0.0.0/8")
	r := reqWith("10.1.2.3:443", "203.0.113.5", "")
	r.Header.Add("X-Forwarded-For", "198.51.100.7, 10.2.2.2")
	r.Header.Add("X-Forwarded-For", "10.3.3.3")
	if got := ClientIP(r, trusted); got != "198.51.100.7" {
		t.Fatalf("应按顺序检查完整 XFF 字段链, got %s", got)
	}
}

func TestClientIPMalformedXFFDoesNotFallBackToOtherHeaders(t *testing.T) {
	trusted := ParseTrustedProxies("10.0.0.0/8")
	for _, field := range []string{"", "not-an-ip, 10.4.4.4"} {
		r := reqWith("10.1.2.3:443", "198.51.100.7", "198.51.100.20")
		r.Header.Add("X-Forwarded-For", field)
		if got := ClientIP(r, trusted); got != "10.1.2.3" {
			t.Errorf("有无法解析的 XFF 字段 %q 时应回退 RemoteAddr, got %s", field, got)
		}
	}
}

func TestClientIPv6(t *testing.T) {
	trusted := ParseTrustedProxies("2001:db8::/32")
	r := reqWith("[2001:db8::1]:443", "2001:db8::9, 203.0.113.5", "")
	if got := ClientIP(r, trusted); got != "203.0.113.5" {
		t.Fatalf("IPv6 可信代理应正确解析, got %s", got)
	}
	r2 := reqWith("[203.0.113.8]:443", "2001:db8::9", "")
	if got := ClientIP(r2, trusted); got != "203.0.113.8" {
		t.Fatalf("IPv6 不可信对端应忽略 XFF, got %s", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	nets := ParseTrustedProxies("10.0.0.0/8, 192.168.1.5, 2001:db8::1, bad, ,")
	if len(nets) != 3 {
		t.Fatalf("应解析 3 个有效项, got %d", len(nets))
	}
	if !nets[1].Contains(net.ParseIP("192.168.1.5")) {
		t.Fatal("单 IPv4 应补 /32")
	}
	if !nets[2].Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("单 IPv6 应补 /128")
	}
	if nets[1].Contains(net.ParseIP("192.168.1.6")) {
		t.Fatal("/32 不应包含相邻 IP")
	}
}
