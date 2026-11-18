package proxy

import (
	"net"
	"testing"
)

func TestIDCTrieLongestMatch(t *testing.T) {
	entries := parseIDCLines("1.2.3.0/24|AWS\n1.2.3.128/25|GCP\n2001:db8::/32|AWS\n# comment\nbad-line\n")
	root4, root6, count := buildIDCTries(entries)
	if count != 3 {
		t.Fatalf("期望 3 条有效 CIDR, got %d", count)
	}
	cases := []struct {
		root *idcNode
		ip   string
		want string
	}{
		{root4, "1.2.3.10", "AWS"},    // 命中 /24
		{root4, "1.2.3.130", "GCP"},   // 最长匹配 /25 覆盖 /24
		{root4, "1.2.3.255", "GCP"},   // /25 边界
		{root4, "9.9.9.9", ""},        // 非 IDC
		{root6, "2001:db8::1", "AWS"}, // IPv6
		{root6, "2001:db9::1", ""},    // IPv6 段外
	}
	for _, c := range cases {
		if got := idcLookup(c.root, net.ParseIP(c.ip)); got != c.want {
			t.Errorf("idcLookup(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestIDCMatchFamilyIsolation(t *testing.T) {
	entries := parseIDCLines("0.0.0.0/1|AWS\n2001:db8::/32|GCP\n")
	root4, root6, _ := buildIDCTries(entries)
	m := &IDCMatcher{root4: root4, root6: root6}
	// IPv4 查询不应误命中 IPv6 段，反之亦然
	if got := m.Match("2001:db8::1"); got != "GCP" {
		t.Errorf("IPv6 查询期望 GCP, got %q", got)
	}
	if got := m.Match("1.0.0.1"); got != "AWS" {
		t.Errorf("IPv4 查询期望 AWS, got %q", got)
	}
	if got := m.Match("not-an-ip"); got != "" {
		t.Errorf("非法 IP 期望空, got %q", got)
	}
}

func TestIDCBaselineLoaded(t *testing.T) {
	entries := parseIDCLines(idcBaseline)
	root4, root6, count := buildIDCTries(entries)
	if count < 10000 {
		t.Fatalf("内嵌 IDC 基线应 >10000 条, got %d", count)
	}
	m := &IDCMatcher{root4: root4, root6: root6}
	if got := m.Match("3.4.12.4"); got != "AWS" {
		t.Errorf("已知 AWS IP 期望 AWS, got %q", got)
	}
	if got := m.Match("34.1.208.1"); got != "GCP" {
		t.Errorf("已知 GCP IP 期望 GCP, got %q", got)
	}
	if got := m.Match("192.168.1.1"); got != "" {
		t.Errorf("私网 IP 不应命中 IDC, got %q", got)
	}
}

func TestTorParseAndHas(t *testing.T) {
	set := parseTorLines("1.2.3.4\n# comment\n\n5.6.7.8\ninvalid\n")
	if len(set) != 2 {
		t.Fatalf("期望 2 个有效出口, got %d", len(set))
	}
	tl := &TorList{set: set}
	if !tl.Has("1.2.3.4") || !tl.Has("5.6.7.8") {
		t.Error("已知出口应命中")
	}
	if tl.Has("9.9.9.9") || tl.Has("bad") {
		t.Error("非出口不应命中")
	}
	if len(parseTorLines(torBaseline)) < 500 {
		t.Error("内嵌 Tor 基线应 >500 个出口")
	}
}

func TestGeoGracefulDegradation(t *testing.T) {
	g := NewGeoIP(t.TempDir()) // 无任何 mmdb
	if g.Available() || g.CityAvailable() || g.ASNAvailable() {
		t.Error("无库时不应可用")
	}
	if g.Country("8.8.8.8") != "" {
		t.Error("无库时 Country 应为空")
	}
	ci := g.CityInfo("8.8.8.8")
	if ci.Country != "" || ci.City != "" {
		t.Error("无库时 CityInfo 应为空")
	}
	if g.ASNInfo("8.8.8.8").Number != 0 {
		t.Error("无库时 ASN 应为 0")
	}
	if !g.Check("8.8.8.8", "block", "US") {
		t.Error("无库时 Check 应放行")
	}
}
