package proxy

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func ip2u32(s string) uint32 { return binary.BigEndian.Uint32(net.ParseIP(s).To4()) }

// buildTestXDB 合成最小 xdb：112.96.0.0-112.97.255.255 → 中国|0|广东省|深圳市|联通
// v3=false 生成 v2 段序（ptr 在前），v3=true 生成 v3 段序（len 在前）
func buildTestXDB(t *testing.T, v3 bool) []byte {
	t.Helper()
	region := "中国|0|广东省|深圳市|联通"
	if v3 {
		region = "中国|广东省|深圳市|联通|CN"
	}
	data := []byte(region)
	segPtr := uint32(xdbHeaderLen + xdbVecIdxLen)
	buff := make([]byte, segPtr)
	if v3 {
		binary.LittleEndian.PutUint16(buff[0:2], 3)
		binary.LittleEndian.PutUint16(buff[16:18], 4)
	} else {
		binary.LittleEndian.PutUint16(buff[0:2], 2)
	}
	binary.LittleEndian.PutUint32(buff[8:12], segPtr)
	binary.LittleEndian.PutUint32(buff[12:16], segPtr)
	for _, il1 := range []byte{96, 97} {
		off := xdbHeaderLen + (112*256+int(il1))*8
		binary.LittleEndian.PutUint32(buff[off:off+4], segPtr)
		binary.LittleEndian.PutUint32(buff[off+4:off+8], segPtr)
	}
	seg := make([]byte, xdbSegLen)
	binary.LittleEndian.PutUint32(seg[0:4], ip2u32("112.96.0.0"))
	binary.LittleEndian.PutUint32(seg[4:8], ip2u32("112.97.255.255"))
	if v3 {
		binary.LittleEndian.PutUint16(seg[8:10], uint16(len(data)))
		binary.LittleEndian.PutUint32(seg[10:14], segPtr+uint32(xdbSegLen))
	} else {
		binary.LittleEndian.PutUint32(seg[8:12], segPtr+uint32(xdbSegLen))
		binary.LittleEndian.PutUint16(seg[12:14], uint16(len(data)))
	}
	buff = append(buff, seg...)
	return append(buff, data...)
}

func TestXDBLookup(t *testing.T) {
	for _, v3 := range []bool{false, true} {
		x := &xdbSearcher{buff: buildTestXDB(t, v3), v3: v3}
		if v3 {
			x.lenPtr, x.ptrOff = 8, 10
		} else {
			x.lenPtr, x.ptrOff = 12, 8
		}
		reg, ok := x.lookup("112.97.81.30")
		if !ok || reg.Country != "中国" || reg.Province != "广东省" || reg.City != "深圳市" || reg.ISP != "联通" {
			t.Fatalf("v3=%v lookup 112.97.81.30 = %+v, ok=%v", v3, reg, ok)
		}
		if v3 && reg.ISO != "CN" {
			t.Fatalf("v3 应带 ISO 码: %+v", reg)
		}
	}
	x := &xdbSearcher{buff: buildTestXDB(t, false)}
	x.lenPtr, x.ptrOff = 12, 8
	if _, ok := x.lookup("112.98.0.1"); ok {
		t.Error("112.98.0.1 不在段内，不应命中")
	}
	if _, ok := x.lookup("8.8.8.8"); ok {
		t.Error("8.8.8.8 无向量索引项，不应命中")
	}
	if _, ok := x.lookup("2001:4860:4860::8888"); ok {
		t.Error("IPv6 不应命中 xdb")
	}
}

func TestCityInfoFromXDB(t *testing.T) {
	for _, tc := range []struct {
		name string
		v3   bool
		file string
	}{
		{"v2 旧文件名", false, "ip2region.xdb"},
		{"v3 新文件名", true, "ip2region_v4.xdb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), buildTestXDB(t, tc.v3), 0o644); err != nil {
				t.Fatal(err)
			}
			g := NewGeoIP(dir)
			if !g.CityAvailable() || !g.XDBAvailable() {
				t.Fatal("xdb 应已加载")
			}
			ci := g.CityInfo("112.97.81.30")
			if ci.Country != "CN" || ci.Region != "广东省" || ci.City != "深圳市" || ci.ISP != "联通" {
				t.Fatalf("CityInfo = %+v", ci)
			}
			if ci := g.CityInfo("8.8.8.8"); ci.Country != "" || ci.City != "" {
				t.Fatalf("仅 xdb 时海外 IP 城市应为空: %+v", ci)
			}
		})
	}
}

// 本地 data/ 放有官方 xdb 时做真实数据自检（data/ 不入库，CI 自动跳过）
func TestCityInfoRealXDB(t *testing.T) {
	dir := filepath.Join("..", "..", "data")
	if _, err := os.Stat(filepath.Join(dir, "ip2region_v4.xdb")); err != nil {
		t.Skip("无真实 ip2region_v4.xdb，跳过")
	}
	g := NewGeoIP(dir)
	if !g.XDBAvailable() {
		t.Fatal("真实 xdb 应加载成功")
	}
	ci := g.CityInfo("112.97.81.30")
	if ci.Country != "CN" || ci.Region != "广东省" || ci.City != "深圳市" || ci.ISP == "" {
		t.Fatalf("真实国内 IP 应解析出省市与运营商: %+v", ci)
	}
	t.Logf("112.97.81.30 → %+v", ci)
}

func TestLoadXDBRejectsBadFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "ip2region.xdb")
	if err := os.WriteFile(bad, make([]byte, 16), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadXDB(bad); err == nil {
		t.Error("过短文件应报错")
	}
	bin := make([]byte, xdbHeaderLen+xdbVecIdxLen+xdbSegLen)
	binary.LittleEndian.PutUint16(bin[0:2], 9)
	if err := os.WriteFile(bad, bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadXDB(bad); err == nil {
		t.Error("未知版本应报错")
	}
	binary.LittleEndian.PutUint16(bin[0:2], 3)
	binary.LittleEndian.PutUint16(bin[16:18], 6)
	if err := os.WriteFile(bad, bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadXDB(bad); err == nil {
		t.Error("v3 IPv6 库应报错")
	}
}
