package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

// ip2region xdb 纯 Go 读取器：全文件内存缓存 + 向量索引二分，零依赖
// 兼容 v2（段索引 start|end|ptr u32|len u16）与 v3（start|end|len u16|ptr u32，仅 IPv4 库）
const (
	xdbHeaderLen = 256
	xdbVecIdxLen = 256 * 256 * 8
	xdbSegLen    = 14
)

type xdbSearcher struct {
	buff   []byte
	v3     bool
	lenPtr int // 段索引内 dataLen 字段偏移（v2=12, v3=8）
	ptrOff int // 段索引内 dataPtr 字段偏移（v2=8, v3=10）
}

func loadXDB(path string) (*xdbSearcher, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < xdbHeaderLen+xdbVecIdxLen+xdbSegLen {
		return nil, fmt.Errorf("xdb 文件过短: %d 字节", len(b))
	}
	x := &xdbSearcher{buff: b}
	switch v := binary.LittleEndian.Uint16(b[0:2]); v {
	case 2:
		x.lenPtr, x.ptrOff = 12, 8
	case 3:
		if ipver := binary.LittleEndian.Uint16(b[16:18]); ipver != 4 {
			return nil, fmt.Errorf("仅支持 IPv4 xdb 库, 当前 IPVersion=%d", ipver)
		}
		x.v3 = true
		x.lenPtr, x.ptrOff = 8, 10
	default:
		return nil, fmt.Errorf("不支持的 xdb 版本: %d", v)
	}
	return x, nil
}

type xdbRegion struct {
	Country  string
	Province string
	City     string
	ISP      string
	ISO      string
}

// 区域串格式：v2 = 国家|区域|省份|城市|ISP；v3 = 国家|省份|城市|ISP|ISO 国家码，空字段为 "0"
func parseXDBRegion(s string, v3 bool) xdbRegion {
	p := strings.Split(s, "|")
	get := func(i int) string {
		if i < len(p) && p[i] != "0" {
			return p[i]
		}
		return ""
	}
	r := xdbRegion{Country: get(0)}
	if v3 {
		r.Province, r.City, r.ISP, r.ISO = get(1), get(2), get(3), get(4)
	} else {
		r.Province, r.City, r.ISP = get(2), get(3), get(4)
	}
	return r
}

func (x *xdbSearcher) lookup(ip string) (xdbRegion, bool) {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil || x == nil {
		return xdbRegion{}, false
	}
	target := binary.BigEndian.Uint32(v4)
	off := xdbHeaderLen + (int(v4[0])*256+int(v4[1]))*8
	startPtr := binary.LittleEndian.Uint32(x.buff[off : off+4])
	endPtr := binary.LittleEndian.Uint32(x.buff[off+4 : off+8])
	if startPtr == 0 || int(endPtr)+xdbSegLen > len(x.buff) {
		return xdbRegion{}, false
	}
	lo, hi := 0, int(endPtr-startPtr)/xdbSegLen
	for lo <= hi {
		mid := (lo + hi) / 2
		p := int(startPtr) + mid*xdbSegLen
		sip := binary.LittleEndian.Uint32(x.buff[p : p+4])
		eip := binary.LittleEndian.Uint32(x.buff[p+4 : p+8])
		if target < sip {
			hi = mid - 1
			continue
		}
		if target > eip {
			lo = mid + 1
			continue
		}
		dlen := int(binary.LittleEndian.Uint16(x.buff[p+x.lenPtr : p+x.lenPtr+2]))
		dptr := binary.LittleEndian.Uint32(x.buff[p+x.ptrOff : p+x.ptrOff+4])
		if int(dptr)+dlen > len(x.buff) {
			return xdbRegion{}, false
		}
		return parseXDBRegion(string(x.buff[dptr : int(dptr)+dlen]), x.v3), true
	}
	return xdbRegion{}, false
}
