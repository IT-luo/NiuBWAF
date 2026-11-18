package proxy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type GeoCity struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	ISP       string  `json:"isp"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type GeoASN struct {
	Number uint   `json:"number"`
	Org    string `json:"org"`
}

// GeoIP 加载 ip2region.xdb（中国省市+运营商，优先）与国家/城市/ASN 三个 mmdb 库，缺失时优雅降级
type GeoIP struct {
	mu      sync.RWMutex
	xdb     *xdbSearcher
	country *maxminddb.Reader
	city    *maxminddb.Reader
	asn     *maxminddb.Reader
}

func NewGeoIP(dataDir string) *GeoIP {
	g := &GeoIP{}
	// 官方 v3 起文件更名为 ip2region_v4.xdb，旧名 ip2region.xdb（v2）同样接受
	if x, err := loadXDB(filepath.Join(dataDir, "ip2region.xdb")); err == nil {
		g.xdb = x
	} else if x, err := loadXDB(filepath.Join(dataDir, "ip2region_v4.xdb")); err == nil {
		g.xdb = x
	}
	g.country, _ = openMMDB(filepath.Join(dataDir, "geoip.mmdb"))
	g.city, _ = openMMDB(filepath.Join(dataDir, "geoip_city.mmdb"))
	g.asn, _ = openMMDB(filepath.Join(dataDir, "geoip_asn.mmdb"))
	return g
}

func openMMDB(path string) (*maxminddb.Reader, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return maxminddb.Open(path)
}

func (g *GeoIP) Available() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.country != nil || g.city != nil
}

func (g *GeoIP) CityAvailable() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.city != nil || g.xdb != nil
}

func (g *GeoIP) XDBAvailable() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.xdb != nil
}

func (g *GeoIP) ASNAvailable() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.asn != nil
}

// countryOf 调用方需持有读锁
func (g *GeoIP) countryOf(ip string) string {
	parsed := net.ParseIP(ip)
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if g.city != nil {
		if err := g.city.Lookup(parsed, &rec); err == nil && rec.Country.ISOCode != "" {
			return rec.Country.ISOCode
		}
	}
	if g.country != nil {
		if err := g.country.Lookup(parsed, &rec); err == nil {
			return rec.Country.ISOCode
		}
	}
	return ""
}

func (g *GeoIP) Country(ip string) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.countryOf(ip)
}

func (g *GeoIP) CityInfo(ip string) GeoCity {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out GeoCity
	if g.xdb != nil {
		// 中国 IP 优先 ip2region（国内城市精度高于 mmdb 城市库），海外仍走 mmdb 城市库
		if reg, ok := g.xdb.lookup(ip); ok && (reg.Country == "中国" || reg.ISO == "CN") {
			out.Country = reg.ISO
			if out.Country == "" {
				out.Country = "CN"
			}
			out.Region = reg.Province
			out.City = reg.City
			if out.City == "" {
				out.City = reg.Province
			}
			out.ISP = reg.ISP
			return out
		}
	}
	if g.city == nil {
		out.Country = g.countryOf(ip)
		return out
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Subdivisions []struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	if err := g.city.Lookup(net.ParseIP(ip), &rec); err != nil {
		out.Country = g.countryOf(ip)
		return out
	}
	out.Country = rec.Country.ISOCode
	out.City = rec.City.Names["zh-CN"]
	if out.City == "" {
		out.City = rec.City.Names["en"]
	}
	if len(rec.Subdivisions) > 0 {
		out.Region = rec.Subdivisions[0].Names["zh-CN"]
		if out.Region == "" {
			out.Region = rec.Subdivisions[0].Names["en"]
		}
	}
	out.Latitude = rec.Location.Latitude
	out.Longitude = rec.Location.Longitude
	return out
}

func (g *GeoIP) ASNInfo(ip string) GeoASN {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out GeoASN
	if g.asn == nil {
		return out
	}
	var rec struct {
		Number uint   `maxminddb:"autonomous_system_number"`
		Org    string `maxminddb:"autonomous_system_organization"`
	}
	if err := g.asn.Lookup(net.ParseIP(ip), &rec); err != nil {
		return out
	}
	out.Number = rec.Number
	out.Org = rec.Org
	return out
}

// Check 返回是否放行。mode: off / block(黑名单国家) / allow(仅允许名单国家)
func (g *GeoIP) Check(ip, mode, countries string) bool {
	if mode == "off" || mode == "" || !g.Available() {
		return true
	}
	c := g.Country(ip)
	if c == "" {
		return true
	}
	list := map[string]bool{}
	for _, x := range strings.Split(countries, ",") {
		x = strings.TrimSpace(strings.ToUpper(x))
		if x != "" {
			list[x] = true
		}
	}
	if mode == "block" {
		return !list[c]
	}
	if mode == "allow" {
		return list[c]
	}
	return true
}
