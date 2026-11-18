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
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type GeoASN struct {
	Number uint   `json:"number"`
	Org    string `json:"org"`
}

// GeoIP 同时加载国家库（geoip.mmdb，回退）、城市库（geoip_city.mmdb）与 ASN 库（geoip_asn.mmdb），缺失时优雅降级
type GeoIP struct {
	mu      sync.RWMutex
	country *maxminddb.Reader
	city    *maxminddb.Reader
	asn     *maxminddb.Reader
}

func NewGeoIP(dataDir string) *GeoIP {
	g := &GeoIP{}
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
	return g.city != nil
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
