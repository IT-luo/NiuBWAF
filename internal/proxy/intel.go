package proxy

// IntelResult 聚合多源 IP 情报：地理（国家/省/市/经纬度）、ASN/组织、IDC 云厂商归属、Tor 出口标记、付费威胁标签
type IntelResult struct {
	IP            string   `json:"ip"`
	Country       string   `json:"country"`
	Region        string   `json:"region"`
	City          string   `json:"city"`
	Latitude      float64  `json:"latitude"`
	Longitude     float64  `json:"longitude"`
	ASN           uint     `json:"asn"`
	ASNOrg        string   `json:"asn_org"`
	IDC           string   `json:"idc"`
	Tor           bool     `json:"tor"`
	ThreatTags    []string `json:"threat_tags"`
	ThreatScore   int      `json:"threat_score"`
	ThreatProvider string  `json:"threat_provider"`
}

// IntelLookup 按需查询（不在每请求热路径上），情报仅作展示标签，不改变自动封禁判定
func (p *Proxy) IntelLookup(ip string) IntelResult {
	city := p.Geo.CityInfo(ip)
	asn := p.Geo.ASNInfo(ip)
	res := IntelResult{
		IP:        ip,
		Country:   city.Country,
		Region:    city.Region,
		City:      city.City,
		Latitude:  city.Latitude,
		Longitude: city.Longitude,
		ASN:       asn.Number,
		ASNOrg:    asn.Org,
		IDC:       p.IDC.Match(ip),
		Tor:       p.Tor.Has(ip),
	}
	if p.threat != nil {
		tr := p.threat.Lookup(ip)
		res.ThreatTags = tr.Tags
		res.ThreatScore = tr.Score
		res.ThreatProvider = tr.Provider
	}
	return res
}

func (p *Proxy) IntelStatus() map[string]any {
	st := map[string]any{
		"geo_country": p.Geo.Available(),
		"geo_city":    p.Geo.CityAvailable(),
		"geo_asn":     p.Geo.ASNAvailable(),
		"idc":         p.IDC.Status(),
		"tor":         p.Tor.Status(),
	}
	if p.threat != nil {
		st["threat"] = p.threat.Status()
	} else {
		st["threat"] = map[string]any{"enabled": false, "provider": "off"}
	}
	return st
}

func (p *Proxy) IntelRefresh() {
	go p.IDC.Refresh()
	go p.Tor.Refresh()
}

// ThreatLookup 暴露付费情报查询供 API 测试连通性使用
func (p *Proxy) ThreatLookup(ip string) ThreatResult {
	if p.threat == nil {
		return ThreatResult{}
	}
	return p.threat.Lookup(ip)
}

// ThreatEnabled 报告付费情报是否已配置启用
func (p *Proxy) ThreatEnabled() bool {
	return p.threat != nil && p.threat.Enabled()
}
