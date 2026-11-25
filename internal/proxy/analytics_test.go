package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeAnaStore struct {
	rows map[int64]string
}

func newFakeAnaStore() *fakeAnaStore { return &fakeAnaStore{rows: map[int64]string{}} }

func (f *fakeAnaStore) SaveAnalyticsHour(ts int64, data string) error {
	f.rows[ts] = data
	return nil
}

func (f *fakeAnaStore) LoadAnalyticsHours(since int64) (map[int64]string, error) {
	out := map[int64]string{}
	for k, v := range f.rows {
		if k >= since {
			out[k] = v
		}
	}
	return out, nil
}

func (f *fakeAnaStore) PruneAnalytics(before int64) error {
	for k := range f.rows {
		if k < before {
			delete(f.rows, k)
		}
	}
	return nil
}

func newTestAnalytics() (*Analytics, *fakeAnaStore) {
	st := newFakeAnaStore()
	return NewAnalytics(st, nil), st
}

func kvFind(kvs []KV, key string) (int64, bool) {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Count, true
		}
	}
	return 0, false
}

func geoFind(kvs []GeoKV, key string) (GeoKV, bool) {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv, true
		}
	}
	return GeoKV{}, false
}

type stubGeo struct{ info GeoCity }

func (g stubGeo) CityInfo(string) GeoCity { return g.info }

func TestAnalyticsUnresolvedAndUnlistedCountries(t *testing.T) {
	a, _ := newTestAnalytics()
	a.Record(ReqStat{IP: "10.0.0.8", Status: 200})
	a.Record(ReqStat{IP: "192.0.2.8", Status: 403, Blocked: true})
	a.geo = stubGeo{info: GeoCity{Country: "XK"}}
	a.Record(ReqStat{IP: "203.0.113.8", Status: 200})

	s := a.Snapshot(24)
	if len(s.Countries) != 2 {
		t.Fatalf("国家统计应包含未解析与字典外国家码: %+v", s.Countries)
	}
	unknown, ok := geoFind(s.Countries, "UNKNOWN")
	if !ok || unknown.Name != "未知 / 内网" || unknown.Count != 2 || unknown.Blocked != 1 {
		t.Fatalf("未解析流量统计错误: %+v", unknown)
	}
	unlisted, ok := geoFind(s.Countries, "XK")
	if !ok || unlisted.Name != "XK" || unlisted.Count != 1 {
		t.Fatalf("内置字典外国家码不应被丢弃: %+v", unlisted)
	}
	if len(s.Provinces) != 0 {
		t.Fatalf("未解析与非中国 IP 不应进入省份榜: %+v", s.Provinces)
	}
}

func TestAnalyticsRecordSnapshot(t *testing.T) {
	a, _ := newTestAnalytics()
	a.Record(ReqStat{IP: "1.2.3.4", Host: "a.com", Path: "/index", UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", Status: 200})
	a.Record(ReqStat{IP: "1.2.3.4", Host: "a.com", Path: "/admin", Status: 404})
	a.Record(ReqStat{IP: "5.6.7.8", Host: "b.com", Path: "/x?id=1", Status: 403, Blocked: true})
	a.Record(ReqStat{IP: "5.6.7.9", Host: "b.com", Path: "/y", Status: 502})

	s := a.Snapshot(24)
	if s.Totals.Req != 4 || s.Totals.Blocked != 1 {
		t.Fatalf("totals = %+v", s.Totals)
	}
	if s.Totals.UV != 3 {
		t.Fatalf("uv = %d, want 3", s.Totals.UV)
	}
	if s.Totals.C4xx != 2 || s.Totals.C5xx != 1 {
		t.Fatalf("4xx/5xx = %d/%d, want 2/1", s.Totals.C4xx, s.Totals.C5xx)
	}
	if s.Totals.BlockRate != 25 {
		t.Fatalf("block rate = %v, want 25", s.Totals.BlockRate)
	}
	if v, _ := kvFind(s.Status, "200"); v != 1 {
		t.Fatalf("status 200 = %d", v)
	}
	if v, _ := kvFind(s.OS, "Windows"); v != 1 {
		t.Fatalf("os windows = %d", v)
	}
	if v, _ := kvFind(s.Browser, "Chrome"); v != 1 {
		t.Fatalf("browser chrome = %d", v)
	}
	if v, _ := kvFind(s.Host, "b.com"); v != 2 {
		t.Fatalf("host b.com = %d", v)
	}
}

func TestAnalyticsTrafficRankings(t *testing.T) {
	a, _ := newTestAnalytics()
	for i := 0; i < 2; i++ {
		a.Record(ReqStat{
			IP: "1.2.3.4", Host: "a.com", Page: "https://a.com/login",
			Referer: "b.com", RefererPage: "https://b.com/from", Status: 200,
		})
	}
	a.Record(ReqStat{IP: "5.6.7.8", Page: "https://a.com/", Referer: "c.com", RefererPage: "https://c.com/", Status: 200})

	s := a.Snapshot(24)
	if v, _ := kvFind(s.Referer, "b.com"); v != 2 {
		t.Fatalf("referer b.com = %d, want 2", v)
	}
	if v, _ := kvFind(s.RefererPage, "https://b.com/from"); v != 2 {
		t.Fatalf("referer page = %d, want 2", v)
	}
	if v, _ := kvFind(s.Page, "https://a.com/login"); v != 2 {
		t.Fatalf("visited page = %d, want 2", v)
	}
}

func TestAnalyticsTrafficRankLimit(t *testing.T) {
	a, _ := newTestAnalytics()
	for i := 0; i < trafficTopN+10; i++ {
		page := "https://a.com/" + itoa(i)
		a.Record(ReqStat{IP: "1.2.3.4", Page: page, RefererPage: page, Status: 200})
	}
	s := a.Snapshot(24)
	if len(s.Page) != trafficTopN || len(s.RefererPage) != trafficTopN {
		t.Fatalf("traffic rank sizes = %d/%d, want %d", len(s.Page), len(s.RefererPage), trafficTopN)
	}
}

func TestExternalReferer(t *testing.T) {
	tests := []struct {
		referer, self, host, page string
	}{
		{"https://stackblitz.com/", "a.com", "stackblitz.com", "https://stackblitz.com/"},
		{"https://cn.bing.com/search?q=secret#result", "a.com", "cn.bing.com", "https://cn.bing.com/search"},
		{"https://B.com:8443/a%2Fb?token=secret", "a.com", "b.com", "https://b.com:8443/a%2Fb"},
		{"https://a.com:8443/internal", "a.com", "", ""},
		{"javascript://a.com/alert", "b.com", "", ""},
		{"not a url", "a.com", "", ""},
		{"", "a.com", "", ""},
	}
	for _, tt := range tests {
		host, page := externalReferer(tt.referer, tt.self)
		if host != tt.host || page != tt.page {
			t.Errorf("externalReferer(%q) = %q/%q, want %q/%q", tt.referer, host, page, tt.host, tt.page)
		}
	}
}

func TestVisitedPage(t *testing.T) {
	if got := visitedPage(true, "a.com", "/login"); got != "https://a.com/login" {
		t.Fatalf("secure visited page = %q", got)
	}
	if got := visitedPage(false, "a.com", ""); got != "http://a.com/" {
		t.Fatalf("empty visited path = %q", got)
	}
	if got := visitedPage(true, "", "/"); got != "" {
		t.Fatalf("empty visited host = %q", got)
	}
}

func TestAnalyticsEventAggregation(t *testing.T) {
	a, _ := newTestAnalytics()
	a.Event(EvStat{IP: "9.9.9.9", Action: "waf", RuleID: 942100, Msg: "SQL Injection Detected", Status: 403, Country: "US", City: "Ashburn", Lat: 39.04, Lon: -77.49, URL: "/login?id=1' OR '1'='1", Domain: "a.com"})
	a.Event(EvStat{IP: "9.9.9.9", Action: "waf", RuleID: 941100, Msg: "XSS Filter", Status: 403, Country: "US", City: "Ashburn", Lat: 39.04, Lon: -77.49, URL: "/search?q=<script>", Domain: "a.com"})
	a.Event(EvStat{IP: "8.8.8.8", Action: "cc", Msg: "访问频率超限，触发人机验证", Status: http.StatusTooManyRequests, Domain: "b.com", URL: "/api"})
	a.Event(EvStat{IP: "7.7.7.7", Action: "bot", Msg: "Bot 防护", RuleID: 200001, Status: 403, Country: "CN", Domain: "a.com", URL: "/"})

	s := a.Snapshot(24)
	if v, _ := kvFind(s.Modules, "攻击防护"); v != 2 {
		t.Fatalf("module 攻击防护 = %d, want 2", v)
	}
	if v, _ := kvFind(s.Modules, "人机验证"); v != 1 {
		t.Fatalf("module 人机验证 = %d, want 1", v)
	}
	if v, _ := kvFind(s.Categories, "SQL 注入"); v != 1 {
		t.Fatalf("category SQL 注入 = %d", v)
	}
	if v, _ := kvFind(s.Categories, "XSS"); v != 1 {
		t.Fatalf("category XSS = %d", v)
	}
	if v, _ := kvFind(s.Categories, "CC 攻击"); v != 1 {
		t.Fatalf("category CC 攻击 = %d", v)
	}
	if v, _ := kvFind(s.AttackIPs, "9.9.9.9"); v != 2 {
		t.Fatalf("attack ip = %d", v)
	}
	if v, _ := kvFind(s.AttackPaths, "/login"); v != 1 {
		t.Fatalf("attack path = %d", v)
	}
	for _, path := range s.AttackPaths {
		if strings.Contains(path.Key, "?") {
			t.Fatalf("攻击路径统计保留了查询串: %q", path.Key)
		}
	}
	if v, _ := kvFind(s.AttackHosts, "a.com"); v != 3 {
		t.Fatalf("attack host = %d", v)
	}
	mips := s.ModuleIPs["攻击防护"]
	if v, _ := kvFind(mips, "9.9.9.9"); v != 2 {
		t.Fatalf("module ip = %d", v)
	}
	if len(s.Arcs) != 1 {
		t.Fatalf("arcs = %+v, want 1 (Ashburn)", s.Arcs)
	}
	if s.Arcs[0].Name != "Ashburn" || s.Arcs[0].Count != 2 {
		t.Fatalf("arc = %+v", s.Arcs[0])
	}
	if len(s.Hours) != 1 || s.Hours[0].Modules["攻击防护"] != 2 {
		t.Fatalf("hour modules = %+v", s.Hours)
	}
}

func TestAnalyticsBucketRotationPersist(t *testing.T) {
	a, st := newTestAnalytics()
	a.Record(ReqStat{IP: "1.1.1.1", Status: 200})
	old := hourOf(time.Now()) - 7200
	a.mu.Lock()
	a.cur.TS = old // 模拟跨小时：当前桶带着数据变成旧桶
	a.mu.Unlock()
	a.Record(ReqStat{IP: "2.2.2.2", Status: 200})

	a.mu.Lock()
	histLen := len(a.hist)
	curTS := a.cur.TS
	a.mu.Unlock()
	if histLen != 1 {
		t.Fatalf("hist = %d, want 1 sealed bucket", histLen)
	}
	if curTS != hourOf(time.Now()) {
		t.Fatalf("cur ts = %d, want current hour", curTS)
	}
	var sealed hourBucket
	if data, ok := st.rows[old]; !ok || json.Unmarshal([]byte(data), &sealed) != nil || sealed.Req != 1 {
		t.Fatalf("sealed bucket not persisted correctly, rows = %v", st.rows)
	}
	// 重启恢复：新实例应从落盘行还原历史桶
	a2 := NewAnalytics(st, nil)
	a2.mu.Lock()
	restored := len(a2.hist)
	a2.mu.Unlock()
	if restored != 1 {
		t.Fatalf("restored hist = %d, want 1", restored)
	}
	s := a2.Snapshot(24)
	var found bool
	for _, h := range s.Hours {
		if h.TS == old && h.Req == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("restored bucket missing from snapshot: %+v", s.Hours)
	}
}

func TestAnalyticsCurrentHourRestore(t *testing.T) {
	st := newFakeAnaStore()
	a := NewAnalytics(st, nil)
	a.Record(ReqStat{IP: "1.1.1.1", Page: "https://a.com/login", RefererPage: "https://b.com/from", Status: 200})
	a.Record(ReqStat{IP: "2.2.2.2", Status: 403, Blocked: true})
	a.Event(EvStat{IP: "8.8.8.8", Action: "waf", RuleID: 942100, Status: 403, Country: "US", City: "Mountain View", Lat: 37.4, Lon: -122.1, URL: "/?id=1", Domain: "bench.local"})
	a.Persist()

	// 模拟重启：当前小时桶必须恢复为活桶，而非封存进 hist 后被 cur 落盘覆盖丢数据
	a2 := NewAnalytics(st, nil)
	a2.mu.Lock()
	curTS, histLen, uvBase := a2.cur.TS, len(a2.hist), a2.cur.uvBase
	a2.mu.Unlock()
	if curTS != hourOf(time.Now()) || histLen != 0 {
		t.Fatalf("当前小时桶应恢复为 cur: ts=%d hist=%d", curTS, histLen)
	}
	if uvBase != 2 {
		t.Fatalf("UV 基数 = %d, want 2", uvBase)
	}
	s := a2.Snapshot(24)
	if s.Totals.Req != 2 || s.Totals.Blocked != 1 {
		t.Fatalf("重启后总量丢失: %+v", s.Totals)
	}
	if len(s.Arcs) != 1 || s.Arcs[0].Count != 1 {
		t.Fatalf("重启后攻击轨迹丢失: %+v", s.Arcs)
	}
	if s.Totals.UV != 2 {
		t.Fatalf("重启后 UV = %d, want 2", s.Totals.UV)
	}
	// 恢复后的活桶继续写入（nil map 不应 panic），再次落盘+重启数据仍不丢
	a2.Record(ReqStat{IP: "3.3.3.3", Page: "https://a.com/login", RefererPage: "https://b.com/from", Status: 200})
	a2.Event(EvStat{IP: "9.9.9.9", Action: "cc", Status: 429})
	a2.Persist()
	if got := a2.Snapshot(24).Totals; got.Req != 3 || got.UV != 3 {
		t.Fatalf("恢复桶累加错误: %+v", got)
	}
	a3 := NewAnalytics(st, nil)
	if got := a3.Snapshot(24).Totals; got.Req != 3 || got.Blocked != 1 || got.UV != 3 {
		t.Fatalf("二次重启数据丢失: %+v", got)
	}
	if len(a3.Snapshot(24).Arcs) != 1 {
		t.Fatal("二次重启后攻击轨迹丢失")
	}
	s3 := a3.Snapshot(24)
	if v, _ := kvFind(s3.Page, "https://a.com/login"); v != 2 {
		t.Fatalf("二次重启后受访页面统计 = %d, want 2", v)
	}
	if v, _ := kvFind(s3.RefererPage, "https://b.com/from"); v != 2 {
		t.Fatalf("二次重启后来源页面统计 = %d, want 2", v)
	}
}

func TestAnalyticsSealReleasesIPSet(t *testing.T) {
	a, _ := newTestAnalytics()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		a.Record(ReqStat{IP: ip, Status: 200})
	}
	old := hourOf(time.Now()) - 7200
	a.mu.Lock()
	a.cur.TS = old // 模拟跨小时
	a.mu.Unlock()
	a.Record(ReqStat{IP: "4.4.4.4", Status: 200})

	a.mu.Lock()
	if len(a.hist) != 1 {
		a.mu.Unlock()
		t.Fatalf("hist = %d, want 1 sealed bucket", len(a.hist))
	}
	sealed := a.hist[0]
	uv, ipsNil := sealed.UV, sealed.ips == nil
	curIPs := len(a.cur.ips)
	a.mu.Unlock()
	if !ipsNil {
		t.Fatalf("sealed bucket still holds %d IPs, want released", len(sealed.ips))
	}
	if uv != 3 {
		t.Fatalf("sealed UV = %d, want 3", uv)
	}
	if curIPs != 1 {
		t.Fatalf("current bucket ips = %d, want 1 (UV 统计不受影响)", curIPs)
	}
	// 释放 IP 集合后，快照中历史桶 UV 仍须正确
	s := a.Snapshot(24)
	var found bool
	for _, h := range s.Hours {
		if h.TS == old {
			found = true
			if h.UV != 3 {
				t.Fatalf("snapshot sealed UV = %d, want 3", h.UV)
			}
		}
	}
	if !found {
		t.Fatalf("sealed bucket missing from snapshot: %+v", s.Hours)
	}
	if s.Totals.UV != 4 {
		t.Fatalf("totals UV = %d, want 4 (3 历史 + 1 当前)", s.Totals.UV)
	}
}

// lockProbeGeo 探针：CityInfo 被调用时若能抢到 Analytics 全局锁，说明查询在锁外执行
type lockProbeGeo struct {
	a    *Analytics
	held bool
}

func (g *lockProbeGeo) CityInfo(ip string) GeoCity {
	if g.a.mu.TryLock() {
		g.a.mu.Unlock()
	} else {
		g.held = true
	}
	return GeoCity{Country: "CN", Region: "广东"}
}

func TestAnalyticsRecordGeoOutsideLock(t *testing.T) {
	a, _ := newTestAnalytics()
	probe := &lockProbeGeo{a: a}
	a.geo = probe
	a.Record(ReqStat{
		IP: "1.1.1.1", Status: 403, Blocked: true,
		UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	})
	if probe.held {
		t.Fatal("CityInfo 在 Analytics 全局锁内执行，高 QPS 下所有请求会在单锁上串行化")
	}
	a.mu.Lock()
	country, countryBlock := a.cur.Country["CN"], a.cur.CnBlock["CN"]
	prov, provBlock := a.cur.Prov["广东"], a.cur.ProvBlock["广东"]
	os, browser := a.cur.OS["Windows"], a.cur.Browser["Chrome"]
	a.mu.Unlock()
	if country != 1 || countryBlock != 1 || prov != 1 || provBlock != 1 {
		t.Fatalf("锁外计算后地理聚合错误: country=%d/%d prov=%d/%d", country, countryBlock, prov, provBlock)
	}
	if os != 1 || browser != 1 {
		t.Fatalf("UA 分类聚合错误: os=%d browser=%d", os, browser)
	}
}

// lockProbeStore 探针：落盘/清理被调用时若能抢到 Analytics 全局锁，说明 I/O 在锁外执行
type lockProbeStore struct {
	*fakeAnaStore
	a    *Analytics
	held bool
}

func (s *lockProbeStore) probe() {
	if s.a.mu.TryLock() {
		s.a.mu.Unlock()
	} else {
		s.held = true
	}
}

func (s *lockProbeStore) SaveAnalyticsHour(ts int64, data string) error {
	s.probe()
	return s.fakeAnaStore.SaveAnalyticsHour(ts, data)
}

func (s *lockProbeStore) PruneAnalytics(before int64) error {
	s.probe()
	return s.fakeAnaStore.PruneAnalytics(before)
}

func TestAnalyticsPersistOutsideLock(t *testing.T) {
	st := &lockProbeStore{fakeAnaStore: newFakeAnaStore()}
	a := NewAnalytics(st, nil)
	st.a = a
	// 跨小时封存路径：Record 触发的落盘与清理都不得在锁内
	a.Record(ReqStat{IP: "1.1.1.1", Status: 200})
	a.mu.Lock()
	a.cur.TS = hourOf(time.Now()) - 7200
	a.mu.Unlock()
	a.Record(ReqStat{IP: "2.2.2.2", Status: 200})
	if st.held {
		t.Fatal("封存桶落盘/清理在全局锁内执行，磁盘 I/O 会停顿请求路径")
	}
	if len(st.rows) != 1 {
		t.Fatalf("封存桶未落盘: rows=%d", len(st.rows))
	}
	// 周期 Persist 路径：当前桶持锁序列化，但写库必须在锁外
	st.held = false
	a.Persist()
	if st.held {
		t.Fatal("Persist 写库在全局锁内执行")
	}
}

func TestAnalyticsSnapshotDeepCopy(t *testing.T) {
	a, _ := newTestAnalytics()
	a.Event(EvStat{IP: "1.1.1.1", Action: "waf", RuleID: 942100, Status: 403})
	s := a.Snapshot(24)
	s.Hours[0].Modules["攻击防护"] = 999
	s2 := a.Snapshot(24)
	if s2.Hours[0].Modules["攻击防护"] != 1 {
		t.Fatalf("snapshot leaked live map: %v", s2.Hours[0].Modules)
	}
}

func TestIncMapCap(t *testing.T) {
	m := map[string]int64{}
	incMap(m, "sentinel")
	for i := 0; i < mapCap+100; i++ {
		incMap(m, "k"+itoa(i))
	}
	if len(m) > mapCap {
		t.Fatalf("map size = %d, want <= %d", len(m), mapCap)
	}
	incMap(m, "")
	incMap(m, "sentinel")
	if m["sentinel"] != 2 {
		t.Fatalf("existing key should still count after cap, got %d", m["sentinel"])
	}
}

func TestClassifyUA(t *testing.T) {
	cases := []struct {
		ua, os, browser string
		wantTool        bool
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", "Windows", "Chrome", false},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "iOS", "Safari", false},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0", "Linux", "Firefox", false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0", "Windows", "Edge", false},
		{"curl/8.4.0", "其他", "其他", true},
		{"python-requests/2.31.0", "其他", "其他", true},
	}
	for _, c := range cases {
		os, br, tool := classifyUA(c.ua)
		if os != c.os || br != c.browser {
			t.Errorf("classifyUA(%q) = %s/%s, want %s/%s", c.ua, os, br, c.os, c.browser)
		}
		if (tool != "") != c.wantTool {
			t.Errorf("classifyUA(%q) tool = %q, wantTool = %v", c.ua, tool, c.wantTool)
		}
	}
}

func TestCategoryOf(t *testing.T) {
	cases := []struct {
		action string
		ruleID int
		want   string
	}{
		{"waf", 942100, "SQL 注入"},
		{"semantic", 100200, "SQL 注入"},
		{"semantic", 100201, "XSS"},
		{"semantic", 100203, "命令注入"},
		{"semantic", 100202, "目录穿越"},
		{"waf", 941100, "XSS"},
		{"waf", 932100, "命令注入"},
		{"waf", 930100, "目录穿越"},
		{"waf", 933100, "代码注入"},
		{"waf", 951100, "信息泄露"},
		{"waf", 920100, "协议异常"},
		{"bot", 200001, "Bot 爬虫"},
		{"cc", 0, "CC 攻击"},
		{"blacklist", 0, "访问控制"},
		{"reputation", 0, "访问控制"},
		{"geo", 0, "访问控制"},
		{"resp", 0, "信息泄露"},
		{"waf", 0, "其他"},
	}
	for _, c := range cases {
		if got := categoryOf(c.action, c.ruleID, ""); got != c.want {
			t.Errorf("categoryOf(%s, %d) = %s, want %s", c.action, c.ruleID, got, c.want)
		}
	}
}

func TestBucketJSONRoundTrip(t *testing.T) {
	b := newBucket(hourOf(time.Now()))
	b.Req = 5
	b.Blocked = 2
	b.Status[403] = 2
	b.Module["攻击防护"] = 2
	b.Arc["Ashburn"] = &arcSrc{Label: "Ashburn", Country: "US", Lat: 39, Lon: -77, N: 2}
	b.ModIP["攻击防护"] = map[string]int64{"9.9.9.9": 2}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	b2 := &hourBucket{}
	if err := json.Unmarshal(data, b2); err != nil {
		t.Fatal(err)
	}
	if b2.Req != 5 || b2.Module["攻击防护"] != 2 || b2.Arc["Ashburn"] == nil || b2.Arc["Ashburn"].N != 2 || b2.ModIP["攻击防护"]["9.9.9.9"] != 2 {
		t.Fatalf("round trip mismatch: req=%d mod=%v arc=%+v modip=%v", b2.Req, b2.Module, b2.Arc["Ashburn"], b2.ModIP)
	}
	// omitempty 空 map 恢复为 nil，mergeAdd 必须容忍
	mergeAdd(map[string]int64{}, b2.ProvBlock)
}

func TestGeoCoordsFallback(t *testing.T) {
	lat, lon := geoCoords(GeoCity{Country: "US"})
	if lat == 0 && lon == 0 {
		t.Fatal("country centroid fallback failed for US")
	}
	lat, lon = geoCoords(GeoCity{Country: "CN", Region: "广东"})
	cent := provinceCentroid["广东"]
	if lat != cent[0] || lon != cent[1] {
		t.Fatalf("province fallback = %v/%v, want %v/%v", lat, lon, cent[0], cent[1])
	}
	// ip2region 风格后缀也必须命中同一质心
	for _, region := range []string{"广东省", "北京市", "广西壮族自治区", "香港特别行政区", "内蒙古自治区"} {
		lat, lon = geoCoords(GeoCity{Country: "CN", Region: region})
		if lat == 0 || lon == 0 {
			t.Fatalf("province fallback failed for %s", region)
		}
	}
	lat, lon = geoCoords(GeoCity{})
	if lat != 0 || lon != 0 {
		t.Fatalf("empty geo should be 0/0, got %v/%v", lat, lon)
	}
}

func TestSnapshotNilSafe(t *testing.T) {
	var a *Analytics
	s := a.Snapshot(24)
	if s == nil || s.Totals.Req != 0 {
		t.Fatalf("nil analytics snapshot = %+v", s)
	}
	q := a.QPS(true)
	if q == nil || q.QPS != 0 || q.Peak != 0 {
		t.Fatalf("nil analytics qps = %+v", q)
	}
}

func TestQPSRollingWindow(t *testing.T) {
	a, _ := newTestAnalytics()
	now := time.Now().Unix()
	// 近 5 个完整秒各 10 req（其中最后一秒 3 blocked），更早一秒 100 req 作峰值
	for i := int64(1); i <= 5; i++ {
		ts := now - i
		a.secs[ts%120] = SecPoint{TS: ts, Req: 10}
	}
	a.secs[(now-1)%120] = SecPoint{TS: now - 1, Req: 10, Blocked: 3}
	a.secs[(now-30)%120] = SecPoint{TS: now - 30, Req: 100}
	q := a.qpsAt(now, true)
	if q.QPS != 10 {
		t.Fatalf("qps = %v, want 10", q.QPS)
	}
	if q.BlockedQPS != 0.6 {
		t.Fatalf("blocked_qps = %v, want 0.6", q.BlockedQPS)
	}
	if q.Peak != 100 {
		t.Fatalf("peak = %v, want 100", q.Peak)
	}
	if q.Req != 10 || q.Blocked != 3 || q.TS != now-1 {
		t.Fatalf("last second = %+v", q)
	}
	if len(q.Series) != 60 || q.Series[59].TS != now-1 || q.Series[0].TS != now-60 {
		t.Fatalf("series shape wrong: len=%d", len(q.Series))
	}
	for i := 1; i < len(q.Series); i++ {
		if q.Series[i].TS <= q.Series[i-1].TS {
			t.Fatalf("series not ascending at %d", i)
		}
	}
	// 峰值滑出 60s 窗口后不再计入
	q = a.qpsAt(now+31, false)
	if q.Peak != 10 {
		t.Fatalf("peak after window slide = %v, want 10", q.Peak)
	}
	if q.QPS != 0 {
		t.Fatalf("qps after idle = %v, want 0", q.QPS)
	}
}

func TestQPSRingOverwrite(t *testing.T) {
	a, _ := newTestAnalytics()
	now := time.Now().Unix()
	ts := now - 1
	slot := ts % 120
	a.secs[slot] = SecPoint{TS: ts, Req: 5}
	// 同槽位被 120 秒前的旧数据复用时不得误读
	a.secs[slot] = SecPoint{TS: ts - 120, Req: 99}
	q := a.qpsAt(now, false)
	if q.Req != 0 || q.QPS != 0 {
		t.Fatalf("stale slot leaked: %+v", q)
	}
}

func TestQPSRecordCounts(t *testing.T) {
	a, _ := newTestAnalytics()
	for i := 0; i < 3; i++ {
		a.Record(ReqStat{IP: "1.2.3.4", UA: "curl/8", Status: 200, Blocked: i == 0})
	}
	q := a.qpsAt(time.Now().Unix()+1, false)
	if q.Req != 3 || q.Blocked != 1 {
		t.Fatalf("record counts = %+v, want req=3 blocked=1", q)
	}
	if q.QPS != 0.6 || q.BlockedQPS != 0.2 {
		t.Fatalf("rolling = %v/%v, want 0.6/0.2", q.QPS, q.BlockedQPS)
	}
}
