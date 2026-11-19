package proxy

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// 分析聚合：小时桶内存累加 + SQLite 落盘，支撑流量分析 / 安全态势 / 大屏攻击轨迹。
// 全部计数有上限（mapCap / ipCap），避免异常流量撑爆内存。

const (
	mapCap      = 512
	ipCap       = 100000
	keepHours   = 24 * 7 // 落盘保留 7 天
	topN        = 10
	arcTopN     = 12
	pathMaxLen  = 128
	referMaxLen = 128
)

type arcSrc struct {
	Label   string  `json:"label"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	N       int64   `json:"n"`
}

type hourBucket struct {
	TS        int64                       `json:"ts"`
	Req       int64                       `json:"req"`
	Blocked   int64                       `json:"blocked"`
	C4xx      int64                       `json:"c4xx"`
	C5xx      int64                       `json:"c5xx"`
	UV        int64                       `json:"uv"`
	Status    map[int]int64               `json:"status,omitempty"`
	OS        map[string]int64            `json:"os,omitempty"`
	Browser   map[string]int64            `json:"browser,omitempty"`
	Tool      map[string]int64            `json:"tool,omitempty"`
	Referer   map[string]int64            `json:"referer,omitempty"`
	Host      map[string]int64            `json:"host,omitempty"`
	Path      map[string]int64            `json:"path,omitempty"`
	Country   map[string]int64            `json:"country,omitempty"`
	CnBlock   map[string]int64            `json:"country_blocked,omitempty"`
	Prov      map[string]int64            `json:"province,omitempty"`
	ProvBlock map[string]int64            `json:"province_blocked,omitempty"`
	Module    map[string]int64            `json:"module,omitempty"`
	Category  map[string]int64            `json:"category,omitempty"`
	AttackIP  map[string]int64            `json:"attack_ip,omitempty"`
	AtkPath   map[string]int64            `json:"attack_path,omitempty"`
	AtkHost   map[string]int64            `json:"attack_host,omitempty"`
	ModIP     map[string]map[string]int64 `json:"mod_ip,omitempty"`
	Arc       map[string]*arcSrc          `json:"arc,omitempty"`

	ips    map[string]struct{} `json:"-"`
	uvBase int64               `json:"-"` // 重启恢复当前小时桶时的 UV 基数（历史 IP 集合不可恢复）
	sealed bool                `json:"-"`
}

func newBucket(hour int64) *hourBucket {
	return &hourBucket{
		TS: hour, Status: map[int]int64{}, OS: map[string]int64{}, Browser: map[string]int64{},
		Tool: map[string]int64{}, Referer: map[string]int64{}, Host: map[string]int64{}, Path: map[string]int64{},
		Country: map[string]int64{}, CnBlock: map[string]int64{}, Prov: map[string]int64{}, ProvBlock: map[string]int64{},
		Module: map[string]int64{}, Category: map[string]int64{}, AttackIP: map[string]int64{},
		AtkPath: map[string]int64{}, AtkHost: map[string]int64{},
		ModIP: map[string]map[string]int64{}, Arc: map[string]*arcSrc{}, ips: map[string]struct{}{},
	}
}

func incMap(m map[string]int64, k string) {
	if k == "" {
		return
	}
	if v, ok := m[k]; ok {
		m[k] = v + 1
	} else if len(m) < mapCap {
		m[k] = 1
	}
}

// ReqStat 单请求维度（ServeHTTP 收尾埋点）
type ReqStat struct {
	IP, Host, Path, UA, Referer string
	Status                      int
	Blocked                     bool
}

// EvStat 单安全事件维度（logAttack 埋点，geo 已含回退坐标）
type EvStat struct {
	IP, Action, Msg string
	RuleID, Status  int
	Country, City   string
	Lat, Lon        float64
	URL, Domain     string
}

// geoLookup 抽象地理查询，便于单测用探针验证查询在全局锁外执行
type geoLookup interface {
	CityInfo(ip string) GeoCity
}

type Analytics struct {
	mu sync.Mutex
	st interface {
		SaveAnalyticsHour(ts int64, data string) error
		LoadAnalyticsHours(since int64) (map[int64]string, error)
		PruneAnalytics(before int64) error
	}
	geo  geoLookup
	cur  *hourBucket
	hist []*hourBucket
	secs [120]SecPoint // 秒级环形桶（仅内存，重启清零），支撑实时 QPS
}

func NewAnalytics(st interface {
	SaveAnalyticsHour(ts int64, data string) error
	LoadAnalyticsHours(since int64) (map[int64]string, error)
	PruneAnalytics(before int64) error
}, geo *GeoIP) *Analytics {
	a := &Analytics{st: st, cur: newBucket(hourOf(time.Now()))}
	if geo != nil {
		a.geo = geo // 仅在非 nil 时装箱，避免接口包裹 nil 指针后判空失效
	}
	if rows, err := st.LoadAnalyticsHours(time.Now().Add(-keepHours * time.Hour).Unix()); err == nil {
		curHour := hourOf(time.Now())
		for ts, data := range rows {
			b := &hourBucket{}
			if json.Unmarshal([]byte(data), b) != nil || b.TS != ts {
				continue
			}
			if ts == curHour {
				// 当前小时桶恢复为活桶继续累加：若放入 hist，cur 的周期落盘会
				// 覆盖该行，导致下次重启丢失本小时全部数据（含大屏攻击轨迹）
				b.ensureMaps()
				b.ips = map[string]struct{}{}
				b.uvBase = b.UV
				a.cur = b
				continue
			}
			b.sealed = true
			a.hist = append(a.hist, b)
		}
		sort.Slice(a.hist, func(i, j int) bool { return a.hist[i].TS < a.hist[j].TS })
	}
	go func() {
		for range time.Tick(60 * time.Second) {
			a.Persist()
		}
	}()
	return a
}

func hourOf(t time.Time) int64 {
	return t.Unix() / 3600 * 3600
}

// ensureMaps 补齐 JSON 恢复后可能为 nil 的 map（omitempty 下空map不序列化），活桶写入前必须调用
func (b *hourBucket) ensureMaps() {
	if b.Status == nil {
		b.Status = map[int]int64{}
	}
	if b.OS == nil {
		b.OS = map[string]int64{}
	}
	if b.Browser == nil {
		b.Browser = map[string]int64{}
	}
	if b.Tool == nil {
		b.Tool = map[string]int64{}
	}
	if b.Referer == nil {
		b.Referer = map[string]int64{}
	}
	if b.Host == nil {
		b.Host = map[string]int64{}
	}
	if b.Path == nil {
		b.Path = map[string]int64{}
	}
	if b.Country == nil {
		b.Country = map[string]int64{}
	}
	if b.CnBlock == nil {
		b.CnBlock = map[string]int64{}
	}
	if b.Prov == nil {
		b.Prov = map[string]int64{}
	}
	if b.ProvBlock == nil {
		b.ProvBlock = map[string]int64{}
	}
	if b.Module == nil {
		b.Module = map[string]int64{}
	}
	if b.Category == nil {
		b.Category = map[string]int64{}
	}
	if b.AttackIP == nil {
		b.AttackIP = map[string]int64{}
	}
	if b.AtkPath == nil {
		b.AtkPath = map[string]int64{}
	}
	if b.AtkHost == nil {
		b.AtkHost = map[string]int64{}
	}
	if b.ModIP == nil {
		b.ModIP = map[string]map[string]int64{}
	}
	if b.Arc == nil {
		b.Arc = map[string]*arcSrc{}
	}
}

// touch 调用方持锁；跨小时则封存当前桶，并返回待落盘的封存桶（调用方解锁后写库）
func (a *Analytics) touch() (cur, sealed *hourBucket) {
	now := hourOf(time.Now())
	if a.cur.TS != now {
		old := a.cur
		a.sealLocked(old)
		a.cur = newBucket(now)
		return a.cur, old
	}
	return a.cur, nil
}

// sealLocked 只做内存操作：封存后桶不可变，序列化与写库在锁外进行
func (a *Analytics) sealLocked(b *hourBucket) {
	if b.sealed {
		return
	}
	b.UV = b.uvBase + int64(len(b.ips))
	// 封存后 UV 已定型（Snapshot 对已封存桶只读 UV），释放 IP 集合，
	// 否则 168 个历史桶各自持有最多 ipCap 个 IP，会累积撑爆内存
	b.ips = nil
	b.sealed = true
	a.hist = append(a.hist, b)
	cut := time.Now().Add(-keepHours * time.Hour).Unix()
	for len(a.hist) > 0 && a.hist[0].TS < cut {
		a.hist = a.hist[1:]
	}
}

// persistSealed 锁外落盘封存桶（不可变，序列化安全），避免磁盘 I/O 停顿请求路径
func (a *Analytics) persistSealed(b *hourBucket) {
	data, err := json.Marshal(b)
	if err != nil {
		log.Printf("分析桶序列化失败(ts=%d): %v", b.TS, err)
		return
	}
	if err := a.st.SaveAnalyticsHour(b.TS, string(data)); err != nil {
		log.Printf("分析桶落盘失败(ts=%d): %v", b.TS, err)
	}
	if err := a.st.PruneAnalytics(time.Now().Add(-keepHours * time.Hour).Unix()); err != nil {
		log.Printf("分析数据清理失败: %v", err)
	}
}

// Persist 周期落盘当前桶（重启最多丢一个 tick 间隔的数据）
func (a *Analytics) Persist() {
	a.mu.Lock()
	b := a.cur
	b.UV = b.uvBase + int64(len(b.ips))
	// 当前桶仍被并发写入，必须持锁序列化；仅写库移出锁外
	data, err := json.Marshal(b)
	a.mu.Unlock()
	if err != nil {
		log.Printf("分析桶序列化失败(ts=%d): %v", b.TS, err)
		return
	}
	if err := a.st.SaveAnalyticsHour(b.TS, string(data)); err != nil {
		log.Printf("分析桶落盘失败(ts=%d): %v", b.TS, err)
	}
}

func (a *Analytics) Record(rs ReqStat) {
	if a == nil {
		return
	}
	// UA 分类与地理查询在锁外完成（对齐 logAttack 模式），锁内只做计数，
	// 避免所有请求在单个互斥锁上串行化
	os, browser, tool := classifyUA(rs.UA)
	var g GeoCity
	if a.geo != nil {
		g = a.geo.CityInfo(rs.IP)
	}
	a.mu.Lock()
	nowSec := time.Now().Unix()
	slot := nowSec % int64(len(a.secs))
	if a.secs[slot].TS != nowSec {
		a.secs[slot] = SecPoint{TS: nowSec}
	}
	a.secs[slot].Req++
	if rs.Blocked {
		a.secs[slot].Blocked++
	}
	b, sealed := a.touch()
	b.Req++
	if rs.Blocked {
		b.Blocked++
	}
	switch {
	case rs.Status >= 400 && rs.Status < 500:
		b.C4xx++
	case rs.Status >= 500:
		b.C5xx++
	}
	if len(b.ips) < ipCap {
		b.ips[rs.IP] = struct{}{}
	}
	if v, ok := b.Status[rs.Status]; ok {
		b.Status[rs.Status] = v + 1
	} else if len(b.Status) < 64 {
		b.Status[rs.Status] = 1
	}
	incMap(b.OS, os)
	incMap(b.Browser, browser)
	incMap(b.Tool, tool)
	incMap(b.Referer, rs.Referer)
	incMap(b.Host, rs.Host)
	incMap(b.Path, rs.Path)
	if g.Country != "" {
		incMap(b.Country, g.Country)
		if rs.Blocked {
			incMap(b.CnBlock, g.Country)
		}
		if g.Country == "CN" && g.Region != "" {
			incMap(b.Prov, g.Region)
			if rs.Blocked {
				incMap(b.ProvBlock, g.Region)
			}
		}
	}
	a.mu.Unlock()
	if sealed != nil {
		a.persistSealed(sealed)
	}
}

func (a *Analytics) Event(ev EvStat) {
	if a == nil {
		return
	}
	a.mu.Lock()
	b, sealed := a.touch()
	mod := moduleOf(ev.Action)
	incMap(b.Module, mod)
	if ev.Status == http.StatusTooManyRequests {
		incMap(b.Module, "人机验证")
	}
	incMap(b.Category, categoryOf(ev.Action, ev.RuleID, ev.Msg))
	incMap(b.AttackIP, ev.IP)
	incMap(b.AtkPath, truncStr(ev.URL, pathMaxLen))
	incMap(b.AtkHost, ev.Domain)
	if m, ok := b.ModIP[mod]; ok {
		incMap(m, ev.IP)
	} else if len(b.ModIP) < mapCap {
		b.ModIP[mod] = map[string]int64{ev.IP: 1}
	}
	if ev.Lat != 0 || ev.Lon != 0 {
		label := ev.City
		if label == "" {
			label = countryName(ev.Country)
		}
		if label == "" {
			label = ev.IP
		}
		if s, ok := b.Arc[label]; ok {
			s.N++
		} else if len(b.Arc) < mapCap {
			b.Arc[label] = &arcSrc{Label: label, Country: ev.Country, Lat: ev.Lat, Lon: ev.Lon}
			b.Arc[label].N = 1
		}
	}
	a.mu.Unlock()
	if sealed != nil {
		a.persistSealed(sealed)
	}
}

func moduleOf(action string) string {
	switch action {
	case "waf", "semantic", "resp":
		return "攻击防护"
	case "blacklist":
		return "IP 黑名单"
	case "reputation":
		return "信誉封禁"
	case "cc":
		return "CC 限流"
	case "bot":
		return "Bot 防护"
	case "dynamic":
		return "动态防护"
	case "custom":
		return "自定义规则"
	case "geo":
		return "地域管控"
	}
	return action
}

func categoryOf(action string, ruleID int, msg string) string {
	switch action {
	case "bot":
		return "Bot 爬虫"
	case "cc":
		return "CC 攻击"
	case "blacklist", "reputation", "geo":
		return "访问控制"
	case "dynamic":
		return "动态防护"
	case "custom":
		return "自定义规则"
	case "resp":
		return "信息泄露"
	}
	switch {
	case ruleID == 100200 || (ruleID >= 942000 && ruleID < 943000):
		return "SQL 注入"
	case ruleID == 100201 || (ruleID >= 941000 && ruleID < 942000):
		return "XSS"
	case ruleID == 100203 || (ruleID >= 932000 && ruleID < 933000):
		return "命令注入"
	case ruleID == 100202 || (ruleID >= 930000 && ruleID < 931000):
		return "目录穿越"
	case ruleID >= 933000 && ruleID < 935000:
		return "代码注入"
	case ruleID >= 951000 && ruleID < 953000:
		return "信息泄露"
	case ruleID >= 920000 && ruleID < 921000:
		return "协议异常"
	}
	if strings.Contains(msg, "SQL") {
		return "SQL 注入"
	}
	if strings.Contains(msg, "XSS") {
		return "XSS"
	}
	return "其他"
}

// classifyUA 从 User-Agent 提取操作系统 / 浏览器 / 自动化工具签名（复用 Bot 特征库）
func classifyUA(ua string) (os, browser, tool string) {
	low := strings.ToLower(ua)
	switch {
	case strings.Contains(low, "windows"):
		os = "Windows"
	case strings.Contains(low, "android"):
		os = "Android"
	case strings.Contains(low, "iphone"), strings.Contains(low, "ipad"):
		os = "iOS"
	case strings.Contains(low, "macintosh"):
		os = "macOS"
	case strings.Contains(low, "linux"):
		os = "Linux"
	default:
		os = "其他"
	}
	switch {
	case strings.Contains(low, "edg/"):
		browser = "Edge"
	case strings.Contains(low, "opr/"):
		browser = "Opera"
	case strings.Contains(low, "firefox"):
		browser = "Firefox"
	case strings.Contains(low, "chrome"):
		browser = "Chrome"
	case strings.Contains(low, "safari"):
		browser = "Safari"
	default:
		browser = "其他"
	}
	if kind, sig := classifyBotUA(ua); kind != "" {
		tool = sig
	}
	return
}

func refererHost(referer, selfHost string) string {
	if referer == "" || len(referer) > referMaxLen*4 {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil || u.Host == "" {
		return ""
	}
	h := strings.ToLower(stripPort(u.Host))
	if h == selfHost || h == "" {
		return ""
	}
	return h
}

type KV struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type GeoKV struct {
	Key     string  `json:"key"`
	Name    string  `json:"name"`
	Count   int64   `json:"count"`
	Blocked int64   `json:"blocked"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

type AnaHourPoint struct {
	TS         int64            `json:"ts"`
	Req        int64            `json:"req"`
	Blocked    int64            `json:"blocked"`
	UV         int64            `json:"uv"`
	C4xx       int64            `json:"c4xx"`
	C5xx       int64            `json:"c5xx"`
	Modules    map[string]int64 `json:"modules"`
	Categories map[string]int64 `json:"categories"`
}

type AnaTotals struct {
	Req       int64   `json:"req"`
	Blocked   int64   `json:"blocked"`
	UV        int64   `json:"uv"`
	C4xx      int64   `json:"c4xx"`
	C5xx      int64   `json:"c5xx"`
	BlockRate float64 `json:"block_rate"`
	Rate4xx   float64 `json:"rate_4xx"`
	Rate5xx   float64 `json:"rate_5xx"`
}

type AnaSnapshot struct {
	Hours       []AnaHourPoint  `json:"hours"`
	Totals      AnaTotals       `json:"totals"`
	Status      []KV            `json:"status"`
	OS          []KV            `json:"os"`
	Browser     []KV            `json:"browser"`
	Tool        []KV            `json:"tool"`
	Referer     []KV            `json:"referer"`
	Host        []KV            `json:"host"`
	Path        []KV            `json:"path"`
	Countries   []GeoKV         `json:"countries"`
	Provinces   []GeoKV         `json:"provinces"`
	Modules     []KV            `json:"modules"`
	Categories  []KV            `json:"categories"`
	AttackIPs   []KV            `json:"attack_ips"`
	AttackPaths []KV            `json:"attack_paths"`
	AttackHosts []KV            `json:"attack_hosts"`
	ModuleIPs   map[string][]KV `json:"module_ips"`
	Arcs        []GeoKV         `json:"arcs"`
	ArcSrcs     int             `json:"arc_srcs"` // 攻击源地域总数（arcs 按 arcTopN 截断前的去重数）
}

func topKV(m map[string]int64, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func mergeAdd(dst map[string]int64, src map[string]int64) {
	for k, v := range src {
		dst[k] += v
	}
}

func copyMap(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// Snapshot 聚合最近 hours 小时的小时桶（含当前未封存桶）
func (a *Analytics) Snapshot(hours int) *AnaSnapshot {
	if a == nil {
		return &AnaSnapshot{}
	}
	if hours < 1 {
		hours = 1
	}
	if hours > keepHours {
		hours = keepHours
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.cur
	b.UV = b.uvBase + int64(len(b.ips))
	cut := hourOf(time.Now()) - int64(hours-1)*3600

	s := &AnaSnapshot{ModuleIPs: map[string][]KV{}}
	status := map[int]int64{}
	osM, brM, toolM := map[string]int64{}, map[string]int64{}, map[string]int64{}
	refM, hostM, pathM := map[string]int64{}, map[string]int64{}, map[string]int64{}
	cnM, cnB, provM, provB := map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}
	modM, catM, atkM := map[string]int64{}, map[string]int64{}, map[string]int64{}
	atkPathM, atkHostM := map[string]int64{}, map[string]int64{}
	modIP := map[string]map[string]int64{}
	arcs := map[string]*arcSrc{}

	all := append(append([]*hourBucket{}, a.hist...), a.cur)
	for _, bk := range all {
		if bk.TS < cut {
			continue
		}
		uv := bk.UV
		if !bk.sealed {
			uv = bk.uvBase + int64(len(bk.ips))
		}
		// 当前桶的 map 仍会被并发写入，快照必须深拷贝
		s.Hours = append(s.Hours, AnaHourPoint{TS: bk.TS, Req: bk.Req, Blocked: bk.Blocked, UV: uv, C4xx: bk.C4xx, C5xx: bk.C5xx, Modules: copyMap(bk.Module), Categories: copyMap(bk.Category)})
		s.Totals.Req += bk.Req
		s.Totals.Blocked += bk.Blocked
		s.Totals.UV += uv
		s.Totals.C4xx += bk.C4xx
		s.Totals.C5xx += bk.C5xx
		for k, v := range bk.Status {
			status[k] += v
		}
		mergeAdd(osM, bk.OS)
		mergeAdd(brM, bk.Browser)
		mergeAdd(toolM, bk.Tool)
		mergeAdd(refM, bk.Referer)
		mergeAdd(hostM, bk.Host)
		mergeAdd(pathM, bk.Path)
		mergeAdd(cnM, bk.Country)
		mergeAdd(cnB, bk.CnBlock)
		mergeAdd(provM, bk.Prov)
		mergeAdd(provB, bk.ProvBlock)
		mergeAdd(modM, bk.Module)
		mergeAdd(catM, bk.Category)
		mergeAdd(atkM, bk.AttackIP)
		mergeAdd(atkPathM, bk.AtkPath)
		mergeAdd(atkHostM, bk.AtkHost)
		for mod, ips := range bk.ModIP {
			if _, ok := modIP[mod]; !ok {
				modIP[mod] = map[string]int64{}
			}
			mergeAdd(modIP[mod], ips)
		}
		for k, v := range bk.Arc {
			if cur, ok := arcs[k]; ok {
				cur.N += v.N
			} else {
				cp := *v
				arcs[k] = &cp
			}
		}
	}
	sort.Slice(s.Hours, func(i, j int) bool { return s.Hours[i].TS < s.Hours[j].TS })
	if s.Totals.Req > 0 {
		s.Totals.BlockRate = round2(float64(s.Totals.Blocked) * 100 / float64(s.Totals.Req))
		s.Totals.Rate4xx = round2(float64(s.Totals.C4xx) * 100 / float64(s.Totals.Req))
		s.Totals.Rate5xx = round2(float64(s.Totals.C5xx) * 100 / float64(s.Totals.Req))
	}
	stKv := make([]KV, 0, len(status))
	for k, v := range status {
		stKv = append(stKv, KV{Key: itoa(k), Count: v})
	}
	sort.Slice(stKv, func(i, j int) bool { return stKv[i].Count > stKv[j].Count })
	s.Status = stKv
	s.OS = topKV(osM, 8)
	s.Browser = topKV(brM, 8)
	s.Tool = topKV(toolM, 10)
	s.Referer = topKV(refM, topN)
	s.Host = topKV(hostM, topN)
	s.Path = topKV(pathM, topN)
	for code, name := range countryNames {
		if c, ok := cnM[code]; ok {
			cent := countryCentroid[code]
			s.Countries = append(s.Countries, GeoKV{Key: code, Name: name, Count: c, Blocked: cnB[code], Lat: cent[0], Lon: cent[1]})
		}
	}
	sort.Slice(s.Countries, func(i, j int) bool { return s.Countries[i].Count > s.Countries[j].Count })
	for name, cnt := range provM {
		s.Provinces = append(s.Provinces, GeoKV{Key: name, Name: name, Count: cnt, Blocked: provB[name]})
	}
	sort.Slice(s.Provinces, func(i, j int) bool { return s.Provinces[i].Count > s.Provinces[j].Count })
	if len(s.Provinces) > topN {
		s.Provinces = s.Provinces[:topN]
	}
	s.Modules = topKV(modM, 12)
	s.Categories = topKV(catM, 10)
	s.AttackIPs = topKV(atkM, topN)
	s.AttackPaths = topKV(atkPathM, topN)
	s.AttackHosts = topKV(atkHostM, topN)
	for mod, ips := range modIP {
		s.ModuleIPs[mod] = topKV(ips, 5)
	}
	arcList := make([]*arcSrc, 0, len(arcs))
	for _, v := range arcs {
		arcList = append(arcList, v)
	}
	sort.Slice(arcList, func(i, j int) bool { return arcList[i].N > arcList[j].N })
	s.ArcSrcs = len(arcList)
	if len(arcList) > arcTopN {
		arcList = arcList[:arcTopN]
	}
	for _, v := range arcList {
		s.Arcs = append(s.Arcs, GeoKV{Key: v.Label, Name: v.Label, Count: v.N, Lat: v.Lat, Lon: v.Lon})
	}
	return s
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// SecPoint 单秒请求计数
type SecPoint struct {
	TS      int64 `json:"ts"`
	Req     int64 `json:"req"`
	Blocked int64 `json:"blocked"`
}

// QPSSnapshot 实时速率快照：最近完整秒的原始值 + 5s 滚动均值 + 60s 峰值
type QPSSnapshot struct {
	TS         int64      `json:"ts"`
	QPS        float64    `json:"qps"`
	BlockedQPS float64    `json:"blocked_qps"`
	Peak       int64      `json:"peak"`
	Req        int64      `json:"req"`
	Blocked    int64      `json:"blocked"`
	Series     []SecPoint `json:"series,omitempty"`
}

// QPS 返回实时速率；withSeries 时附带近 60 个完整秒的序列（升序），供前端曲线播种
func (a *Analytics) QPS(withSeries bool) *QPSSnapshot {
	if a == nil {
		return &QPSSnapshot{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.qpsAt(time.Now().Unix(), withSeries)
}

func (a *Analytics) qpsAt(now int64, withSeries bool) *QPSSnapshot {
	last := now - 1
	s := &QPSSnapshot{TS: last}
	n := int64(len(a.secs))
	var sum5, sumB5 int64
	for i := int64(0); i < 60; i++ {
		ts := last - i
		slot := ts % n
		if slot < 0 {
			slot += n
		}
		var req, blk int64
		if a.secs[slot].TS == ts {
			req, blk = a.secs[slot].Req, a.secs[slot].Blocked
		}
		if i == 0 {
			s.Req, s.Blocked = req, blk
		}
		if i < 5 {
			sum5 += req
			sumB5 += blk
		}
		if req > s.Peak {
			s.Peak = req
		}
		if withSeries {
			s.Series = append(s.Series, SecPoint{TS: ts, Req: req, Blocked: blk})
		}
	}
	if withSeries {
		for i, j := 0, len(s.Series)-1; i < j; i, j = i+1, j-1 {
			s.Series[i], s.Series[j] = s.Series[j], s.Series[i]
		}
	}
	s.QPS = round2(float64(sum5) / 5)
	s.BlockedQPS = round2(float64(sumB5) / 5)
	return s
}

// qpsLoop 每秒向 SSE 订阅者推送速率帧（帧体小、复用既有长连接，不加轮询压力）
func (p *Proxy) qpsLoop() {
	for range time.Tick(time.Second) {
		s := p.Ana.QPS(false)
		p.Hub.Broadcast(map[string]any{
			"type": "qps", "ts": s.TS, "qps": s.QPS, "blocked_qps": s.BlockedQPS,
			"peak": s.Peak, "req": s.Req, "blocked": s.Blocked,
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
