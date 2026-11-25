// Package metrics 以 Prometheus 文本暴露格式（0.0.4）手写实现指标采集，零第三方依赖。
// 仅覆盖 WAF 核心可观测维度：请求量/时延、攻击计数、上游健康、信誉封禁、响应字节与运行时。
package metrics

import (
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default 全局注册表，供代理各埋点直接调用。
var Default = New()

var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type sample struct {
	labels string // 预渲染的 {k="v",...}，空串表示无标签
	v      uint64
}

type counterVec struct {
	help   string
	names  []string
	mu     sync.Mutex
	series map[string]*sample
}

func (c *counterVec) inc(vals ...string) {
	k := strings.Join(vals, "\x00")
	c.mu.Lock()
	s := c.series[k]
	if s == nil {
		s = &sample{labels: encodeLabels(c.names, vals)}
		c.series[k] = s
	}
	c.mu.Unlock()
	atomic.AddUint64(&s.v, 1)
}

func (c *counterVec) render(b *strings.Builder, name string) {
	c.mu.Lock()
	keys := make([]string, 0, len(c.series))
	for k := range c.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", name, c.help, name)
	for _, k := range keys {
		s := c.series[k]
		fmt.Fprintf(b, "%s%s %d\n", name, s.labels, atomic.LoadUint64(&s.v))
	}
	c.mu.Unlock()
}

type gaugeVec struct {
	help   string
	names  []string
	mu     sync.Mutex
	series map[string]*int64
	labels map[string]string
}

func (g *gaugeVec) set(vals []string, v int64) {
	k := strings.Join(vals, "\x00")
	g.mu.Lock()
	p := g.series[k]
	if p == nil {
		p = new(int64)
		g.series[k] = p
		g.labels[k] = encodeLabels(g.names, vals)
	}
	g.mu.Unlock()
	atomic.StoreInt64(p, v)
}

// replace 以全量样本替换整个 gauge 族，清除已消失的站点/上游旧序列。
func (g *gaugeVec) replace(items []GaugeItem) {
	ns := map[string]*int64{}
	nl := map[string]string{}
	for _, it := range items {
		k := strings.Join(it.Vals, "\x00")
		p := new(int64)
		atomic.StoreInt64(p, it.V)
		ns[k] = p
		nl[k] = encodeLabels(g.names, it.Vals)
	}
	g.mu.Lock()
	g.series, g.labels = ns, nl
	g.mu.Unlock()
}

func (g *gaugeVec) render(b *strings.Builder, name string) {
	g.mu.Lock()
	keys := make([]string, 0, len(g.series))
	for k := range g.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n", name, g.help, name)
	for _, k := range keys {
		fmt.Fprintf(b, "%s%s %d\n", name, g.labels[k], atomic.LoadInt64(g.series[k]))
	}
	g.mu.Unlock()
}

type histogram struct {
	help    string
	buckets []float64
	counts  []uint64 // 累积桶计数（含 +Inf 前的各 le）
	sumBits uint64
	count   uint64
}

func (h *histogram) observe(v float64) {
	for i, ub := range h.buckets {
		if v <= ub {
			atomic.AddUint64(&h.counts[i], 1)
		}
	}
	atomic.AddUint64(&h.count, 1)
	for {
		old := atomic.LoadUint64(&h.sumBits)
		nw := math.Float64bits(math.Float64frombits(old) + v)
		if atomic.CompareAndSwapUint64(&h.sumBits, old, nw) {
			break
		}
	}
}

func (h *histogram) render(b *strings.Builder, name string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", name, h.help, name)
	for i, ub := range h.buckets {
		fmt.Fprintf(b, "%s_bucket{le=\"%g\"} %d\n", name, ub, atomic.LoadUint64(&h.counts[i]))
	}
	cnt := atomic.LoadUint64(&h.count)
	fmt.Fprintf(b, "%s_bucket{le=\"+Inf\"} %d\n", name, cnt)
	fmt.Fprintf(b, "%s_sum %g\n", name, math.Float64frombits(atomic.LoadUint64(&h.sumBits)))
	fmt.Fprintf(b, "%s_count %d\n", name, cnt)
}

// GaugeItem 一条带标签的 gauge 样本。
type GaugeItem struct {
	Vals []string
	V    int64
}

// UpstreamSample 上游健康样本。
type UpstreamSample struct {
	Site string
	URL  string
	Up   bool
}

// Registry 指标注册表。
type Registry struct {
	requests         counterVec
	attacks          counterVec
	rateLimited      counterVec
	overloadRejected counterVec
	upstreamWait     histogram
	upstreamWaiting  atomic.Int64
	upstreamTimeouts atomic.Uint64
	respBytes        uint64
	duration         histogram
	upstreams        gaugeVec
	repBanned        int64
	start            time.Time
}

// New 创建空注册表。
func New() *Registry {
	return &Registry{
		requests:         counterVec{help: "按站点与结果统计的代理请求总数", names: []string{"site", "result"}, series: map[string]*sample{}},
		attacks:          counterVec{help: "按处置动作统计的攻击命中总数", names: []string{"action"}, series: map[string]*sample{}},
		rateLimited:      counterVec{help: "按策略范围统计的限流请求总数", names: []string{"scope"}, series: map[string]*sample{}},
		overloadRejected: counterVec{help: "按原因统计的上游过载拒绝总数", names: []string{"reason"}, series: map[string]*sample{}},
		duration:         histogram{help: "代理请求处理时延（秒）", buckets: durationBuckets, counts: make([]uint64, len(durationBuckets))},
		upstreamWait:     histogram{help: "进入上游请求名额队列后的等待时长（秒）", buckets: durationBuckets, counts: make([]uint64, len(durationBuckets))},
		upstreams:        gaugeVec{help: "上游健康状态（1=健康 0=故障）", names: []string{"site", "url"}, series: map[string]*int64{}, labels: map[string]string{}},
		start:            time.Now(),
	}
}

// IncRequest 记录一次代理请求，result 为 allowed/blocked。
func (r *Registry) IncRequest(site, result string) { r.requests.inc(site, result) }

// IncAttack 记录一次攻击命中。
func (r *Registry) IncAttack(action string) { r.attacks.inc(action) }

func (r *Registry) IncRateLimited(scope string) { r.rateLimited.inc(scope) }

func (r *Registry) IncOverloadRejected(reason string) { r.overloadRejected.inc(reason) }

func (r *Registry) IncUpstreamTimeout() { r.upstreamTimeouts.Add(1) }

func (r *Registry) StartUpstreamWait() { r.upstreamWaiting.Add(1) }

func (r *Registry) FinishUpstreamWait(elapsed time.Duration) {
	r.upstreamWaiting.Add(-1)
	r.upstreamWait.observe(elapsed.Seconds())
}

// ObserveDuration 记录请求时延（秒）。
func (r *Registry) ObserveDuration(sec float64) { r.duration.observe(sec) }

// AddResponseBytes 累加转发响应字节数。
func (r *Registry) AddResponseBytes(n int64) {
	if n > 0 {
		atomic.AddUint64(&r.respBytes, uint64(n))
	}
}

// SetRepBanned 设置当前生效的信誉自动封禁 IP 数。
func (r *Registry) SetRepBanned(n int) { atomic.StoreInt64(&r.repBanned, int64(n)) }

// SetUpstreams 以全量健康样本替换上游 gauge 族。
func (r *Registry) SetUpstreams(items []UpstreamSample) {
	gi := make([]GaugeItem, 0, len(items))
	for _, it := range items {
		v := int64(0)
		if it.Up {
			v = 1
		}
		gi = append(gi, GaugeItem{Vals: []string{it.Site, it.URL}, V: v})
	}
	r.upstreams.replace(gi)
}

// Render 输出 Prometheus 文本暴露格式。
func (r *Registry) Render() string {
	var b strings.Builder
	r.requests.render(&b, "niubwaf_requests_total")
	r.attacks.render(&b, "niubwaf_attacks_total")
	r.rateLimited.render(&b, "niubwaf_rate_limited_total")
	r.overloadRejected.render(&b, "niubwaf_overload_rejections_total")
	r.upstreamWait.render(&b, "niubwaf_upstream_queue_duration_seconds")
	fmt.Fprintf(&b, "# HELP niubwaf_upstream_queue_requests 正在等待上游请求名额的请求数\n# TYPE niubwaf_upstream_queue_requests gauge\nniubwaf_upstream_queue_requests %d\n", r.upstreamWaiting.Load())
	fmt.Fprintf(&b, "# HELP niubwaf_upstream_timeouts_total 上游转发尝试超时总数\n# TYPE niubwaf_upstream_timeouts_total counter\nniubwaf_upstream_timeouts_total %d\n", r.upstreamTimeouts.Load())
	fmt.Fprintf(&b, "# HELP niubwaf_response_bytes_total 转发响应字节累计\n# TYPE niubwaf_response_bytes_total counter\nniubwaf_response_bytes_total %d\n", atomic.LoadUint64(&r.respBytes))
	r.duration.render(&b, "niubwaf_request_duration_seconds")
	r.upstreams.render(&b, "niubwaf_upstream_up")
	fmt.Fprintf(&b, "# HELP niubwaf_reputation_banned 当前信誉自动封禁 IP 数\n# TYPE niubwaf_reputation_banned gauge\nniubwaf_reputation_banned %d\n", atomic.LoadInt64(&r.repBanned))
	fmt.Fprintf(&b, "# HELP niubwaf_build_info 构建信息\n# TYPE niubwaf_build_info gauge\nniubwaf_build_info{version=\"1.0\",goversion=%q} 1\n", runtime.Version())
	fmt.Fprintf(&b, "# HELP process_start_time_seconds 进程启动 Unix 时间\n# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds %d\n", r.start.Unix())
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(&b, "# HELP go_goroutines 当前 goroutine 数\n# TYPE go_goroutines gauge\ngo_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&b, "# HELP go_memstats_alloc_bytes 当前堆分配字节\n# TYPE go_memstats_alloc_bytes gauge\ngo_memstats_alloc_bytes %d\n", ms.Alloc)
	fmt.Fprintf(&b, "# HELP go_memstats_sys_bytes 向 OS 申请的内存字节\n# TYPE go_memstats_sys_bytes gauge\ngo_memstats_sys_bytes %d\n", ms.Sys)
	return b.String()
}

// Handler 返回暴露 /metrics 的 HTTP 处理器（鉴权由上层负责）。
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.Render()))
	})
}

// encodeLabels 渲染标签集，按标签名字典序排列（Prometheus 惯例），并转义反斜杠/换行/双引号。
func encodeLabels(names, vals []string) string {
	if len(names) == 0 {
		return ""
	}
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(names))
	for i, n := range names {
		v := ""
		if i < len(vals) {
			v = vals[i]
		}
		v = strings.ReplaceAll(v, "\\", "\\\\")
		v = strings.ReplaceAll(v, "\n", "\\n")
		v = strings.ReplaceAll(v, "\"", "\\\"")
		pairs = append(pairs, kv{n, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.k+"=\""+p.v+"\"")
	}
	return "{" + strings.Join(parts, ",") + "}"
}
