package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"niubwaf/internal/engine"
	"niubwaf/internal/store"
)

func TestClassifyBotUA(t *testing.T) {
	// 真实浏览器 / App：不得命中任何 Bot 特征
	normal := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Dart/3.2 (dart:io)", // 说明：不在库内 → 普通
	}
	for _, ua := range normal {
		if kind, sig := classifyBotUA(ua); kind != "" {
			t.Errorf("正常客户端被误判为 %q(%q): %s", kind, sig, ua)
		}
	}

	// 善意爬虫：归类 good（默认放行，仅严格模式处置）
	good := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
		"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
	}
	for _, ua := range good {
		if kind, sig := classifyBotUA(ua); kind != "good" || sig == "" {
			t.Errorf("善意爬虫应归类 good，got kind=%q sig=%q: %s", kind, sig, ua)
		}
	}

	// 恶意/自动化客户端：归类 bad
	bad := []string{
		"python-requests/2.31.0",
		"Python-urllib/3.9",
		"curl/8.4.0",
		"Wget/1.21",
		"Go-http-client/1.1",
		"Java/1.8.0_362",
		"okhttp/4.12.0",
		"Scrapy/2.11.0 (+https://scrapy.org)",
		"sqlmap/1.7.12#stable (https://sqlmap.org)",
		"Nikto/2.5.0",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine)",
		"gobuster/3.6",
		"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
		"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
		"Mozilla/5.0 AppleWebKit/537.36 HeadlessChrome/120.0.0.0 Safari/537.36",
		"axios/1.6.2",
		"", // 空 UA
		"   ",
	}
	for _, ua := range bad {
		if kind, sig := classifyBotUA(ua); kind != "bad" || sig == "" {
			t.Errorf("恶意/自动化客户端应归类 bad，got kind=%q sig=%q: %q", kind, sig, ua)
		}
	}

	// 关键防误伤：Baiduspider 含 "spider" 但必须归 good（恶意类不含裸 spider）
	if kind, _ := classifyBotUA("Baiduspider"); kind != "good" {
		t.Fatalf("Baiduspider 应归 good，got %q", kind)
	}
}

// newBotTestProxy 构建带真实引擎的代理并从存储载入站点，覆盖 Reload 对新列的读取
func newBotTestProxy(t *testing.T, st *store.Store, upstream string) *Proxy {
	t.Helper()
	eng, err := engine.New()
	if err != nil {
		t.Fatalf("构建引擎失败: %v", err)
	}
	p := &Proxy{
		Store: st, Engine: eng, Geo: &GeoIP{},
		Limiter: NewLimiter(), Cap: NewCaptcha("unit-test-secret"), Hub: NewHub(),
		sites: map[string]*cachedSite{},
	}
	p.Reload()
	_ = upstream
	return p
}

func doReq(p *Proxy, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://bot.test/", nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

func TestBotServeHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("origin-ok"))
	}))
	defer upstream.Close()

	const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	const pyreq = "python-requests/2.31.0"
	const googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

	newSite := func(t *testing.T, botMode string, strict bool) *Proxy {
		st, err := store.Open(filepath.Join(t.TempDir(), "bot.db"))
		if err != nil {
			t.Fatalf("打开测试库失败: %v", err)
		}
		t.Cleanup(func() { st.Close() })
		s := &store.Site{Name: "bot", Domain: "bot.test", Upstream: upstream.URL, Enabled: true, WAFMode: "balanced", BotMode: botMode, BotStrict: strict}
		if err := st.CreateSite(s); err != nil {
			t.Fatalf("创建站点失败: %v", err)
		}
		// 验证新列已持久化
		got, err := st.GetSite(s.ID)
		if err != nil {
			t.Fatalf("读取站点失败: %v", err)
		}
		if got.BotMode != botMode || got.BotStrict != strict {
			t.Fatalf("bot 字段未正确持久化: mode=%q strict=%v", got.BotMode, got.BotStrict)
		}
		return newBotTestProxy(t, st, upstream.URL)
	}

	// 关闭：任何 UA 都放行
	p := newSite(t, "off", false)
	if rec := doReq(p, pyreq); rec.Code != http.StatusOK {
		t.Errorf("off 模式应放行脚本 UA, got %d", rec.Code)
	}

	// 拦截：脚本 UA → 403；浏览器 → 200；搜索引擎 → 200（非严格放行）
	p = newSite(t, "block", false)
	if rec := doReq(p, pyreq); rec.Code != http.StatusForbidden {
		t.Errorf("block 模式脚本 UA 应 403, got %d", rec.Code)
	}
	if rec := doReq(p, chrome); rec.Code != http.StatusOK {
		t.Errorf("block 模式浏览器应放行 200, got %d", rec.Code)
	}
	if rec := doReq(p, googlebot); rec.Code != http.StatusOK {
		t.Errorf("block 模式搜索引擎（非严格）应放行 200, got %d", rec.Code)
	}

	// 严格：搜索引擎也拦截
	p = newSite(t, "block", true)
	if rec := doReq(p, googlebot); rec.Code != http.StatusForbidden {
		t.Errorf("严格模式搜索引擎应 403, got %d", rec.Code)
	}

	// 人机验证：脚本 UA → 429 挑战页
	p = newSite(t, "captcha", false)
	if rec := doReq(p, pyreq); rec.Code != http.StatusTooManyRequests {
		t.Errorf("captcha 模式脚本 UA 应 429, got %d", rec.Code)
	}
	if rec := doReq(p, chrome); rec.Code != http.StatusOK {
		t.Errorf("captcha 模式浏览器应放行 200, got %d", rec.Code)
	}

	// 观察：脚本 UA 仍放行 200（仅记录）
	p = newSite(t, "log", false)
	if rec := doReq(p, pyreq); rec.Code != http.StatusOK {
		t.Errorf("log 模式脚本 UA 应放行 200, got %d", rec.Code)
	}
}
