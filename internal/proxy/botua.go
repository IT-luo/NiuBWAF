package proxy

import "strings"

// botRuleID 反爬/Bot 防护日志规则号，避开 CRS(9xxxxx)/语义(1002xx)/动态(100300)/自定义(2000xx+) 号段
const botRuleID = 100400

// 内置爬虫 UA 特征库：对 User-Agent 做大小写不敏感的子串匹配（线性、无正则、无 ReDoS）。
// 分两类：
//   - goodBotUA：搜索引擎与链接预览/可用性等善意爬虫，默认放行（仅站点开启"严格模式"时才处置），
//     避免误伤 SEO 收录。开启来源验证时，Googlebot 和 Bingbot 还需匹配官方网段。
//   - badBotUA：脚本库、采集框架、下载器、漏洞扫描/攻击工具、SEO 外链爬虫等，命中即按站点动作处置。
// 匹配顺序：先判善意（命中即归类 good 并返回），再判恶意，最后空 UA 视为可疑自动化。
// 因此"baiduspider"含"spider"也不会被恶意类误伤——恶意类不含裸 spider/crawl/bot 等宽泛词。

// goodBotUA 善意爬虫（搜索引擎 / 链接预览 / 可用性监控），全部小写
var goodBotUA = []string{
	// 搜索引擎
	"googlebot", "google-inspectionagent", "google-extended", "googleother", "google-read-aloud",
	"bingbot", "bingpreview", "adidxbot", "msnbot",
	"slurp", "yahoo",
	"duckduckbot", "duckduckgo-favicons",
	"baiduspider", "baidu-yunguance",
	"sogou web spider", "sogou-news-spider", "sogou inst spider", "sogou test spider",
	"360spider", "haosouspider", "so.com spider",
	"yandexbot", "yandeximages", "yandex",
	"applebot", "petalbot",
	// 链接预览 / IM 抓取
	"facebookexternalhit", "facebookcatalog", "twitterbot", "linkedinbot",
	"whatsapp", "telegrambot", "slackbot", "discordbot", "skypeuripreview",
	"embedly", "ifttt", "feedfetcher", "tiny tiny rss", "flipboard", "pinterest",
	// 可用性 / 健康监控
	"pingdom", "uptimerobot", "statuscake", "jetmon", "site24x7", "uptime-kuma", "better uptime",
}

// badBotUA 恶意/自动化客户端特征，全部小写；命中返回具体特征串用于日志定位
var badBotUA = []string{
	// 脚本语言 HTTP 库 / 默认 UA
	"python-requests", "python-urllib", "python/", "pycurl", "python", "aiohttp", "httpx",
	"go-http-client", "java/", "java-http", "jakarta commons-httpclient", "apache-httpclient",
	"okhttp", "libwww-perl", "lwp::", "lwp-trivial", "www-mechanize", "perl", "ruby",
	"php/", "node-fetch", "axios", "superagent", "undici", "restsharp", "winhttp",
	"indy library", "pecl/http", "guzzle", "twisted web client", "cfnnetwork", "scrapy",
	// 通用下载 / 命令行客户端
	"curl/", "libcurl", "wget/", "wget2", "aria2", "flashget", "thunder", "xunlei",
	"freedownloadmanager", "download master", "httpcat",
	// 采集 / 抓取框架
	"80legs", "grab-site", "dataproxy", "colly", "node-crawler", "crawler", "scraper", "scraping",
	// 无头浏览器 / 自动化
	"headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
	// 漏洞扫描 / 攻击 / 目录爆破工具
	"sqlmap", "sqlninja", "nikto", "nmap", "masscan", "zmap", "zgrab", "fscan",
	"gobuster", "dirbuster", "dirsearch", "dirb/", "wfuzz", "ffuf", "hydra", "nuclei",
	"acunetix", "nessus", "openvas", "wpscan", "joomscan", "subfinder", "amass",
	"whatweb", "w3af", "arachni", "skipfish", "burp", "appscan", "webscarab",
	"hawkeye", "censys", "shodan", "metasploit", "commix", "xsstrike", "dalfox",
	"katana", "arjun", "goby", "xray", "afrog", "webshag", "xspider", "lbd/",
	// SEO 外链 / 权重爬虫（大量抓取、多数站点主动屏蔽）
	"ahrefsbot", "semrushbot", "semrush", "mj12bot", "dotbot", "blexbot",
	"dataforseo", "serpstatbot", "megaindex", "seokicks", "rogerbot",
	"screaming frog", "xenu", "sitebulb",
}

// classifyBotUA 归类 User-Agent：
//   - kind="" 普通客户端（真实浏览器等），不处置
//   - kind="good" 已知善意爬虫，仅严格模式处置；sig 为命中特征
//   - kind="bad" 恶意/自动化客户端，按站点动作处置；sig 为命中特征
//
// 空 UA 归为 bad（大量简易爬虫不带 UA）。匹配为大小写不敏感子串，线性无回溯。
func classifyBotUA(ua string) (kind, sig string) {
	if strings.TrimSpace(ua) == "" {
		return "bad", "空 User-Agent"
	}
	low := strings.ToLower(ua)
	for _, s := range goodBotUA {
		if strings.Contains(low, s) {
			return "good", s
		}
	}
	for _, s := range badBotUA {
		if strings.Contains(low, s) {
			return "bad", s
		}
	}
	return "", ""
}
