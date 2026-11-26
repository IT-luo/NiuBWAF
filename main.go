package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"niubwaf/internal/api"
	"niubwaf/internal/engine"
	"niubwaf/internal/monitor"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
	"niubwaf/internal/web"

	"golang.org/x/net/netutil"
)

func main() {
	proxyAddr := flag.String("proxy", ":8080", "防护代理 HTTP 监听地址")
	tlsAddr := flag.String("tls", ":8443", "防护代理 HTTPS 监听地址")
	certFile := flag.String("cert", "", "代理默认证书文件（PEM），留空则自动生成自签名证书")
	keyFile := flag.String("key", "", "代理默认私钥文件（PEM）")
	adminAddr := flag.String("admin", "127.0.0.1:9443", "管理控制台监听地址")
	adminCert := flag.String("admin-cert", "", "管理控制台证书文件（PEM），留空自动生成自签名证书")
	adminKey := flag.String("admin-key", "", "管理控制台私钥文件（PEM）")
	dataDir := flag.String("data", "./data", "数据目录")
	upstreamConnections := flag.Int("upstream-connections", proxy.DefaultUpstreamConnections, "每个上游源站的连接上限")
	acmeHTTP := flag.String("acme-http", ":80", "ACME HTTP-01 挑战监听地址（仅 acme_enabled=on 时启动）")
	flag.Parse()
	if *upstreamConnections <= 0 {
		log.Fatal("-upstream-connections 必须为正整数")
	}

	fmt.Println("==============================================")
	fmt.Println("  牛B WAF - 新一代智能 Web 应用防火墙")
	fmt.Println("  基于 Coraza 引擎 + OWASP CRS 规则集")
	fmt.Println("==============================================")

	if err := preparePrivateDataDir(*dataDir); err != nil {
		log.Fatalf("无法保护数据目录: %v", err)
	}

	st, err := store.Open(filepath.Join(*dataDir, "niubwaf.db"))
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}

	log.Println("正在加载检测引擎与 OWASP CRS 规则集...")
	start := time.Now()
	eng, err := engine.New()
	if err != nil {
		log.Fatalf("引擎初始化失败: %v", err)
	}
	log.Printf("引擎就绪（OWASP CRS %s，平衡/严格双模式），耗时 %s", engine.CRSVersion, time.Since(start).Round(time.Millisecond))

	geo := proxy.NewGeoIP(*dataDir)
	if geo.Available() || geo.CityAvailable() {
		log.Printf("GeoIP 已加载（ip2region=%v 城市库=%v ASN库=%v）", geo.XDBAvailable(), geo.CityAvailable(), geo.ASNAvailable())
	} else {
		log.Println("GeoIP 数据库未找到（data/ip2region_v4.xdb 或 data/geoip.mmdb），地理位置功能暂不可用")
	}

	secret := st.GetSetting("cookie_secret")
	if secret == "" {
		secret = store.RandToken()
		st.SetSetting("cookie_secret", secret)
	}

	idc := proxy.NewIDCMatcher(*dataDir)
	tor := proxy.NewTorList(*dataDir)
	log.Printf("IP 情报源就绪（IDC CIDR %d 条 / Tor 出口 %d 个，后台自动刷新）", idc.Status()["count"], tor.Status()["count"])

	p := proxy.NewWithUpstreamLimit(st, eng, geo, idc, tor, secret, *upstreamConnections)
	if p.Cap.ConfigureTurnstile(os.Getenv("NIUBWAF_TURNSTILE_SITE_KEY"), os.Getenv("NIUBWAF_TURNSTILE_SECRET_KEY")) {
		log.Println("Turnstile 人机验证已配置")
	}
	p.HTTPSAddr = *tlsAddr
	p.InitACME(*dataDir)
	a := api.New(st, p)
	a.DataDir = *dataDir
	// 管理台默认强制 HTTPS：未显式提供证书时自动生成自签名管理证书
	adminCertPath, adminKeyPath := *adminCert, *adminKey
	if adminCertPath == "" || adminKeyPath == "" {
		cp, kp, err := ensureAdminCert(*dataDir)
		if err != nil {
			log.Fatalf("管理台自签名证书生成失败: %v", err)
		}
		adminCertPath, adminKeyPath = cp, kp
		log.Println("管理台使用自动生成的自签名证书（生产环境请通过 -admin-cert/-admin-key 配置正式证书）")
	}
	a.AdminTLS = true

	if *certFile != "" && *keyFile != "" {
		certPEM, err := os.ReadFile(*certFile)
		if err != nil {
			log.Fatalf("读取证书失败: %v", err)
		}
		keyPEM, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("读取私钥失败: %v", err)
		}
		if err := p.SetDefaultCert(certPEM, keyPEM); err != nil {
			log.Fatalf("默认证书无效: %v", err)
		}
		log.Printf("代理默认证书已加载: %s", *certFile)
	} else {
		if err := loadOrGenerateCert(p, *dataDir); err != nil {
			log.Fatalf("自签名证书生成失败: %v", err)
		}
		log.Println("代理使用自动生成的自签名证书（生产环境请通过 -cert/-key 或控制台配置正式证书）")
	}

	defaultCertPath := filepath.Join(*dataDir, "default_cert.pem")
	if *certFile != "" && *keyFile != "" {
		defaultCertPath = *certFile
	}
	inspector, err := monitor.New(monitor.Config{
		Store: st, DataDir: *dataDir, DefaultCertFile: defaultCertPath, AdminCertFile: adminCertPath,
		UpstreamSource: monitor.UpstreamSourceFunc(func(ctx context.Context) ([]monitor.UpstreamStatus, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			statuses := p.UpstreamHealth()
			out := make([]monitor.UpstreamStatus, 0, len(statuses))
			for _, status := range statuses {
				item := monitor.UpstreamStatus{SiteID: status.SiteID, Domain: status.Domain, Targets: make([]monitor.TargetStatus, 0, len(status.Targets))}
				for _, target := range status.Targets {
					item.Targets = append(item.Targets, monitor.TargetStatus{URL: target.URL, Up: target.Up})
				}
				out = append(out, item)
			}
			return out, nil
		}),
		GeoSource: monitor.GeoSourceFunc(func(ctx context.Context) ([]monitor.GeoData, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			statuses := geo.DataStatus()
			out := make([]monitor.GeoData, 0, len(statuses))
			for _, status := range statuses {
				out = append(out, monitor.GeoData{Kind: status.Kind, Path: status.Path, BuildTime: status.BuildTime, ModTime: status.ModTime})
			}
			return out, nil
		}),
		Notifier: p,
	})
	if err != nil {
		log.Fatalf("巡检模块初始化失败: %v", err)
	}
	a.Inspector = inspector

	go func() {
		for {
			days := 30
			if v := st.GetSetting("log_retention_days"); v != "" {
				fmt.Sscanf(v, "%d", &days)
			}
			if days > 0 {
				st.CleanupLogs(days)
			}
			time.Sleep(6 * time.Hour)
		}
	}()

	console := http.FileServer(http.FS(web.FS))

	go func() {
		for {
			if name, err := a.RunBackup(); err != nil {
				log.Printf("数据库自动备份失败: %v", err)
			} else {
				log.Printf("数据库自动备份完成: backups/%s", name)
			}
			time.Sleep(6 * time.Hour)
		}
	}()

	if p.ACMEEnabled() {
		go func() {
			log.Printf("ACME HTTP-01 挑战监听: %s（Let's Encrypt 需公网可达该地址；内网无法签发）", *acmeHTTP)
			srv := &http.Server{Addr: *acmeHTTP, Handler: p.ACMEHandler(p), ReadHeaderTimeout: 10 * time.Second}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("ACME HTTP-01 监听启动失败（不影响其他服务）: %v", err)
			}
		}()
	}

	adminServer := &http.Server{
		Addr:              *adminAddr,
		Handler:           a.Handler(console),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	proxyTLSServer := &http.Server{
		Addr:              *tlsAddr,
		Handler:           p,
		TLSConfig:         p.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	proxyServer := &http.Server{
		Addr:              *proxyAddr,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	// ReadTimeout 约束从接受到读完请求体的时间；不设置全局 WriteTimeout，避免截断 SSE/WebSocket 长响应。
	services := []httpService{
		{name: "管理控制台", server: adminServer, useTLS: true, certFile: adminCertPath, keyFile: adminKeyPath, maxConnections: 32},
		{name: "HTTPS 防护代理", server: proxyTLSServer, useTLS: true, maxConnections: 1024},
		{name: "HTTP 防护代理", server: proxyServer, maxConnections: 1024},
	}
	log.Printf("管理控制台: https://%s （首次登录需修改初始密码）", *adminAddr)
	log.Printf("防护代理 HTTPS 监听: %s（按站点 SNI 证书，可在控制台配置）", *tlsAddr)
	log.Printf("防护代理 HTTP 监听: %s", *proxyAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	inspector.Start(ctx)
	runErr := runHTTPServices(ctx, services)
	stop()
	inspector.Wait()
	st.Close()
	if runErr != nil {
		log.Fatalf("HTTP 服务异常终止: %v", runErr)
	}
}

type httpService struct {
	name           string
	server         *http.Server
	useTLS         bool
	certFile       string
	keyFile        string
	maxConnections int
}

type httpServiceResult struct {
	name string
	err  error
}

func (s httpService) serve() error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("%s监听 %s 失败: %w", s.name, s.server.Addr, err)
	}
	limitedListener := netutil.LimitListener(listener, s.maxConnections)
	defer limitedListener.Close()

	if s.useTLS {
		err = s.server.ServeTLS(limitedListener, s.certFile, s.keyFile)
	} else {
		err = s.server.Serve(limitedListener)
	}
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("%s服务失败: %w", s.name, err)
}

func runHTTPServices(ctx context.Context, services []httpService) error {
	if len(services) == 0 {
		return nil
	}

	results := make(chan httpServiceResult, len(services))
	for _, service := range services {
		go func() {
			results <- httpServiceResult{name: service.name, err: service.serve()}
		}()
	}

	remaining := len(services)
	var runErr error
	select {
	case <-ctx.Done():
	case result := <-results:
		remaining--
		if result.err != nil {
			runErr = result.err
		} else {
			runErr = fmt.Errorf("%s意外停止", result.name)
		}
	}

	// 并发关闭所有监听器，避免某个长连接阻塞其他服务的优雅关闭。
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownResults := make(chan error, len(services))
	for _, service := range services {
		go func() {
			if err := service.server.Shutdown(shutdownCtx); err != nil {
				log.Printf("%s优雅关闭失败，强制关闭: %v", service.name, err)
				if closeErr := service.server.Close(); closeErr != nil {
					shutdownResults <- fmt.Errorf("%s强制关闭失败: %w", service.name, closeErr)
					return
				}
			}
			shutdownResults <- nil
		}()
	}
	for range services {
		if err := <-shutdownResults; err != nil {
			runErr = errors.Join(runErr, err)
		}
	}

	// 等待所有 Listen/Serve 路径退出，避免遗漏启动或运行错误。
	for ; remaining > 0; remaining-- {
		if result := <-results; result.err != nil {
			runErr = errors.Join(runErr, result.err)
		}
	}
	return runErr
}

func generateSelfSigned(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "NiuBWAF", Organization: []string{"NiuBWAF"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "niubwaf.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
}

func loadOrGenerateCert(p *proxy.Proxy, dataDir string) error {
	certPath := filepath.Join(dataDir, "default_cert.pem")
	keyPath := filepath.Join(dataDir, "default_key.pem")
	if err := generateSelfSigned(certPath, keyPath); err != nil {
		return err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	return p.SetDefaultCert(certPEM, keyPEM)
}

func ensureAdminCert(dataDir string) (string, string, error) {
	certPath := filepath.Join(dataDir, "admin_cert.pem")
	keyPath := filepath.Join(dataDir, "admin_key.pem")
	if err := generateSelfSigned(certPath, keyPath); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}
