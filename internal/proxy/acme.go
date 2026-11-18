package proxy

import (
	"crypto/tls"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// stagingDirectory Let's Encrypt 测试 CA，签发的证书不受浏览器信任，用于联调避免触发生产速率限制。
const stagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// InitACME 设置证书缓存目录并首次构建 ACME 管理器。需在 New 之后由 main 调用。
func (p *Proxy) InitACME(dataDir string) {
	p.mu.Lock()
	p.acmeDataDir = dataDir
	p.mu.Unlock()
	p.refreshACME()
}

// refreshACME 依据设置构建/重建 autocert.Manager；配置未变化时跳过，避免丢失签发状态。
func (p *Proxy) refreshACME() {
	p.mu.RLock()
	dataDir := p.acmeDataDir
	p.mu.RUnlock()
	if dataDir == "" {
		return
	}
	enabled := p.Store.GetSetting("acme_enabled") == "on"
	domainsRaw := p.Store.GetSetting("acme_domains")
	email := p.Store.GetSetting("acme_email")
	staging := p.Store.GetSetting("acme_staging") == "on"
	var domains []string
	for _, d := range strings.Split(domainsRaw, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			domains = append(domains, d)
		}
	}
	sig := strings.Join([]string{domainsRaw, email, stagingDirectoryFlag(staging), boolFlag(enabled && len(domains) > 0)}, "|")
	p.mu.RLock()
	unchanged := p.acmeSig == sig
	p.mu.RUnlock()
	if unchanged {
		return
	}
	var mgr *autocert.Manager
	if enabled && len(domains) > 0 {
		dirURL := autocert.DefaultACMEDirectory
		if staging {
			dirURL = stagingDirectory
		}
		mgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(filepath.Join(dataDir, "acme")),
			Email:      email,
			Client:     &acme.Client{DirectoryURL: dirURL},
		}
		log.Printf("ACME 自动证书已启用：%s（staging=%v，缓存 %s/acme）", strings.Join(domains, ","), staging, dataDir)
	}
	p.mu.Lock()
	p.acme = mgr
	p.acmeSig = sig
	p.mu.Unlock()
}

func stagingDirectoryFlag(staging bool) string {
	if staging {
		return "staging"
	}
	return "prod"
}

func boolFlag(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ACMEEnabled 报告当前是否已构建 ACME 管理器，供 main 决定是否启动 HTTP-01 监听。
func (p *Proxy) ACMEEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.acme != nil
}

// ACMEHandler 包装 HTTP-01 挑战处理：启用时拦截 /.well-known/acme-challenge/，其余请求交给 fallback。
func (p *Proxy) ACMEHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.RLock()
		mgr := p.acme
		p.mu.RUnlock()
		if mgr != nil {
			mgr.HTTPHandler(fallback).ServeHTTP(w, r)
			return
		}
		if fallback != nil {
			fallback.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// acmeCertificate 在已配置站点证书之外尝试 ACME 签发；调用方须已释放 p.mu。
func acmeCertificate(mgr *autocert.Manager, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if mgr == nil {
		return nil, nil
	}
	return mgr.GetCertificate(hello)
}