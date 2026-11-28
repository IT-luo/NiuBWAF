package certmgr

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
)

func init() {
	// The manager sanitizes provider errors before surfacing them as job status.
	legolog.Logger = log.New(io.Discard, "", 0)
}

type credentials struct {
	Key    string
	Secret string
}

func dnsProvider(vendor string, secret credentials) (challenge.Provider, error) {
	const propagation = 2 * time.Minute
	const polling = 2 * time.Second
	const apiTimeout = 10 * time.Second
	switch vendor {
	case "alidns":
		config := alidns.NewDefaultConfig()
		config.APIKey, config.SecretKey = secret.Key, secret.Secret
		config.RAMRole = ""
		config.PropagationTimeout, config.PollingInterval, config.HTTPTimeout = propagation, polling, apiTimeout
		return alidns.NewDNSProviderConfig(config)
	case "cloudflare":
		config := cloudflare.NewDefaultConfig()
		config.AuthToken, config.ZoneToken = secret.Key, secret.Secret
		config.PropagationTimeout, config.PollingInterval = propagation, polling
		config.HTTPClient.Timeout = apiTimeout
		return cloudflare.NewDNSProviderConfig(config)
	case "tencentcloud":
		config := tencentcloud.NewDefaultConfig()
		config.SecretID, config.SecretKey = secret.Key, secret.Secret
		config.PropagationTimeout, config.PollingInterval, config.HTTPTimeout = propagation, polling, apiTimeout
		return tencentcloud.NewDNSProviderConfig(config)
	default:
		return nil, fmt.Errorf("不支持的 DNS 服务商")
	}
}

type acmeAccount struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (a *acmeAccount) GetEmail() string                        { return a.email }
func (a *acmeAccount) GetPrivateKey() crypto.PrivateKey        { return a.key }
func (a *acmeAccount) GetRegistration() *registration.Resource { return a.registration }

type requestTransport struct {
	ctx  context.Context
	base http.RoundTripper
}

type cancellableDNS struct {
	challenge.Provider
	ctx       context.Context
	attempted sync.Map
}

func (d *cancellableDNS) Present(domain, token, keyAuth string) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	d.attempted.Store([3]string{domain, token, keyAuth}, struct{}{})
	return d.Provider.Present(domain, token, keyAuth)
}

func (d *cancellableDNS) CleanUp(domain, token, keyAuth string) error {
	// A failed presentation may still have created a record.
	if _, ok := d.attempted.Load([3]string{domain, token, keyAuth}); ok {
		return d.Provider.CleanUp(domain, token, keyAuth)
	}
	return nil
}

func (d *cancellableDNS) Timeout() (time.Duration, time.Duration) {
	if provider, ok := d.Provider.(challenge.ProviderTimeout); ok {
		return provider.Timeout()
	}
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}

func (t requestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	stop := context.AfterFunc(t.ctx, func() { cancel(t.ctx.Err()) })
	finish := func() {
		stop()
		cancel(nil)
	}
	response, err := t.base.RoundTrip(r.WithContext(ctx))
	if err != nil || response.Body == nil {
		finish()
		return response, err
	}
	response.Body = &requestBody{ReadCloser: response.Body, finish: finish}
	return response, nil
}

type requestBody struct {
	io.ReadCloser
	finish func()
}

func (b *requestBody) Close() error {
	defer b.finish()
	return b.ReadCloser.Close()
}

func issueDNS(ctx context.Context, job Certificate, provider string, secret credentials, keyDER []byte) ([]byte, []byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("无法读取 ACME 账号密钥: %w", err)
	}
	dns, err := dnsProvider(provider, secret)
	if err != nil {
		return nil, nil, fmt.Errorf("初始化 DNS 服务商: %w", err)
	}
	account := &acmeAccount{email: job.Email, key: key}
	config := lego.NewConfig(account)
	config.Certificate.KeyType = certcrypto.EC256
	if job.Staging {
		config.CADirURL = lego.LEDirectoryStaging
	}
	config.HTTPClient.Transport = requestTransport{ctx, config.HTTPClient.Transport}
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("连接 CA: %w", err)
	}
	checkCtx := dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		return check(fqdn, value)
	})
	if err := client.Challenge.SetDNS01Provider(&cancellableDNS{Provider: dns, ctx: ctx}, checkCtx); err != nil {
		return nil, nil, fmt.Errorf("初始化 DNS-01 验证: %w", err)
	}
	account.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("注册 ACME 账号: %w", err)
	}
	result, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: job.Domains, Bundle: true})
	if err != nil {
		return nil, nil, fmt.Errorf("DNS-01 签发: %w", err)
	}
	return result.Certificate, result.PrivateKey, nil
}
