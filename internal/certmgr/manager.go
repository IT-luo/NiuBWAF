package certmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"

	"niubwaf/internal/store"
)

const (
	jobTimeout    = 10 * time.Minute
	leaseDuration = 15 * time.Minute
)

var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type Account struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

type Certificate struct {
	ID        int64    `json:"id"`
	AccountID int64    `json:"account_id"`
	Domains   []string `json:"domains"`
	Email     string   `json:"email"`
	Staging   bool     `json:"staging"`
	ExpiresAt int64    `json:"expires_at"`
	Status    string   `json:"status"`
	LastError string   `json:"last_error"`
}

type Binding struct {
	SiteID        int64 `json:"site_id"`
	CertificateID int64 `json:"certificate_id"`
}

type Manager struct {
	db      *sql.DB
	dataDir string
	reload  func()
	alert   func(context.Context, string, string, map[string]any) (bool, error)
	wake    chan struct{}
	issue   func(context.Context, Certificate, string, credentials, []byte) ([]byte, []byte, error)
}

func New(db *sql.DB, dataDir string, reload func(), alert func(context.Context, string, string, map[string]any) (bool, error)) *Manager {
	return &Manager{db: db, dataDir: dataDir, reload: reload, alert: alert, wake: make(chan struct{}, 1), issue: issueDNS}
}

func (m *Manager) notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) SaveAccount(a Account, key, secret string) error {
	a.Name = strings.TrimSpace(a.Name)
	cred := credentials{strings.TrimSpace(key), strings.TrimSpace(secret)}
	if a.Name == "" || len(a.Name) > 100 || cred.Key == "" || len(cred.Key) > 4096 || len(cred.Secret) > 4096 {
		return errors.New("请填写 DNS 账号名称和有效凭据")
	}
	switch a.Provider {
	case "alidns", "tencentcloud":
		if cred.Secret == "" {
			return errors.New("此 DNS 服务商必须提供 Key 和 Secret")
		}
	case "cloudflare":
	default:
		return errors.New("不支持的 DNS 服务商")
	}
	plain, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	sealed, err := m.seal(plain, "dns-account:"+a.Provider, true)
	if err != nil {
		return err
	}
	if a.ID == 0 {
		_, err = m.db.Exec("INSERT INTO dns_certificate_accounts(name,provider,credentials) VALUES(?,?,?)", a.Name, a.Provider, sealed)
		return err
	}
	result, err := m.db.Exec("UPDATE dns_certificate_accounts SET name=?,credentials=? WHERE id=? AND provider=?", a.Name, sealed, a.ID, a.Provider)
	return affected(result, err, "DNS 账号不存在或服务商已改变")
}

func (m *Manager) Accounts() ([]Account, error) {
	rows, err := m.db.Query("SELECT id,name,provider FROM dns_certificate_accounts ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		var account Account
		if err := rows.Scan(&account.ID, &account.Name, &account.Provider); err != nil {
			return nil, err
		}
		out = append(out, account)
	}
	return out, rows.Err()
}

func canonicalDomains(domains []string) ([]string, error) {
	if len(domains) == 0 || len(domains) > 20 {
		return nil, errors.New("请输入 1 至 20 个域名")
	}
	seen := make(map[string]bool)
	result := make([]string, 0, len(domains))
	for _, raw := range domains {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		host := strings.TrimPrefix(domain, "*.")
		if len(domain) > 253 || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
			return nil, errors.New("请填写公网域名或一级通配符域名")
		}
		for _, label := range strings.Split(host, ".") {
			if !domainLabel.MatchString(label) {
				return nil, errors.New("域名格式不正确，国际化域名请填写 Punycode")
			}
		}
		if !seen[domain] {
			result = append(result, domain)
			seen[domain] = true
		}
	}
	sort.Strings(result)
	return result, nil
}

func (m *Manager) Queue(c Certificate) error {
	domains, err := canonicalDomains(c.Domains)
	if err != nil {
		return err
	}
	c.Email = strings.TrimSpace(c.Email)
	address, err := mail.ParseAddress(c.Email)
	if err != nil || address.Address != c.Email || len(c.Email) > 254 {
		return errors.New("请输入有效的联系邮箱")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	sealed, err := m.seal(der, "acme-account", false)
	if err != nil {
		return err
	}
	result, err := m.db.Exec(`INSERT INTO managed_certificates(account_id,domains,email,staging,account_key)
		SELECT id,?,?,?,? FROM dns_certificate_accounts WHERE id=?`,
		strings.Join(domains, ","), c.Email, c.Staging, sealed, c.AccountID)
	if err := affected(result, err, "请先选择已配置的 DNS 账号"); err != nil {
		return err
	}
	m.notify()
	return nil
}

func (m *Manager) Certificates() ([]Certificate, error) {
	rows, err := m.db.Query("SELECT id,account_id,domains,email,staging,expires_at,status,last_error FROM managed_certificates ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Certificate{}
	for rows.Next() {
		var c Certificate
		var domains string
		if err := rows.Scan(&c.ID, &c.AccountID, &domains, &c.Email, &c.Staging, &c.ExpiresAt, &c.Status, &c.LastError); err != nil {
			return nil, err
		}
		c.Domains = strings.Split(domains, ",")
		out = append(out, c)
	}
	return out, rows.Err()
}

func (m *Manager) Retry(id int64) error {
	result, err := m.db.Exec(`UPDATE managed_certificates SET next_attempt=0,status='queued',last_error='',lease=''
		WHERE id=? AND (lease='' OR next_attempt<=?)`, id, time.Now().Unix())
	if err := affected(result, err, "证书不存在或签发任务正在执行"); err != nil {
		return err
	}
	m.notify()
	return nil
}

func (m *Manager) Bindings() ([]Binding, error) {
	rows, err := m.db.Query("SELECT site_id,certificate_id FROM managed_certificate_sites ORDER BY site_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		var item Binding
		if err := rows.Scan(&item.SiteID, &item.CertificateID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (m *Manager) Bind(siteID, certID int64) error {
	if certID == 0 {
		if _, err := m.db.Exec("DELETE FROM managed_certificate_sites WHERE site_id=?", siteID); err != nil {
			return err
		}
	} else {
		var domain, certPEM, keyPEM string
		err := m.db.QueryRow(`SELECT s.domain,c.cert_pem,c.key_pem FROM sites s,managed_certificates c
			WHERE s.id=? AND c.id=? AND c.staging=0 AND c.expires_at>?`, siteID, certID, time.Now().Unix()).Scan(&domain, &certPEM, &keyPEM)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("请选择存在的站点和已签发的生产证书")
		}
		if err != nil {
			return err
		}
		if _, err := validatePair([]byte(certPEM), []byte(keyPEM), []string{domain}, time.Now()); err != nil {
			return err
		}
		result, err := m.db.Exec(`INSERT INTO managed_certificate_sites(site_id,certificate_id,domain)
			SELECT id,?,domain FROM sites WHERE id=? AND domain=?
			ON CONFLICT(site_id) DO UPDATE SET certificate_id=excluded.certificate_id,domain=excluded.domain`, certID, siteID, domain)
		if err := affected(result, err, "站点信息已变化，请重新选择"); err != nil {
			return err
		}
	}
	m.reload()
	return nil
}

func affected(result sql.Result, err error, missing string) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return errors.New(missing)
	}
	return err
}

func validatePair(certPEM, keyPEM []byte, domains []string, now time.Time) (time.Time, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("证书与私钥无法配对: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return time.Time{}, errors.New("证书不在有效期内")
	}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			found := false
			for _, name := range leaf.DNSNames {
				found = found || strings.EqualFold(name, domain)
			}
			if !found {
				return time.Time{}, fmt.Errorf("证书未覆盖 %s", domain)
			}
		} else if err := leaf.VerifyHostname(domain); err != nil {
			return time.Time{}, fmt.Errorf("证书未覆盖 %s", domain)
		}
	}
	return leaf.NotAfter, nil
}

func (m *Manager) Run(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for ctx.Err() == nil {
			for ctx.Err() == nil {
				worked, err := m.processNext(ctx)
				if err != nil {
					log.Printf("托管证书任务失败: %v", err)
				}
				if err != nil || !worked {
					break
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
			case <-tick.C:
			}
		}
	}()
	return done
}

func (m *Manager) processNext(ctx context.Context) (bool, error) {
	now := time.Now()
	lease := store.RandToken()
	var c Certificate
	var domains string
	var accountKey []byte
	err := m.db.QueryRow(`UPDATE managed_certificates SET status='issuing',next_attempt=?,lease=?
		WHERE id=(SELECT id FROM managed_certificates WHERE next_attempt<=? ORDER BY next_attempt,id LIMIT 1)
		RETURNING id,account_id,domains,email,staging,account_key,expires_at,last_error`, now.Add(leaseDuration).Unix(), lease, now.Unix()).
		Scan(&c.ID, &c.AccountID, &domains, &c.Email, &c.Staging, &accountKey, &c.ExpiresAt, &c.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	c.Domains = strings.Split(domains, ",")
	jobCtx, cancel := context.WithTimeout(ctx, jobTimeout)
	defer cancel()
	certPEM, keyPEM, err := m.obtain(jobCtx, c, accountKey)
	finished := time.Now()
	if ctx.Err() != nil && err != nil {
		_, saveErr := m.db.Exec(`UPDATE managed_certificates SET status='queued',lease='',next_attempt=?
			WHERE id=? AND lease=?`, finished.Add(time.Minute).Unix(), c.ID, lease)
		return true, saveErr
	}
	var expires time.Time
	if err == nil {
		expires, err = validatePair(certPEM, keyPEM, c.Domains, finished)
	}
	if err != nil {
		result, saveErr := m.db.Exec(`UPDATE managed_certificates SET status='failed',last_error=?,lease='',next_attempt=?
			WHERE id=? AND lease=?`, err.Error(), finished.Add(time.Hour).Unix(), c.ID, lease)
		if saveErr == nil && !c.Staging && c.ExpiresAt > 0 && c.LastError == "" && m.alert != nil && ctx.Err() == nil {
			if changed, _ := result.RowsAffected(); changed > 0 {
				_, _ = m.alert(ctx, "certificate_renewal_failed", "托管证书续期失败，请查看证书管理："+domains,
					map[string]any{"certificate_id": c.ID, "domains": c.Domains})
			}
		}
		return true, saveErr
	}
	renewAt := expires.Add(-30 * 24 * time.Hour)
	if minimum := finished.Add((expires.Sub(finished)) / 2); renewAt.Before(minimum) {
		renewAt = minimum
	}
	result, err := m.db.Exec(`UPDATE managed_certificates SET cert_pem=?,key_pem=?,expires_at=?,status='ready',
		last_error='',lease='',next_attempt=? WHERE id=? AND lease=? AND expires_at<?`,
		string(certPEM), string(keyPEM), expires.Unix(), renewAt.Unix(), c.ID, lease, expires.Unix())
	if err != nil {
		return true, err
	}
	changed, err := result.RowsAffected()
	if err == nil && changed > 0 {
		m.reload()
	} else if err == nil {
		// The CA may return the current certificate when renewal is requested early.
		remaining := time.Unix(c.ExpiresAt, 0).Sub(finished)
		retryIn := max(time.Second, min(12*time.Hour, remaining/2))
		_, err = m.db.Exec(`UPDATE managed_certificates SET status='ready',last_error='',lease='',next_attempt=? WHERE id=? AND lease=?`,
			finished.Add(retryIn).Unix(), c.ID, lease)
	}
	return true, err
}

func (m *Manager) obtain(ctx context.Context, c Certificate, encryptedKey []byte) ([]byte, []byte, error) {
	var provider string
	var ciphertext []byte
	if err := m.db.QueryRow("SELECT provider,credentials FROM dns_certificate_accounts WHERE id=?", c.AccountID).
		Scan(&provider, &ciphertext); err != nil {
		return nil, nil, err
	}
	plain, err := m.open(ciphertext, "dns-account:"+provider)
	if err != nil {
		return nil, nil, err
	}
	var cred credentials
	if err := json.Unmarshal(plain, &cred); err != nil {
		return nil, nil, err
	}
	key, err := m.open(encryptedKey, "acme-account")
	if err != nil {
		return nil, nil, err
	}
	cert, priv, err := m.issue(ctx, c, provider, cred, key)
	if err != nil {
		message := err.Error()
		for _, secret := range []string{cred.Key, cred.Secret} {
			if secret != "" {
				message = strings.ReplaceAll(message, secret, "[已隐藏]")
			}
		}
		runes := []rune(message)
		if len(runes) > 1000 {
			message = string(runes[:1000])
		}
		err = errors.New(message)
	}
	return cert, priv, err
}
