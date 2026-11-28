package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	attackLogQueueSize  = 8192
	attackLogFlushBatch = 4096
	auditLogLimit       = 10000
	auditPruneInterval  = 100
)

type Store struct {
	DB *sql.DB

	setMu            sync.RWMutex
	settingsRevision uint64
	settings         map[string]string

	tMu     sync.Mutex
	traffic map[trafficKey]trafficVal

	logCh             chan *AttackLog
	droppedAttackLogs atomic.Uint64
	auditInserts      atomic.Uint64
	stopCh            chan struct{}
	doneCh            chan struct{}
}

type trafficKey struct {
	minute string
	siteID int64
}

type trafficVal struct {
	reqs, blocks, bytes int64
}

type Site struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	Upstream     string `json:"upstream"`
	Enabled      bool   `json:"enabled"`
	WAFMode      string `json:"waf_mode"`
	AuthUser     string `json:"auth_user"`
	AuthPass     string `json:"-"`
	CCRate       int    `json:"cc_rate"`
	CCBurst      int    `json:"cc_burst"`
	Captcha      bool   `json:"captcha"`
	RespDetect   bool   `json:"resp_detect"`
	DynamicMode  string `json:"dynamic_mode"`
	BotMode      string `json:"bot_mode"`
	BotStrict    bool   `json:"bot_strict"`
	CertPEM      string `json:"-"`
	KeyPEM       string `json:"-"`
	HTTPRedirect bool   `json:"http_redirect"`
	CreatedAt    string `json:"created_at"`
}

type AttackLog struct {
	ID            int64  `json:"id"`
	Ts            string `json:"ts"`
	SiteID        int64  `json:"site_id"`
	Domain        string `json:"domain"`
	ClientIP      string `json:"client_ip"`
	Country       string `json:"country"`
	City          string `json:"city"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	QueryRedacted bool   `json:"query_redacted,omitempty"`
	Action        string `json:"action"`
	RuleID        int    `json:"rule_id"`
	Msg           string `json:"msg"`
	Severity      string `json:"severity"`
	Status        int    `json:"status"`
	ReqID         string `json:"req_id"`
}

// RedactQuery removes URL query data from a log before it is displayed or exported.
func (l *AttackLog) RedactQuery() {
	if path, _, hasQuery := strings.Cut(l.URL, "?"); hasQuery {
		l.URL, l.QueryRedacted = path, true
	}
}

type IPEntry struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	IP        string `json:"ip"`
	Note      string `json:"note"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

type IPReputation struct {
	IP            string `json:"ip"`
	Score         int    `json:"score"`
	BanCount      int    `json:"ban_count"`
	BannedUntil   string `json:"banned_until"`
	PardonedUntil string `json:"pardoned_until"`
	Reason        string `json:"reason"`
	Updated       string `json:"updated"`
}

type IPScore struct {
	IP     string
	Score  int
	Count  int
	LastTs string
}

type AuditLog struct {
	ID     int64  `json:"id"`
	Ts     string `json:"ts"`
	User   string `json:"user"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

type Exclusion struct {
	ID        int64  `json:"id"`
	SiteID    int64  `json:"site_id"`
	RuleID    int    `json:"rule_id"`
	URLPrefix string `json:"url_prefix"`
	Param     string `json:"param"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

type CustomRule struct {
	ID          int64  `json:"id"`
	SiteID      int64  `json:"site_id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
	Logic       string `json:"logic"`
	Conditions  string `json:"conditions"`
	Action      string `json:"action"`
	ActionParam string `json:"action_param"`
	Shadow      bool   `json:"shadow"`
	Note        string `json:"note"`
	CreatedAt   string `json:"created_at"`
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	// WAL + busy_timeout 已在 DSN 启用：读并发不阻塞写，写竞争由 busy_timeout 重试。
	// 小连接池避免单连接串行瓶颈，同时限制句柄数（SQLite 写仍串行）。
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)
	s := &Store{
		DB:       db,
		settings: map[string]string{},
		traffic:  map[trafficKey]trafficVal{},
		logCh:    make(chan *AttackLog, attackLogQueueSize),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	go s.flushLoop()
	return s, nil
}

func (s *Store) flushLoop() {
	defer close(s.doneCh)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.flush()
		case <-s.stopCh:
			s.flush()
			for len(s.logCh) > 0 {
				s.flush()
			}
			return
		}
	}
}

func (s *Store) flush() {
	s.tMu.Lock()
	pending := s.traffic
	s.traffic = map[trafficKey]trafficVal{}
	s.tMu.Unlock()
	if len(pending) > 0 {
		if err := s.flushTraffic(pending); err != nil {
			log.Printf("统计落盘失败，丢弃 %d 条聚合: %v", len(pending), err)
		}
	}
	batch := make([]*AttackLog, 0, attackLogFlushBatch)
	for len(batch) < attackLogFlushBatch {
		select {
		case l := <-s.logCh:
			batch = append(batch, l)
		default:
			goto write
		}
	}
write:
	if len(batch) > 0 {
		if err := s.flushLogs(batch); err != nil {
			log.Printf("攻击日志落盘失败，丢弃 %d 条: %v", len(batch), err)
		}
	}
}

// flushTraffic 将内存聚合的流量统计写入 SQLite。采用先交换后写：失败时仅丢弃本批
// 聚合（不回填，避免 DB 持续异常时内存无界增长），但错误会被记录而非静默吞掉。
func (s *Store) flushTraffic(pending map[trafficKey]trafficVal) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO traffic(minute,site_id,reqs,blocks,bytes) VALUES(?,?,?,?,?)
		ON CONFLICT(minute,site_id) DO UPDATE SET reqs=reqs+excluded.reqs, blocks=blocks+excluded.blocks, bytes=bytes+excluded.bytes`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for k, v := range pending {
		if _, err := stmt.Exec(k.minute, k.siteID, v.reqs, v.blocks, v.bytes); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	if err := stmt.Close(); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// flushLogs 批量写入攻击日志，错误同样上报而非静默丢弃。
func (s *Store) flushLogs(batch []*AttackLog) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO attack_logs(site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id,query_redacted)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, l := range batch {
		if _, err := stmt.Exec(l.SiteID, l.Domain, l.ClientIP, l.Country, l.Method, l.URL, l.Action, l.RuleID, l.Msg, l.Severity, l.Status, l.ReqID, l.QueryRedacted); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	if err := stmt.Close(); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() {
	close(s.stopCh)
	<-s.doneCh
	s.DB.Close()
	log.Println("统计数据已落盘")
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sites(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			domain TEXT NOT NULL UNIQUE,
			upstream TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			waf_mode TEXT DEFAULT 'balanced',
			auth_user TEXT DEFAULT '',
			auth_pass TEXT DEFAULT '',
			cc_rate INTEGER DEFAULT 0,
			cc_burst INTEGER DEFAULT 0,
			captcha INTEGER DEFAULT 0,
			resp_detect INTEGER DEFAULT 0,
			dynamic_mode TEXT DEFAULT 'off',
			bot_mode TEXT DEFAULT 'off',
			bot_strict INTEGER DEFAULT 0,
			cert_pem TEXT DEFAULT '',
			key_pem TEXT DEFAULT '',
			http_redirect INTEGER DEFAULT 0,
			created_at TEXT DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE TABLE IF NOT EXISTS site_api_policies (
			site_id INTEGER PRIMARY KEY,
			mode TEXT NOT NULL CHECK(mode IN ('off','observe','block')),
			prefix TEXT NOT NULL,
			document TEXT NOT NULL
		)`,
		`CREATE TRIGGER IF NOT EXISTS delete_site_api_policy AFTER DELETE ON sites
			BEGIN DELETE FROM site_api_policies WHERE site_id=OLD.id; END`,
		`CREATE TABLE IF NOT EXISTS site_upload_policies (
			site_id INTEGER PRIMARY KEY,
			policies TEXT NOT NULL
		)`,
		`CREATE TRIGGER IF NOT EXISTS delete_site_upload_policies AFTER DELETE ON sites
			BEGIN DELETE FROM site_upload_policies WHERE site_id=OLD.id; END`,
		`CREATE TABLE IF NOT EXISTS attack_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT DEFAULT (datetime('now','localtime')),
			site_id INTEGER, domain TEXT, client_ip TEXT, country TEXT,
			method TEXT, url TEXT, action TEXT, rule_id INTEGER,
			msg TEXT, severity TEXT, status INTEGER, req_id TEXT,
			query_redacted INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_ts ON attack_logs(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_recent_attacks ON attack_logs(id) WHERE status<>200`,
		`CREATE INDEX IF NOT EXISTS idx_logs_ip ON attack_logs(client_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_req_id ON attack_logs(req_id) WHERE req_id IS NOT NULL`,
		// 覆盖索引：信誉评分按 ts 范围 + client_ip 分组 + severity/action 聚合，全部字段入索引可索引-only 扫描，避免 60s 周期回表
		`CREATE INDEX IF NOT EXISTS idx_logs_rep ON attack_logs(ts, client_ip, severity, action)`,
		// 域名精确/后缀过滤走索引，避免前导 % LIKE 全表扫
		`CREATE INDEX IF NOT EXISTS idx_logs_domain ON attack_logs(domain)`,
		`CREATE TABLE IF NOT EXISTS ip_lists(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			kind TEXT NOT NULL, ip TEXT NOT NULL, note TEXT DEFAULT '',
			expires_at TEXT DEFAULT '',
			created_at TEXT DEFAULT (datetime('now','localtime')),
			UNIQUE(kind, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`,
		`CREATE TABLE IF NOT EXISTS console_accounts(
			username TEXT PRIMARY KEY,
			role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
			password_hash TEXT NOT NULL,
			enabled INTEGER NOT NULL,
			must_change INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS console_sessions(
			token BLOB PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL,
			csrf TEXT NOT NULL, must_change INTEGER NOT NULL, expires INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_console_sessions_user ON console_sessions(username)`,
		`CREATE INDEX IF NOT EXISTS idx_console_sessions_expires ON console_sessions(expires)`,
		`CREATE TRIGGER IF NOT EXISTS revoke_console_on_account_update AFTER UPDATE ON console_accounts
			BEGIN DELETE FROM console_sessions WHERE username=OLD.username; END`,
		`CREATE TRIGGER IF NOT EXISTS revoke_console_on_account_delete AFTER DELETE ON console_accounts
			BEGIN DELETE FROM console_sessions WHERE username=OLD.username; END`,
		`CREATE TRIGGER IF NOT EXISTS revoke_root_console_on_settings_update AFTER UPDATE ON settings
			WHEN OLD.key IN ('admin_pass','must_change_pass') AND OLD.value<>NEW.value
			BEGIN DELETE FROM console_sessions WHERE username='admin'; END`,
		`CREATE TRIGGER IF NOT EXISTS revoke_root_console_on_settings_delete AFTER DELETE ON settings
			WHEN OLD.key IN ('admin_pass','must_change_pass')
			BEGIN DELETE FROM console_sessions WHERE username='admin'; END`,
		`CREATE TRIGGER IF NOT EXISTS revoke_root_console_on_settings_insert AFTER INSERT ON settings
			WHEN NEW.key IN ('admin_pass','must_change_pass')
			BEGIN DELETE FROM console_sessions WHERE username='admin'; END`,
		`CREATE TABLE IF NOT EXISTS audit_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT DEFAULT (datetime('now','localtime')),
			user TEXT, action TEXT, detail TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS traffic(
			minute TEXT NOT NULL, site_id INTEGER NOT NULL,
			reqs INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
			PRIMARY KEY(minute, site_id)
		)`,
		`CREATE TABLE IF NOT EXISTS exclusions(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			site_id INTEGER NOT NULL DEFAULT 0,
			rule_id INTEGER NOT NULL,
			url_prefix TEXT DEFAULT '',
			param TEXT DEFAULT '',
			note TEXT DEFAULT '',
			created_at TEXT DEFAULT (datetime('now','localtime')),
			UNIQUE(site_id, rule_id, url_prefix, param)
		)`,
		`CREATE TABLE IF NOT EXISTS ip_reputation(
			ip TEXT PRIMARY KEY,
			score INTEGER DEFAULT 0,
			ban_count INTEGER DEFAULT 0,
			banned_until TEXT DEFAULT '',
			pardoned_until TEXT DEFAULT '',
			reason TEXT DEFAULT '',
			updated TEXT DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE TABLE IF NOT EXISTS custom_rules(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			site_id INTEGER NOT NULL DEFAULT 0,
			name TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			priority INTEGER DEFAULT 100,
			logic TEXT DEFAULT 'and',
			conditions TEXT DEFAULT '[]',
			action TEXT NOT NULL,
			action_param TEXT DEFAULT '',
			shadow INTEGER DEFAULT 0,
			note TEXT DEFAULT '',
			created_at TEXT DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE TABLE IF NOT EXISTS analytics_hour(
			ts INTEGER PRIMARY KEY,
			data TEXT NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := s.DB.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	for _, col := range []string{"cert_pem TEXT DEFAULT ''", "key_pem TEXT DEFAULT ''", "http_redirect INTEGER DEFAULT 0", "dynamic_mode TEXT DEFAULT 'off'", "bot_mode TEXT DEFAULT 'off'", "bot_strict INTEGER DEFAULT 0"} {
		s.DB.Exec("ALTER TABLE sites ADD COLUMN " + col)
	}
	// 老库幂等补齐影子运行开关；已存在时 SQLite 返回 duplicate column，可安全忽略。
	s.DB.Exec(`ALTER TABLE custom_rules ADD COLUMN shadow INTEGER DEFAULT 0`)
	if _, err := s.DB.Exec(`ALTER TABLE attack_logs ADD COLUMN query_redacted INTEGER NOT NULL DEFAULT 0`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name: query_redacted") {
		return fmt.Errorf("迁移攻击日志脱敏字段: %w", err)
	}
	if err := s.loadStartupSettings(); err != nil {
		return fmt.Errorf("读取数据库设置: %w", err)
	}
	adminHash := s.GetSetting("admin_pass")
	legacyDefault := false
	if adminHash != "" {
		legacyDefault, _ = VerifyPass("admin123", adminHash)
	}
	if adminHash == "" || legacyDefault {
		initialPasswordToLog := ""
		initialPassword, fromEnv := os.LookupEnv("NIUBWAF_ADMIN_PASSWORD")
		if fromEnv {
			if len(initialPassword) < 8 ||
				!strings.ContainsAny(initialPassword, "0123456789") ||
				!strings.ContainsAny(initialPassword, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				return fmt.Errorf("NIUBWAF_ADMIN_PASSWORD 强度不足：密码必须至少 8 位且同时包含字母和数字")
			}
			if initialPassword == "admin123" {
				return fmt.Errorf("NIUBWAF_ADMIN_PASSWORD 不能使用默认密码 admin123")
			}
		} else {
			initialPassword = RandToken()
			initialPasswordToLog = initialPassword
		}
		changed, err := s.initializeAdminPassword(adminHash, HashPass(initialPassword))
		if err != nil {
			return fmt.Errorf("初始化管理密码: %w", err)
		}
		if err := s.loadStartupSettings(); err != nil {
			return fmt.Errorf("读取初始化后的数据库设置: %w", err)
		}
		if changed && initialPasswordToLog != "" {
			log.Printf("初始管理员密码: %s（仅首次初始化显示，请立即修改）", initialPasswordToLog)
		}
	} else if s.GetSetting("must_change_pass") == "" {
		if _, err := s.DB.Exec(`INSERT INTO settings(key,value) VALUES('must_change_pass','off')
			ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE settings.value IS NULL OR settings.value=''`); err != nil {
			return fmt.Errorf("迁移强制改密设置: %w", err)
		}
		if err := s.loadStartupSettings(); err != nil {
			return fmt.Errorf("读取迁移后的数据库设置: %w", err)
		}
	}
	if err := s.migrateManagedCertificates(); err != nil {
		return fmt.Errorf("迁移托管证书: %w", err)
	}
	return s.migrateAuthPass()
}

func (s *Store) loadStartupSettings() error {
	settings, err := readAllConfigSettings(s.DB)
	if err != nil {
		return err
	}
	s.settings = settings
	return nil
}

// Keep password initialization and the first-login gate atomic across workers.
func (s *Store) initializeAdminPassword(expected, hash string) (bool, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO settings(key,value) VALUES('admin_pass',?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE settings.value=?`, hash, expected)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES('must_change_pass','on')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// migrateAuthPass 将存量明文站点 Basic-Auth 口令一次性升级为 PBKDF2 哈希（幂等）
func (s *Store) migrateAuthPass() error {
	rows, err := s.DB.Query(`SELECT id, auth_pass FROM sites WHERE auth_pass != ''`)
	if err != nil {
		return fmt.Errorf("读取待迁移站点口令: %w", err)
	}
	defer rows.Close()
	type row struct {
		id   int64
		pass string
	}
	var todo []row
	for rows.Next() {
		var id int64
		var pass string
		if err := rows.Scan(&id, &pass); err != nil {
			return fmt.Errorf("读取待迁移站点口令: %w", err)
		}
		if !strings.HasPrefix(pass, "pbkdf2_sha256$") {
			todo = append(todo, row{id, pass})
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历待迁移站点口令: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("关闭站点口令查询: %w", err)
	}
	for _, r := range todo {
		// Another worker may have changed the credential while we hashed it.
		if _, err := s.DB.Exec(`UPDATE sites SET auth_pass=? WHERE id=? AND auth_pass=?`, HashPass(r.pass), r.id, r.pass); err != nil {
			return fmt.Errorf("迁移站点 %d 口令: %w", r.id, err)
		}
	}
	return nil
}

// Backup 通过 VACUUM INTO 生成一致性热备份，可在服务运行中安全执行
func (s *Store) Backup(dest string) error {
	_, err := s.DB.Exec("VACUUM INTO ?", dest)
	return err
}

const pbkdf2Iterations = 200000

// pbkdf2SHA256 标准库实现 PBKDF2-HMAC-SHA256（RFC 8018），避免引入额外依赖
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

// HashPass 生成带随机盐的 PBKDF2-HMAC-SHA256 口令哈希
func HashPass(p string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand 不可用: " + err.Error())
	}
	dk := pbkdf2SHA256([]byte(p), salt, pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(dk))
}

func legacyHash(p string) string {
	h := sha256.Sum256([]byte("niubwaf:" + p))
	return hex.EncodeToString(h[:])
}

// VerifyPass 校验口令。兼容旧版无盐 SHA-256；needsRehash 为 true 时调用方应升级为 HashPass
func VerifyPass(password, stored string) (ok bool, needsRehash bool) {
	if strings.HasPrefix(stored, "pbkdf2_sha256$") {
		parts := strings.Split(stored, "$")
		if len(parts) != 4 {
			return false, false
		}
		iter, err := strconv.Atoi(parts[1])
		if err != nil || iter <= 0 || iter > 1_000_000 {
			return false, false
		}
		if len(parts[2]) != 2*16 || len(parts[3]) != 2*sha256.Size {
			return false, false
		}
		salt, err := hex.DecodeString(parts[2])
		if err != nil {
			return false, false
		}
		want, err := hex.DecodeString(parts[3])
		if err != nil {
			return false, false
		}
		got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
		return subtle.ConstantTimeCompare(got, want) == 1, false
	}
	ok = subtle.ConstantTimeCompare([]byte(legacyHash(password)), []byte(stored)) == 1
	return ok, ok
}

func RandToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (s *Store) GetSetting(key string) string {
	s.setMu.RLock()
	defer s.setMu.RUnlock()
	return s.settings[key]
}

func (s *Store) SetSetting(key, val string) error {
	return s.SetSettings(map[string]string{key: val})
}

func (s *Store) SetSettings(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	s.setMu.Lock()
	defer s.setMu.Unlock()
	if err := tx.Commit(); err != nil {
		return err
	}
	for key, value := range values {
		s.settings[key] = value
	}
	s.settingsRevision++
	return nil
}

func (s *Store) ListSites() ([]Site, error) {
	rows, err := s.DB.Query(`SELECT id,name,domain,upstream,enabled,waf_mode,auth_user,auth_pass,cc_rate,cc_burst,captcha,resp_detect,dynamic_mode,bot_mode,bot_strict,cert_pem,key_pem,http_redirect,created_at FROM sites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		var t Site
		if err := rows.Scan(&t.ID, &t.Name, &t.Domain, &t.Upstream, &t.Enabled, &t.WAFMode, &t.AuthUser, &t.AuthPass, &t.CCRate, &t.CCBurst, &t.Captcha, &t.RespDetect, &t.DynamicMode, &t.BotMode, &t.BotStrict, &t.CertPEM, &t.KeyPEM, &t.HTTPRedirect, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetSite(id int64) (*Site, error) {
	var t Site
	err := s.DB.QueryRow(`SELECT id,name,domain,upstream,enabled,waf_mode,auth_user,auth_pass,cc_rate,cc_burst,captcha,resp_detect,dynamic_mode,bot_mode,bot_strict,cert_pem,key_pem,http_redirect,created_at FROM sites WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.Domain, &t.Upstream, &t.Enabled, &t.WAFMode, &t.AuthUser, &t.AuthPass, &t.CCRate, &t.CCBurst, &t.Captcha, &t.RespDetect, &t.DynamicMode, &t.BotMode, &t.BotStrict, &t.CertPEM, &t.KeyPEM, &t.HTTPRedirect, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) CreateSite(t *Site) error {
	r, err := s.DB.Exec(`INSERT INTO sites(name,domain,upstream,enabled,waf_mode,auth_user,auth_pass,cc_rate,cc_burst,captcha,resp_detect,dynamic_mode,bot_mode,bot_strict,cert_pem,key_pem,http_redirect)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.Name, t.Domain, t.Upstream, t.Enabled, t.WAFMode, t.AuthUser, t.AuthPass, t.CCRate, t.CCBurst, t.Captcha, t.RespDetect, t.DynamicMode, t.BotMode, t.BotStrict, t.CertPEM, t.KeyPEM, t.HTTPRedirect)
	if err != nil {
		return err
	}
	t.ID, _ = r.LastInsertId()
	return nil
}

func (s *Store) UpdateSite(t *Site, replaceTLS bool) (tlsConfigured bool, err error) {
	return s.updateSite(t, replaceTLS, false, nil)
}

// UpdateSitePreservingUpstream retains the database's current upstream, including data
// that the console must not reveal, when a different site setting is edited.
func (s *Store) UpdateSitePreservingUpstream(t *Site, replaceTLS bool) (bool, error) {
	return s.updateSite(t, replaceTLS, true, nil)
}

// UpdateSiteRetainingTLS updates the site only if the domain and retained TLS pair still match the validated snapshot.
func (s *Store) UpdateSiteRetainingTLS(t, previous *Site, keepUpstream bool) (bool, error) {
	return s.updateSite(t, false, keepUpstream, previous)
}

func (s *Store) updateSite(t *Site, replaceTLS, keepUpstream bool, previous *Site) (tlsConfigured bool, err error) {
	var domain, cert, key string
	if previous != nil {
		domain, cert, key = previous.Domain, previous.CertPEM, previous.KeyPEM
	}
	err = s.DB.QueryRow(`UPDATE sites SET name=?,domain=?,upstream=CASE WHEN ? THEN upstream ELSE ? END,enabled=?,waf_mode=?,auth_user=?,
		auth_pass=COALESCE(NULLIF(?, ''), auth_pass),cc_rate=?,cc_burst=?,captcha=?,resp_detect=?,
		dynamic_mode=?,bot_mode=?,bot_strict=?,cert_pem=CASE WHEN ? THEN ? ELSE cert_pem END,
		key_pem=CASE WHEN ? THEN ? ELSE key_pem END,http_redirect=? WHERE id=?
		AND (? OR (domain=? AND cert_pem=? AND key_pem=?))
		RETURNING cert_pem <> '' AND key_pem <> '', upstream`,
		t.Name, t.Domain, keepUpstream, t.Upstream, t.Enabled, t.WAFMode, t.AuthUser, t.AuthPass, t.CCRate, t.CCBurst,
		t.Captcha, t.RespDetect, t.DynamicMode, t.BotMode, t.BotStrict, replaceTLS, t.CertPEM, replaceTLS,
		t.KeyPEM, t.HTTPRedirect, t.ID, previous == nil, domain, cert, key).Scan(&tlsConfigured, &t.Upstream)
	return tlsConfigured, err
}

func (s *Store) DeleteSite(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM sites WHERE id=?`, id)
	return err
}

func (s *Store) LogAttack(l *AttackLog) error {
	entry := *l
	entry.RedactQuery()
	select {
	case s.logCh <- &entry:
	default:
		dropped := s.droppedAttackLogs.Add(1)
		if dropped == 1 || dropped%1000 == 0 {
			log.Printf("攻击日志队列已满，累计丢弃 %d 条攻击日志", dropped)
		}
	}
	return nil
}

// logWhere 构造攻击日志过滤条件。IP/域名优先使用可走索引的等值或前缀匹配
// （整 IP、整域名为最常见查询），仅当输入确为中间片段时才回退前导 % LIKE 全表扫。
func logWhere(ip, domain, action string) (string, []any) {
	where := " WHERE 1=1"
	args := []any{}
	if ip != "" {
		switch {
		case net.ParseIP(ip) != nil:
			where += " AND client_ip=?"
			args = append(args, ip)
		case strings.Trim(ip, "0123456789abcdefABCDEF.:") == "":
			where += " AND client_ip LIKE ?"
			args = append(args, ip+"%")
		default:
			where += " AND client_ip LIKE ?"
			args = append(args, "%"+ip+"%")
		}
	}
	if domain != "" {
		if isFullHost(domain) {
			where += " AND domain=?"
			args = append(args, strings.ToLower(domain))
		} else {
			where += " AND domain LIKE ?"
			args = append(args, "%"+domain+"%")
		}
	}
	if action != "" {
		where += " AND action=?"
		args = append(args, action)
	}
	return where, args
}

func isFullHost(s string) bool {
	if !strings.Contains(s, ".") || strings.ContainsAny(s, "%_ ") {
		return false
	}
	return strings.Trim(strings.ToLower(s), "abcdefghijklmnopqrstuvwxyz0123456789.-") == ""
}

func (s *Store) QueryLogs(ip, domain, action string, limit, offset int) ([]AttackLog, int, error) {
	return s.queryLogs(ip, domain, action, limit, offset, false)
}

func (s *Store) QueryAttackLogs(ip, domain, action string, limit, offset int) ([]AttackLog, int, error) {
	return s.queryLogs(ip, domain, action, limit, offset, true)
}

func (s *Store) RecentAttackLogs(limit int) ([]AttackLog, error) {
	return s.readLogRows(" WHERE status<>200", nil, limit, 0)
}

func (s *Store) queryLogs(ip, domain, action string, limit, offset int, attackOnly bool) ([]AttackLog, int, error) {
	where, args := logWhere(ip, domain, action)
	if attackOnly {
		where += " AND status<>200"
	}
	var total int
	s.DB.QueryRow(`SELECT COUNT(*) FROM attack_logs`+where, args...).Scan(&total)
	list, err := s.readLogRows(where, args, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (s *Store) readLogRows(where string, args []any, limit, offset int) ([]AttackLog, error) {
	rows, err := s.DB.Query(`SELECT id,ts,site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id,query_redacted
		FROM attack_logs`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AttackLog{}
	for rows.Next() {
		var l AttackLog
		if err := rows.Scan(&l.ID, &l.Ts, &l.SiteID, &l.Domain, &l.ClientIP, &l.Country, &l.Method, &l.URL, &l.Action, &l.RuleID, &l.Msg, &l.Severity, &l.Status, &l.ReqID, &l.QueryRedacted); err != nil {
			return nil, err
		}
		l.RedactQuery()
		out = append(out, l)
	}
	return out, rows.Err()
}

// EachAttackForAnalytics 遍历指定时段的已处置日志，用于修复旧版小时汇总。
func (s *Store) EachAttackForAnalytics(from, to time.Time, fn func(AttackLog)) error {
	rows, err := s.DB.Query(`SELECT COALESCE(client_ip,''),COALESCE(country,''),COALESCE(domain,''),
		COALESCE(url,''),COALESCE(action,''),COALESCE(msg,''),COALESCE(rule_id,0),status
		FROM attack_logs WHERE ts >= ? AND ts < ? AND status<>200 ORDER BY ts, id`,
		from.Local().Format(time.DateTime), to.Local().Format(time.DateTime))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var l AttackLog
		if err := rows.Scan(&l.ClientIP, &l.Country, &l.Domain, &l.URL, &l.Action, &l.Msg, &l.RuleID, &l.Status); err != nil {
			return err
		}
		fn(l)
	}
	return rows.Err()
}

// EachLog 流式遍历攻击日志（不在内存累积），供 CSV 导出等大批量场景使用
func (s *Store) EachLog(ip, domain, action string, fn func(*AttackLog) error) error {
	where, args := logWhere(ip, domain, action)
	rows, err := s.DB.Query(`SELECT id,ts,site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id,query_redacted
		FROM attack_logs`+where+` ORDER BY id DESC`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var l AttackLog
		if err := rows.Scan(&l.ID, &l.Ts, &l.SiteID, &l.Domain, &l.ClientIP, &l.Country, &l.Method, &l.URL, &l.Action, &l.RuleID, &l.Msg, &l.Severity, &l.Status, &l.ReqID, &l.QueryRedacted); err != nil {
			return err
		}
		l.RedactQuery()
		if err := fn(&l); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) ClearLogs() (int64, error) {
	res, err := s.DB.Exec(`DELETE FROM attack_logs`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// MaxLogID 返回攻击日志最大行 id（O(1)），用于判断自上次计算后是否有新日志
func (s *Store) MaxLogID() int64 {
	var id int64
	s.DB.QueryRow(`SELECT COALESCE(MAX(id),0) FROM attack_logs`).Scan(&id)
	return id
}

func (s *Store) ListIPs(kind string) ([]IPEntry, error) {
	q := `SELECT id,kind,ip,note,expires_at,created_at FROM ip_lists`
	args := []any{}
	if kind != "" {
		q += ` WHERE kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY id DESC`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPEntry{}
	for rows.Next() {
		var e IPEntry
		if err := rows.Scan(&e.ID, &e.Kind, &e.IP, &e.Note, &e.ExpiresAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AddIP(kind, ip, note, expires string) error {
	_, err := s.DB.Exec(`INSERT INTO ip_lists(kind,ip,note,expires_at) VALUES(?,?,?,?)
		ON CONFLICT(kind,ip) DO UPDATE SET note=excluded.note, expires_at=excluded.expires_at`, kind, ip, note, expires)
	return err
}

func (s *Store) DeleteIP(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM ip_lists WHERE id=?`, id)
	return err
}

// ScoreIPs 聚合滑动窗口内的攻击评分：仅统计已处置的真实攻击检测（waf/resp/cc/semantic），
// 排除观察记录及 blacklist/geo/reputation 等处置动作，避免封禁后自我累积导致永不解封。
// 权重 CRITICAL=3 / WARNING=2 / 其它=1。
func (s *Store) ScoreIPs(windowStart string, threshold int) ([]IPScore, error) {
	rows, err := s.DB.Query(`SELECT client_ip,
		SUM(CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'WARNING' THEN 2 ELSE 1 END) score,
		COUNT(*) cnt, MAX(ts) last_ts
		FROM attack_logs
		WHERE ts >= ? AND client_ip != '' AND status<>200 AND action IN ('waf','resp','cc','semantic')
		GROUP BY client_ip HAVING score >= ?`, windowStart, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPScore{}
	for rows.Next() {
		var sc IPScore
		if err := rows.Scan(&sc.IP, &sc.Score, &sc.Count, &sc.LastTs); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

func (s *Store) GetReputation(ip string) *IPReputation {
	var r IPReputation
	err := s.DB.QueryRow(`SELECT ip,score,ban_count,banned_until,pardoned_until,reason,updated
		FROM ip_reputation WHERE ip=?`, ip).
		Scan(&r.IP, &r.Score, &r.BanCount, &r.BannedUntil, &r.PardonedUntil, &r.Reason, &r.Updated)
	if err != nil {
		return nil
	}
	return &r
}

func (s *Store) UpsertReputation(ip string, score, banCount int, bannedUntil, reason string) error {
	_, err := s.DB.Exec(`INSERT INTO ip_reputation(ip,score,ban_count,banned_until,reason,updated)
		VALUES(?,?,?,?,?,datetime('now','localtime'))
		ON CONFLICT(ip) DO UPDATE SET score=excluded.score, ban_count=excluded.ban_count,
		banned_until=excluded.banned_until, reason=excluded.reason, updated=excluded.updated`,
		ip, score, banCount, bannedUntil, reason)
	return err
}

func (s *Store) ListReputation(limit int) ([]IPReputation, error) {
	rows, err := s.DB.Query(`SELECT ip,score,ban_count,banned_until,pardoned_until,reason,updated
		FROM ip_reputation ORDER BY banned_until DESC, score DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPReputation{}
	for rows.Next() {
		var r IPReputation
		if err := rows.Scan(&r.IP, &r.Score, &r.BanCount, &r.BannedUntil, &r.PardonedUntil, &r.Reason, &r.Updated); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ActiveBans 返回当前生效的自动封禁（ip → unix 到期秒），供代理载入内存判定层
func (s *Store) ActiveBans(now string) (map[string]int64, error) {
	out := map[string]int64{}
	rows, err := s.DB.Query(`SELECT ip,banned_until FROM ip_reputation WHERE banned_until > ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, until string
		if err := rows.Scan(&ip, &until); err != nil {
			return nil, err
		}
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", until, time.Local); err == nil {
			out[ip] = t.Unix()
		}
	}
	return out, rows.Err()
}

// Unban 人工解封：清空封禁并重置递增计数，给予一个窗口期的赦免，避免立即被重新封禁
func (s *Store) Unban(ip, pardonedUntil string) error {
	_, err := s.DB.Exec(`UPDATE ip_reputation SET banned_until='', ban_count=0, pardoned_until=?,
		updated=datetime('now','localtime') WHERE ip=?`, pardonedUntil, ip)
	return err
}

func (s *Store) PruneReputation(before string) {
	s.DB.Exec(`DELETE FROM ip_reputation WHERE banned_until='' AND updated < ?`, before)
}

func (s *Store) IPAttackCount(ip string) int {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM attack_logs WHERE client_ip=? AND status<>200 AND action IN ('waf','resp','cc','semantic')`, ip).Scan(&n)
	return n
}

func (s *Store) Audit(user, action, detail string) {
	if _, err := s.DB.Exec(`INSERT INTO audit_logs(user,action,detail) VALUES(?,?,?)`, user, action, detail); err != nil {
		return
	}
	if s.auditInserts.Add(1)%auditPruneInterval == 0 {
		if err := s.pruneAuditLogs(); err != nil {
			log.Printf("审计日志清理失败: %v", err)
		}
	}
}

// pruneAuditLogs 保留 id 最大的 auditLogLimit 条审计日志。
func (s *Store) pruneAuditLogs() error {
	_, err := s.DB.Exec(`DELETE FROM audit_logs WHERE id < (
		SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1 OFFSET ?
	)`, auditLogLimit-1)
	return err
}

func (s *Store) ListAudit(limit int) ([]AuditLog, error) {
	rows, err := s.DB.Query(`SELECT id,ts,user,action,detail FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditLog{}
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.Ts, &a.User, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *Store) AddTraffic(siteID int64, blocked bool, bytes int64) {
	minute := time.Now().Format("2006-01-02 15:04")
	s.tMu.Lock()
	v := s.traffic[trafficKey{minute, siteID}]
	v.reqs++
	if blocked {
		v.blocks++
	}
	v.bytes += bytes
	s.traffic[trafficKey{minute, siteID}] = v
	s.tMu.Unlock()
}

// SaveAnalyticsHour upsert 小时级分析桶（JSON 载荷）
func (s *Store) SaveAnalyticsHour(ts int64, data string) error {
	_, err := s.DB.Exec("INSERT INTO analytics_hour(ts, data) VALUES(?, ?) ON CONFLICT(ts) DO UPDATE SET data=excluded.data", ts, data)
	return err
}

func (s *Store) LoadAnalyticsHours(since int64) (map[int64]string, error) {
	rows, err := s.DB.Query("SELECT ts, data FROM analytics_hour WHERE ts >= ?", since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var ts int64
		var data string
		if err := rows.Scan(&ts, &data); err != nil {
			return nil, err
		}
		out[ts] = data
	}
	return out, rows.Err()
}

func (s *Store) PruneAnalytics(before int64) error {
	_, err := s.DB.Exec("DELETE FROM analytics_hour WHERE ts < ?", before)
	return err
}

type TrendPoint struct {
	Minute string `json:"minute"`
	Reqs   int64  `json:"reqs"`
	Blocks int64  `json:"blocks"`
}

func (s *Store) Trend(hours int) ([]TrendPoint, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04")
	rows, err := s.DB.Query(`SELECT minute, SUM(reqs), SUM(blocks) FROM traffic WHERE minute>=? GROUP BY minute ORDER BY minute`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrendPoint{}
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.Minute, &p.Reqs, &p.Blocks); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

type Stats struct {
	TodayReqs         int64  `json:"today_reqs"`
	TodayBlocks       int64  `json:"today_blocks"`
	TotalReqs         int64  `json:"total_reqs"`
	TotalBlocks       int64  `json:"total_blocks"`
	DroppedAttackLogs uint64 `json:"dropped_attack_logs"`
}

func (s *Store) Stats() Stats {
	var st Stats
	today := time.Now().Format("2006-01-02")
	s.DB.QueryRow(`SELECT COALESCE(SUM(reqs),0), COALESCE(SUM(blocks),0) FROM traffic WHERE minute LIKE ?`, today+"%").Scan(&st.TodayReqs, &st.TodayBlocks)
	s.DB.QueryRow(`SELECT COALESCE(SUM(reqs),0), COALESCE(SUM(blocks),0) FROM traffic`).Scan(&st.TotalReqs, &st.TotalBlocks)
	s.tMu.Lock()
	for k, v := range s.traffic {
		st.TotalReqs += v.reqs
		st.TotalBlocks += v.blocks
		if strings.HasPrefix(k.minute, today) {
			st.TodayReqs += v.reqs
			st.TodayBlocks += v.blocks
		}
	}
	s.tMu.Unlock()
	st.DroppedAttackLogs = s.droppedAttackLogs.Load()
	return st
}

type KV struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

func (s *Store) TopIPs(limit int) ([]KV, error) {
	return s.topKV(`SELECT client_ip, COUNT(*) c FROM attack_logs WHERE status<>200 GROUP BY client_ip ORDER BY c DESC LIMIT ?`, limit)
}

func (s *Store) TopRules(limit int) ([]KV, error) {
	return s.topKV(`SELECT COALESCE(NULLIF(msg,''),'规则'||rule_id), COUNT(*) c FROM attack_logs WHERE status<>200 GROUP BY msg ORDER BY c DESC LIMIT ?`, limit)
}

func (s *Store) TopDomains(limit int) ([]KV, error) {
	return s.topKV(`SELECT domain, COUNT(*) c FROM attack_logs WHERE status<>200 GROUP BY domain ORDER BY c DESC LIMIT ?`, limit)
}

func (s *Store) TopCountries(limit int) ([]KV, error) {
	return s.topKV(`SELECT COALESCE(NULLIF(country,''),'未知'), COUNT(*) c FROM attack_logs WHERE status<>200 GROUP BY country ORDER BY c DESC LIMIT ?`, limit)
}

func (s *Store) topKV(q string, limit int) ([]KV, error) {
	rows, err := s.DB.Query(q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KV{}
	for rows.Next() {
		var kv KV
		if err := rows.Scan(&kv.Key, &kv.Count); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, nil
}

func (s *Store) CleanupLogs(days int) error {
	before := time.Now().AddDate(0, 0, -days).Format("2006-01-02 15:04:05")
	_, err := s.DB.Exec(`DELETE FROM attack_logs WHERE ts < ?`, before)
	return err
}

func (s *Store) ListExclusions() ([]Exclusion, error) {
	rows, err := s.DB.Query(`SELECT id,site_id,rule_id,url_prefix,param,note,created_at FROM exclusions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Exclusion{}
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.ID, &e.SiteID, &e.RuleID, &e.URLPrefix, &e.Param, &e.Note, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AddExclusion(e *Exclusion) error {
	r, err := s.DB.Exec(`INSERT INTO exclusions(site_id,rule_id,url_prefix,param,note) VALUES(?,?,?,?,?)
		ON CONFLICT(site_id,rule_id,url_prefix,param) DO UPDATE SET note=excluded.note`,
		e.SiteID, e.RuleID, e.URLPrefix, e.Param, e.Note)
	if err != nil {
		return err
	}
	e.ID, _ = r.LastInsertId()
	return nil
}

func (s *Store) DeleteExclusion(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM exclusions WHERE id=?`, id)
	return err
}

func (s *Store) ListRules() ([]CustomRule, error) {
	rows, err := s.DB.Query(`SELECT id,site_id,name,enabled,priority,logic,conditions,action,action_param,shadow,note,created_at
		FROM custom_rules ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CustomRule{}
	for rows.Next() {
		var r CustomRule
		if err := rows.Scan(&r.ID, &r.SiteID, &r.Name, &r.Enabled, &r.Priority, &r.Logic, &r.Conditions, &r.Action, &r.ActionParam, &r.Shadow, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateRule(r *CustomRule) error {
	res, err := s.DB.Exec(`INSERT INTO custom_rules(site_id,name,enabled,priority,logic,conditions,action,action_param,shadow,note)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.SiteID, r.Name, r.Enabled, r.Priority, r.Logic, r.Conditions, r.Action, r.ActionParam, r.Shadow, r.Note)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateRule(r *CustomRule) error {
	_, err := s.DB.Exec(`UPDATE custom_rules SET site_id=?,name=?,enabled=?,priority=?,logic=?,conditions=?,action=?,action_param=?,shadow=?,note=? WHERE id=?`,
		r.SiteID, r.Name, r.Enabled, r.Priority, r.Logic, r.Conditions, r.Action, r.ActionParam, r.Shadow, r.Note, r.ID)
	return err
}

func (s *Store) DeleteRule(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM custom_rules WHERE id=?`, id)
	return err
}

// AttackCountSince 统计窗口内攻击事件数，供告警阈值判定（日志异步落盘，约 1s 延迟）
func (s *Store) AttackCountSince(since string) int {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM attack_logs WHERE ts >= ? AND status<>200`, since).Scan(&n)
	return n
}
