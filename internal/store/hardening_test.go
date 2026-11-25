package store

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func unsetAdminPasswordEnv(t *testing.T) {
	t.Helper()
	const key = "NIUBWAF_ADMIN_PASSWORD"
	old, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("清除管理员密码环境变量失败: %v", err)
	}
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

func captureStoreLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	oldWriter, oldFlags, oldPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})
	return &output
}

func openHardening(t *testing.T) *Store {
	t.Helper()
	unsetAdminPasswordEnv(t)
	s, err := Open(filepath.Join(t.TempDir(), "hard.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func initialPasswordFromLogs(t *testing.T, output string) string {
	t.Helper()
	const marker = "初始管理员密码: "
	start := strings.LastIndex(output, marker)
	if start < 0 {
		t.Fatalf("首次初始化应记录随机管理员密码，日志为 %q", output)
	}
	rest := output[start+len(marker):]
	if len(rest) < 48 {
		t.Fatalf("随机管理员密码日志格式异常: %q", rest)
	}
	return rest[:48]
}

func TestMustChangePassFreshRandom(t *testing.T) {
	logs := captureStoreLogs(t)
	first := openHardening(t)
	firstPassword := initialPasswordFromLogs(t, logs.String())
	if got := first.GetSetting("must_change_pass"); got != "on" {
		t.Fatalf("全新部署使用随机口令应强制改密, got %q", got)
	}
	if ok, _ := VerifyPass("admin123", first.GetSetting("admin_pass")); ok {
		t.Fatal("新部署不应能使用 admin123 登录")
	}
	if ok, _ := VerifyPass(firstPassword, first.GetSetting("admin_pass")); !ok {
		t.Fatal("日志中的随机初始密码应能校验通过")
	}
	if strings.Count(logs.String(), "初始管理员密码: ") != 1 {
		t.Fatalf("首个新库应只打印一次初始密码: %q", logs.String())
	}

	second := openHardening(t)
	secondPassword := initialPasswordFromLogs(t, logs.String())
	if firstPassword == secondPassword {
		t.Fatal("两个新库的随机初始密码不应相同")
	}
	if ok, _ := VerifyPass("admin123", second.GetSetting("admin_pass")); ok {
		t.Fatal("第二个新库也不应能使用 admin123 登录")
	}
	if ok, _ := VerifyPass(secondPassword, second.GetSetting("admin_pass")); !ok {
		t.Fatal("第二个新库的随机初始密码应能校验通过")
	}
	if got := second.GetSetting("must_change_pass"); got != "on" {
		t.Fatalf("第二个新库应强制改密, got %q", got)
	}
}

func TestAdminPasswordEnvironmentAndReopen(t *testing.T) {
	const envPassword = "Str0ngPass"
	t.Setenv("NIUBWAF_ADMIN_PASSWORD", envPassword)
	logs := captureStoreLogs(t)
	path := filepath.Join(t.TempDir(), "reopen.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("使用环境密码创建数据库失败: %v", err)
	}
	if ok, _ := VerifyPass(envPassword, s.GetSetting("admin_pass")); !ok {
		t.Fatal("应优先使用 NIUBWAF_ADMIN_PASSWORD")
	}
	if ok, _ := VerifyPass("admin123", s.GetSetting("admin_pass")); ok {
		t.Fatal("环境密码初始化不应回退到 admin123")
	}
	if got := s.GetSetting("must_change_pass"); got != "on" {
		t.Fatalf("环境密码初始化后仍应强制改密, got %q", got)
	}
	if strings.Contains(logs.String(), "初始管理员密码: ") {
		t.Fatal("环境变量提供的密码不应写入日志")
	}
	originalHash := s.GetSetting("admin_pass")
	s.Close()

	logs.Reset()
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("重新打开已有数据库失败: %v", err)
	}
	defer reopened.Close()
	if got := reopened.GetSetting("admin_pass"); got != originalHash {
		t.Fatal("重新打开已有数据库不应重置管理员密码")
	}
	if ok, _ := VerifyPass(envPassword, reopened.GetSetting("admin_pass")); !ok {
		t.Fatal("重开后原管理员密码仍应有效")
	}
	if strings.Contains(logs.String(), "初始管理员密码: ") {
		t.Fatalf("已有数据库重开不应再次打印初始密码: %q", logs.String())
	}
}

func TestAdminPasswordEnvironmentRejectsWeakValues(t *testing.T) {
	cases := []struct {
		name, password, want string
	}{
		{name: "空密码", password: "", want: "至少 8 位"},
		{name: "过短", password: "Ab1", want: "至少 8 位"},
		{name: "纯字母", password: "abcdefgh", want: "字母和数字"},
		{name: "纯数字", password: "12345678", want: "字母和数字"},
		{name: "默认密码", password: "admin123", want: "不能使用默认密码"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NIUBWAF_ADMIN_PASSWORD", tc.password)
			s, err := Open(filepath.Join(t.TempDir(), "weak.db"))
			if err == nil {
				s.Close()
				t.Fatal("弱环境密码应返回错误")
			}
			if !strings.Contains(err.Error(), "NIUBWAF_ADMIN_PASSWORD") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误应明确说明环境密码问题 %q, got %v", tc.want, err)
			}
		})
	}
}

func TestLegacyDefaultHashRotatesOnReopen(t *testing.T) {
	t.Setenv("NIUBWAF_ADMIN_PASSWORD", "Str0ngPass")
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := HashPass("admin123")
	if err := s.SetSetting("admin_pass", legacyHash); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("must_change_pass", "off"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	logs := captureStoreLogs(t)
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.GetSetting("admin_pass"); got == legacyHash {
		t.Fatal("遗留默认密码哈希应在重开时轮换")
	}
	if ok, _ := VerifyPass("admin123", reopened.GetSetting("admin_pass")); ok {
		t.Fatal("遗留默认密码不应继续通过校验")
	}
	if ok, _ := VerifyPass("Str0ngPass", reopened.GetSetting("admin_pass")); !ok {
		t.Fatal("轮换后应使用环境变量提供的新密码")
	}
	if got := reopened.GetSetting("must_change_pass"); got != "on" {
		t.Fatalf("遗留默认密码轮换后应强制改密, got %q", got)
	}
	if strings.Contains(logs.String(), "初始管理员密码: ") {
		t.Fatal("环境变量提供的轮换密码不应写入日志")
	}
}

func TestMigrateAuthPassHashesPlaintext(t *testing.T) {
	s := openHardening(t)
	site := &Site{Name: "t", Domain: "t.local", Upstream: "http://127.0.0.1:8081", Enabled: true, WAFMode: "balanced", AuthUser: "u", AuthPass: "sitepw", DynamicMode: "off"}
	if err := s.CreateSite(site); err != nil {
		t.Fatalf("创建站点失败: %v", err)
	}
	// 模拟存量明文库：重启迁移应升级为哈希
	s.migrateAuthPass()
	got, err := s.GetSite(site.ID)
	if err != nil {
		t.Fatalf("读取站点失败: %v", err)
	}
	if !strings.HasPrefix(got.AuthPass, "pbkdf2_sha256$") {
		t.Fatalf("明文口令应被哈希, got %q", got.AuthPass)
	}
	if ok, _ := VerifyPass("sitepw", got.AuthPass); !ok {
		t.Fatal("哈希后原口令仍应校验通过")
	}
	// 幂等：再次迁移不应改变已哈希值
	first := got.AuthPass
	s.migrateAuthPass()
	again, _ := s.GetSite(site.ID)
	if again.AuthPass != first {
		t.Fatal("已哈希口令不应被重复哈希")
	}
}

func TestGetSiteRoundTrip(t *testing.T) {
	s := openHardening(t)
	site := &Site{Name: "g", Domain: "g.local", Upstream: "http://127.0.0.1:8081", Enabled: true, WAFMode: "strict", AuthUser: "bob", AuthPass: HashPass("pw12345"), DynamicMode: "observe"}
	if err := s.CreateSite(site); err != nil {
		t.Fatalf("创建站点失败: %v", err)
	}
	got, err := s.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite 失败: %v", err)
	}
	if got.Domain != "g.local" || got.WAFMode != "strict" || got.AuthUser != "bob" || got.DynamicMode != "observe" {
		t.Fatalf("字段往返不一致: %+v", got)
	}
	if _, err := s.GetSite(999999); err == nil {
		t.Fatal("不存在的站点应返回错误")
	}
}

func TestBackupVacuumInto(t *testing.T) {
	s := openHardening(t)
	site := &Site{Name: "b", Domain: "b.local", Upstream: "http://127.0.0.1:8081", Enabled: true, WAFMode: "balanced", DynamicMode: "off"}
	if err := s.CreateSite(site); err != nil {
		t.Fatalf("创建站点失败: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(dest); err != nil {
		t.Fatalf("备份失败: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("备份文件应存在: %v", err)
	}
	// 备份应为可独立打开的一致副本
	b, err := Open(dest)
	if err != nil {
		t.Fatalf("打开备份失败: %v", err)
	}
	defer b.Close()
	sites, err := b.ListSites()
	if err != nil || len(sites) != 1 || sites[0].Domain != "b.local" {
		t.Fatalf("备份内容不一致: sites=%v err=%v", sites, err)
	}
}
