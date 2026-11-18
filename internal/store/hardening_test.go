package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openHardening(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "hard.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMustChangePassFreshDefault(t *testing.T) {
	s := openHardening(t)
	if got := s.GetSetting("must_change_pass"); got != "on" {
		t.Fatalf("全新部署使用默认口令应强制改密, got %q", got)
	}
	if ok, _ := VerifyPass("admin123", s.GetSetting("admin_pass")); !ok {
		t.Fatal("默认口令应为 admin123")
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