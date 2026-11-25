package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

func hardenAPI(t *testing.T) *API {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "harden.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(st, nil)
	setTestAdminPass(a, "admin123")
	return a
}

// setTestAdminPass 显式固定认证测试口令，不依赖生产环境的随机初始密码。
func setTestAdminPass(a *API, pass string) {
	a.Store.SetSetting("admin_pass", store.HashPass(pass))
	if pass == "admin123" {
		a.Store.SetSetting("must_change_pass", "on")
	} else {
		a.Store.SetSetting("must_change_pass", "off")
	}
}

func testJSONRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func loginCookie(t *testing.T, h http.Handler, pass string) (*http.Cookie, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	r := testJSONRequest("POST", "/api/login", `{"password":"`+pass+`"}`)
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("登录失败: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "niub_admin" {
			return c, body
		}
	}
	t.Fatal("登录未下发会话 Cookie")
	return nil, nil
}

func csrfToken(t *testing.T, h http.Handler, ck *http.Cookie) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/csrf", nil)
	r.AddCookie(ck)
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("获取 CSRF token 失败: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Token == "" {
		t.Fatalf("CSRF 响应应包含非空 token: body=%s err=%v", rec.Body.String(), err)
	}
	return body.Token
}

func adminCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "niub_admin" {
			return ck
		}
	}
	t.Fatal("响应未下发管理会话 Cookie")
	return nil
}

func TestMustChangeGateFlow(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ck, body := loginCookie(t, h, "admin123")
	if body["must_change"] != true {
		t.Fatalf("默认口令登录应返回 must_change=true, got %v", body["must_change"])
	}
	otherCK, _ := loginCookie(t, h, "admin123")
	token := csrfToken(t, h, ck) // 强制改密期间也必须能获取 CSRF token

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/sites", nil)
	r.AddCookie(ck)
	h.ServeHTTP(rec, r)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "must_change") {
		t.Fatalf("未改密应被门禁拦截 403, got %d %s", rec.Code, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	r2 := testJSONRequest("PUT", "/api/password", `{"old":"admin123","new":"Str0ngPass"}`)
	r2.AddCookie(ck)
	r2.Header.Set("X-NiuB-CSRF", token)
	h.ServeHTTP(rec2, r2)
	if rec2.Code != 200 {
		t.Fatalf("改密应成功, got %d %s", rec2.Code, rec2.Body.String())
	}
	if a.Store.GetSetting("must_change_pass") != "off" {
		t.Fatal("改密后应清除强制改密标志")
	}
	newCK := adminCookie(t, rec2)
	if newCK.Value == "" || newCK.Value == ck.Value {
		t.Fatal("改密成功必须轮换当前会话 Cookie")
	}

	for name, oldCK := range map[string]*http.Cookie{"当前旧会话": ck, "其他旧会话": otherCK} {
		oldRec := httptest.NewRecorder()
		oldReq := httptest.NewRequest("GET", "/api/sites", nil)
		oldReq.AddCookie(oldCK)
		h.ServeHTTP(oldRec, oldReq)
		if oldRec.Code != 401 {
			t.Fatalf("%s改密后应被撤销并返回 401, got %d %s", name, oldRec.Code, oldRec.Body.String())
		}
	}
	rec3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("GET", "/api/sites", nil)
	r3.AddCookie(newCK)
	h.ServeHTTP(rec3, r3)
	if rec3.Code != 200 {
		t.Fatalf("改密后的新会话应放行业务 API, got %d %s", rec3.Code, rec3.Body.String())
	}
	newToken := csrfToken(t, h, newCK)
	if newToken == token {
		t.Fatal("改密后应同时轮换 CSRF token")
	}
	a.mu.Lock()
	sessionCount, csrfCount := len(a.sessions), len(a.csrfTokens)
	a.mu.Unlock()
	if sessionCount != 1 || csrfCount != 1 {
		t.Fatalf("改密后应仅保留新会话及对应 CSRF token, sessions=%d csrf=%d", sessionCount, csrfCount)
	}
}

func TestChangePassStrength(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.NotFoundHandler())
	cookie, _ := loginCookie(t, h, "admin123")
	csrf := csrfToken(t, h, cookie)
	change := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := testJSONRequest(http.MethodPut, "/api/password", body)
		req.AddCookie(cookie)
		req.Header.Set("X-NiuB-CSRF", csrf)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, nw := range []string{"Ab1", "admin123", "abcdefgh", "12345678"} {
		rec := change(`{"old":"admin123","new":"` + nw + `"}`)
		if rec.Code != 400 {
			t.Errorf("弱口令 %q 应被拒, got %d", nw, rec.Code)
		}
	}
	recBad := change(`{"old":"wrong","new":"Str0ngPass"}`)
	if recBad.Code != 403 {
		t.Errorf("原密码错误应 403, got %d", recBad.Code)
	}
	recOK := change(`{"old":"admin123","new":"Str0ngPass"}`)
	if recOK.Code != 200 {
		t.Fatalf("合规口令应成功, got %d %s", recOK.Code, recOK.Body.String())
	}
	if ok, _ := store.VerifyPass("Str0ngPass", a.Store.GetSetting("admin_pass")); !ok {
		t.Fatal("新口令应生效")
	}
	if a.Store.GetSetting("must_change_pass") != "off" {
		t.Fatal("改密后应清除强制标志")
	}
	// 已公开的历史默认口令即使符合通用强度规则也不能重新启用。
	cookie = adminCookie(t, recOK)
	csrf = csrfToken(t, h, cookie)
	recLegacyName := change(`{"old":"Str0ngPass","new":"admin123"}`)
	if recLegacyName.Code != 400 {
		t.Fatalf("历史默认口令应被拒绝, got %d %s", recLegacyName.Code, recLegacyName.Body.String())
	}
	if ok, _ := store.VerifyPass("Str0ngPass", a.Store.GetSetting("admin_pass")); !ok {
		t.Fatal("拒绝弱口令后原口令应保持不变")
	}
}

func TestTrustedProxiesRejectTrustAll(t *testing.T) {
	a := hardenAPI(t)
	for _, v := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8,0.0.0.0/0"} {
		rec := httptest.NewRecorder()
		a.putSettings(rec, testJSONRequest("PUT", "/api/settings", `{"trusted_proxies":"`+v+`"}`))
		if rec.Code != 400 {
			t.Errorf("信任全部网段 %q 应被拒, got %d %s", v, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	a.putSettings(rec, testJSONRequest("PUT", "/api/settings", `{"trusted_proxies":"999.0.0.0/8"}`))
	if rec.Code != 400 {
		t.Errorf("非法 CIDR 应被拒, got %d", rec.Code)
	}
}

func TestSitesMaskAuthPass(t *testing.T) {
	a := hardenAPI(t)
	site := &store.Site{Name: "m", Domain: "m.local", Upstream: "http://127.0.0.1:8081", Enabled: true, WAFMode: "balanced", AuthUser: "u", AuthPass: store.HashPass("pw12345"), DynamicMode: "off"}
	if err := a.Store.CreateSite(site); err != nil {
		t.Fatalf("创建站点失败: %v", err)
	}
	a.Store.SetSetting("must_change_pass", "off")
	a.mu.Lock()
	a.sessions["tok"] = time.Now().Add(time.Hour)
	a.mu.Unlock()
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/sites", nil)
	r.AddCookie(&http.Cookie{Name: "niub_admin", Value: "tok"})
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("列表应 200, got %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "pbkdf2_sha256$") || strings.Contains(rec.Body.String(), "pw12345") {
		t.Fatalf("列表不应回显口令哈希: %s", rec.Body.String())
	}
	var sites []store.Site
	json.Unmarshal(rec.Body.Bytes(), &sites)
	if len(sites) != 1 || sites[0].AuthPass != "" || sites[0].AuthUser != "u" {
		t.Fatalf("auth_pass 应掩码为空且保留 auth_user: %+v", sites)
	}
}

func fullTestAPI(t *testing.T) *API {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "full.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng, err := engine.New()
	if err != nil {
		t.Fatalf("引擎初始化失败: %v", err)
	}
	p := proxy.New(st, eng, proxy.NewGeoIP(dir), proxy.NewIDCMatcher(dir), proxy.NewTorList(dir), "secret")
	a := New(st, p)
	a.DataDir = dir
	a.Store.SetSetting("must_change_pass", "off")
	return a
}

func TestSaveSiteHashesAuthPass(t *testing.T) {
	a := fullTestAPI(t)
	rec := httptest.NewRecorder()
	a.saveSite(rec, testJSONRequest("POST", "/api/sites", `{"name":"s","domain":"s.local","upstream":"http://127.0.0.1:8081","enabled":true,"waf_mode":"balanced","auth_user":"u","auth_pass":"plainpw","dynamic_mode":"off"}`), 0)
	if rec.Code != 200 {
		t.Fatalf("创建失败 %d %s", rec.Code, rec.Body.String())
	}
	var created store.Site
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.AuthPass != "" {
		t.Fatal("创建响应应掩码 auth_pass")
	}
	got, err := a.Store.GetSite(created.ID)
	if err != nil {
		t.Fatalf("读取站点失败: %v", err)
	}
	if !strings.HasPrefix(got.AuthPass, "pbkdf2_sha256$") {
		t.Fatalf("应哈希落盘: %q", got.AuthPass)
	}
	if ok, _ := store.VerifyPass("plainpw", got.AuthPass); !ok {
		t.Fatal("原口令应校验通过")
	}
	// 更新留空：保留原口令哈希
	rec2 := httptest.NewRecorder()
	a.saveSite(rec2, testJSONRequest("PUT", "/api/sites/"+strconv.FormatInt(created.ID, 10), `{"name":"s","domain":"s.local","upstream":"http://127.0.0.1:8081","enabled":true,"waf_mode":"balanced","auth_user":"u","auth_pass":"","dynamic_mode":"off"}`), created.ID)
	if rec2.Code != 200 {
		t.Fatalf("更新失败 %d %s", rec2.Code, rec2.Body.String())
	}
	got2, _ := a.Store.GetSite(created.ID)
	if got2.AuthPass != got.AuthPass {
		t.Fatal("留空更新应保留原口令哈希")
	}
	// 更新新口令：重新哈希
	rec3 := httptest.NewRecorder()
	a.saveSite(rec3, testJSONRequest("PUT", "/api/sites/"+strconv.FormatInt(created.ID, 10), `{"name":"s","domain":"s.local","upstream":"http://127.0.0.1:8081","enabled":true,"waf_mode":"balanced","auth_user":"u","auth_pass":"newpw123","dynamic_mode":"off"}`), created.ID)
	if rec3.Code != 200 {
		t.Fatalf("更新新口令失败 %d %s", rec3.Code, rec3.Body.String())
	}
	got3, _ := a.Store.GetSite(created.ID)
	if ok, _ := store.VerifyPass("newpw123", got3.AuthPass); !ok {
		t.Fatal("新口令应生效")
	}
	if got3.AuthPass == got.AuthPass {
		t.Fatal("新口令应产生新哈希")
	}
}

func TestBackupAPI(t *testing.T) {
	a := fullTestAPI(t)
	rec := httptest.NewRecorder()
	a.backup(rec, httptest.NewRequest("POST", "/api/backup", nil))
	if rec.Code != 200 {
		t.Fatalf("备份应成功, got %d %s", rec.Code, rec.Body.String())
	}
	var res map[string]string
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["name"] == "" {
		t.Fatal("备份应返回文件名")
	}
	rec2 := httptest.NewRecorder()
	a.listBackups(rec2, httptest.NewRequest("GET", "/api/backups", nil))
	if rec2.Code != 200 || !strings.Contains(rec2.Body.String(), res["name"]) {
		t.Fatalf("备份列表应含刚生成的备份: %s", rec2.Body.String())
	}
}
