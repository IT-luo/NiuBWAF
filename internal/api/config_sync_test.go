package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"niubwaf/internal/store"
)

func TestConfigSyncAPIExportPreviewApply(t *testing.T) {
	source := hardenAPI(t)
	target := fullTestAPI(t)
	for k, v := range map[string]string{"admin_pass": "API_CANARY_ADMIN", "cookie_secret": "API_CANARY_COOKIE", "metrics_token": "API_CANARY_METRICS", "intel_api_key": "API_CANARY_INTEL"} {
		if err := source.Store.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	site := store.Site{Name: "api", Domain: "api-sync.test", Upstream: "http://127.0.0.1:65534", Enabled: true, WAFMode: "balanced", AuthPass: "API_CANARY_AUTH", CertPEM: "API_CANARY_CERT", KeyPEM: "API_CANARY_KEY"}
	if err := source.Store.CreateSite(&site); err != nil {
		t.Fatal(err)
	}
	if err := source.Store.SetSetting("body_scan_kb", "64"); err != nil {
		t.Fatal(err)
	}
	if err := source.Store.SetSetting("rep_threshold", "42"); err != nil {
		t.Fatal(err)
	}

	exportRec := httptest.NewRecorder()
	source.exportConfig(exportRec, testJSONRequest("POST", "/api/config/export", `{"source_label":"node-a"}`))
	if exportRec.Code != 200 {
		t.Fatalf("导出失败: %d %s", exportRec.Code, exportRec.Body.String())
	}
	if got := exportRec.Header().Get("Content-Disposition"); !strings.Contains(got, "niubwaf-config.json") {
		t.Fatalf("导出应提供固定安全文件名: %q", got)
	}
	for _, canary := range []string{"API_CANARY_ADMIN", "API_CANARY_COOKIE", "API_CANARY_METRICS", "API_CANARY_INTEL", "API_CANARY_AUTH", "API_CANARY_CERT", "API_CANARY_KEY"} {
		if strings.Contains(exportRec.Body.String(), canary) {
			t.Fatalf("API 导出泄露 %s", canary)
		}
	}
	var pkg store.ConfigPackage
	if err := json.Unmarshal(exportRec.Body.Bytes(), &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.Kind != store.ConfigKind || pkg.FormatVersion != 1 || pkg.SourceLabel != "node-a" {
		t.Fatalf("包元数据异常: %+v", pkg)
	}

	previewRec := httptest.NewRecorder()
	target.previewConfigImport(previewRec, testJSONRequest("POST", "/api/config/import/preview", mustConfigSyncJSON(t, configImportPreviewRequest{Package: pkg, Mode: "merge"})))
	if previewRec.Code != 200 {
		t.Fatalf("预览失败: %d %s", previewRec.Code, previewRec.Body.String())
	}
	var preview store.ConfigImportPreview
	if err := json.Unmarshal(previewRec.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.PackageSHA256 == "" || preview.TargetSHA256 == "" || preview.PreviewSHA256 == "" || preview.Stats["sites"].Create != 1 {
		t.Fatalf("预览摘要/统计异常: %+v", preview)
	}

	applyRec := httptest.NewRecorder()
	applyReq := configImportApplyRequest{Package: pkg, Mode: "merge", PackageSHA256: preview.PackageSHA256, TargetSHA256: preview.TargetSHA256, PreviewSHA256: preview.PreviewSHA256}
	target.applyConfigImport(applyRec, testJSONRequest("POST", "/api/config/import/apply", mustConfigSyncJSON(t, applyReq)))
	if applyRec.Code != 200 {
		t.Fatalf("应用失败: %d %s", applyRec.Code, applyRec.Body.String())
	}
	var response configImportApplyResponse
	if err := json.Unmarshal(applyRec.Body.Bytes(), &response); err != nil || !response.OK {
		t.Fatalf("应用响应异常: %s err=%v", applyRec.Body.String(), err)
	}
	if got := target.Store.GetSetting("body_scan_kb"); got != "64" {
		t.Fatalf("apply 后 settings 缓存未刷新: %q", got)
	}
	if got := target.Proxy.Engine.ScanLimit(); got != 64<<10 {
		t.Fatalf("apply 后 Proxy.Reload 未应用扫描上限: %d", got)
	}
	sites, err := target.Store.ListSites()
	if err != nil || len(sites) != 1 || sites[0].Domain != "api-sync.test" {
		t.Fatalf("apply 后站点异常: %+v err=%v", sites, err)
	}
}

func TestConfigSyncAPIConflictAndUnknownFields(t *testing.T) {
	source, target := hardenAPI(t), hardenAPI(t)
	if err := source.Store.CreateSite(&store.Site{Name: "api", Domain: "conflict-api.test", Upstream: "http://127.0.0.1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pkg, err := source.Store.ExportConfig("node-a")
	if err != nil {
		t.Fatal(err)
	}
	previewRec := httptest.NewRecorder()
	target.previewConfigImport(previewRec, testJSONRequest("POST", "/api/config/import/preview", mustConfigSyncJSON(t, configImportPreviewRequest{Package: *pkg, Mode: "merge"})))
	if previewRec.Code != 200 {
		t.Fatalf("预览失败: %d %s", previewRec.Code, previewRec.Body.String())
	}
	var preview store.ConfigImportPreview
	if err := json.Unmarshal(previewRec.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if err := target.Store.SetSetting("trusted_proxies", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	applyRec := httptest.NewRecorder()
	target.applyConfigImport(applyRec, testJSONRequest("POST", "/api/config/import/apply", mustConfigSyncJSON(t, configImportApplyRequest{
		Package: *pkg, Mode: "merge", PackageSHA256: preview.PackageSHA256,
		TargetSHA256: preview.TargetSHA256, PreviewSHA256: preview.PreviewSHA256,
	})))
	if applyRec.Code != 409 {
		t.Fatalf("目标变化应返回 409: %d %s", applyRec.Code, applyRec.Body.String())
	}

	var object map[string]any
	raw := mustConfigSyncJSON(t, configImportPreviewRequest{Package: *pkg, Mode: "merge"})
	if err := json.Unmarshal([]byte(raw), &object); err != nil {
		t.Fatal(err)
	}
	object["package"].(map[string]any)["unknown"] = true
	unknownRec := httptest.NewRecorder()
	target.previewConfigImport(unknownRec, testJSONRequest("POST", "/api/config/import/preview", mustConfigSyncJSON(t, object)))
	if unknownRec.Code != 400 {
		t.Fatalf("嵌套包未知字段应返回 400: %d %s", unknownRec.Code, unknownRec.Body.String())
	}
}

func mustConfigSyncJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
