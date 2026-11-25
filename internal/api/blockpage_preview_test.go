package api

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBlockPagePreviewUsesIsolatedDocument(t *testing.T) {
	a := hardenAPI(t)
	h := a.Handler(http.NotFoundHandler())
	path := "/api/block-page/preview"
	anon := httptest.NewRecorder()
	h.ServeHTTP(anon, testJSONRequest(http.MethodPost, path, `{}`))
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous preview returned %d", anon.Code)
	}
	request := adminJSONRequests(t, a)
	template := `<!doctype html><html lang="zh-CN"><head><meta http-equiv="refresh" content="1"><style>body{color:#246}</style></head><body style="margin:0"><p>{{REQ_ID}}</p><a href="https://example.test">文档</a><script>console.log('preview')</script></body></html>`
	rec := request(http.MethodPost, path, map[string]string{"template": template})
	var result map[string]string
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
		t.Fatalf("invalid custom preview response: %d", rec.Code)
	}
	page := html.UnescapeString(result["html"])
	for _, want := range []string{blockPreviewPolicy, `lang="zh-CN"`, `<body style="margin:0">`, `body{color:#246}`, `7f2c4d91a638`} {
		if !strings.Contains(page, want) {
			t.Errorf("preview omitted %q", want)
		}
	}
	for _, unwanted := range []string{`<script`, `href=`, `http-equiv="refresh"`, `{{REQ_ID}}`} {
		if strings.Contains(page, unwanted) {
			t.Errorf("preview contains %q", unwanted)
		}
	}
	if a.Store.GetSetting("block_page") != "" {
		t.Fatal("preview saved the draft")
	}
	rec = request(http.MethodGet, path, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || !strings.Contains(rec.Body.String(), `id="block-title"`) {
		t.Fatal("default preview stopped working")
	}
}
