package proxy

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"niubwaf/internal/store"
)

func uploadTestProxy(t *testing.T, origin string) *Proxy {
	t.Helper()
	p := newSecurityTestProxy(t, store.Site{Domain: "uploads.test", Name: "Uploads", Upstream: origin, Enabled: true}, nil)
	policy := store.UploadPolicy{Method: http.MethodPost, Path: "/api/upload", MaxBodyMiB: 2, MaxConcurrent: 1}
	if err := p.Store.SetUploadPolicies(p.sites["uploads.test"].ID, []store.UploadPolicy{policy}); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	return p
}

func multipartUpload(t *testing.T, fileSize int) (string, []byte) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	f, err := w.CreateFormFile("file", "fixture.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(f, strings.NewReader(strings.Repeat("a", fileSize))); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("title", "deployment fixture"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return w.FormDataContentType(), body.Bytes()
}

func TestUploadPolicyScopesAndBounds(t *testing.T) {
	_, empty := multipartUpload(t, 0)
	contentType, body := multipartUpload(t, (2<<20)-len(empty))
	if len(body) != 2<<20 {
		t.Fatalf("fixture length = %d", len(body))
	}
	hits := make(chan int, 3)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(data, body) || r.Header.Get("Expect") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hits <- len(data)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	p := uploadTestProxy(t, origin.URL)
	for _, tc := range []struct {
		method, path string
		chunked      bool
		extra        bool
		want         int
	}{
		{http.MethodPost, "/api/upload?name=fixture", false, false, 204},
		{http.MethodPost, "/api/upload", true, false, 204},
		{http.MethodPost, "/api/upload", false, true, 413},
		{http.MethodPost, "/api/upload", true, true, 413},
		{http.MethodPut, "/api/upload", false, false, 413},
		{http.MethodPost, "/api/upload/other", false, false, 413},
		{http.MethodPost, "/api/%75pload", false, false, 413},
	} {
		data := body
		if tc.extra {
			data = append(bytes.Clone(body), 'x')
		}
		req := httptest.NewRequest(tc.method, "http://uploads.test"+tc.path, bytes.NewReader(data))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Expect", "100-continue")
		if tc.chunked {
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
		}
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %s chunked=%v extra=%v got %d, want %d: %s", tc.method, tc.path, tc.chunked, tc.extra, rec.Code, tc.want, rec.Body.String())
		}
	}
	if len(hits) != 2 {
		t.Fatalf("origin received %d uploads, want 2", len(hits))
	}
}

func TestUploadConcurrencySurvivesReload(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Query().Get("hold") == "1" {
			started <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	p := uploadTestProxy(t, origin.URL)
	contentType, body := multipartUpload(t, 64<<10)
	request := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://uploads.test/api/upload"+query, bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- request("?hold=1") }()
	select {
	case <-started:
	case rec := <-result:
		t.Fatalf("first upload was not forwarded: %d %s", rec.Code, rec.Body)
	case <-time.After(8 * time.Second):
		t.Fatal("first upload did not reach upstream")
	}
	p.Reload()
	if rec := request(""); rec.Code != 503 || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("upload capacity response = %d, Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	close(release)
	if rec := <-result; rec.Code != 204 {
		t.Fatalf("first upload response = %d", rec.Code)
	}
	if rec := request(""); rec.Code != 204 {
		t.Fatalf("upload slot was not released: %d", rec.Code)
	}
}

func TestUploadPolicyAtGlobalScanLimit(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	p := uploadTestProxy(t, origin.URL)
	if err := p.Store.SetSetting("body_scan_kb", "1024"); err != nil {
		t.Fatal(err)
	}
	p.Reload()
	_, empty := multipartUpload(t, 0)
	contentType, body := multipartUpload(t, (1<<20)-len(empty))
	req := httptest.NewRequest(http.MethodPost, "http://uploads.test/api/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("upload at default-engine boundary got %d: %s", rec.Code, rec.Body)
	}
}
