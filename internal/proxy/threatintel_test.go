package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"niubwaf/internal/store"
)

func TestParseThreatJSONTopLevel(t *testing.T) {
	body := []byte(`{"proxy":true,"vpn":false,"tor":true,"botnet":true,"tags":["Scanner"," spam "],"threat_score":80}`)
	r := parseThreatJSON(body, "generic")
	want := []string{"botnet", "proxy", "scanner", "spam", "tor"}
	if !reflect.DeepEqual(r.Tags, want) {
		t.Fatalf("tags = %v, want %v", r.Tags, want)
	}
	if r.Score != 80 || r.Provider != "generic" {
		t.Fatalf("score/provider = %d/%s", r.Score, r.Provider)
	}
}

func TestParseThreatJSONNested(t *testing.T) {
	for _, nest := range []string{"security", "threat", "data", "result"} {
		body := []byte(`{"` + nest + `":{"malicious":true,"hosting":true,"risk_score":55}}`)
		r := parseThreatJSON(body, "generic")
		if !reflect.DeepEqual(r.Tags, []string{"hosting", "malicious"}) {
			t.Fatalf("%s: tags = %v", nest, r.Tags)
		}
		if r.Score != 55 {
			t.Fatalf("%s: score = %d", nest, r.Score)
		}
	}
}

func TestParseThreatJSONFractionalScore(t *testing.T) {
	r := parseThreatJSON([]byte(`{"risk":0.72}`), "generic")
	if r.Score != 72 {
		t.Fatalf("fractional score = %d, want 72", r.Score)
	}
}

func TestParseThreatJSONScoreClamp(t *testing.T) {
	if r := parseThreatJSON([]byte(`{"score":999}`), "generic"); r.Score != 100 {
		t.Fatalf("clamp high = %d", r.Score)
	}
	if r := parseThreatJSON([]byte(`{"score":-5}`), "generic"); r.Score != 0 {
		t.Fatalf("clamp low = %d", r.Score)
	}
}

func TestParseThreatJSONMaxScoreAcrossKeys(t *testing.T) {
	r := parseThreatJSON([]byte(`{"score":10,"threat_score":90,"risk_score":40}`), "generic")
	if r.Score != 90 {
		t.Fatalf("max score = %d, want 90", r.Score)
	}
}

func TestParseThreatJSONInvalid(t *testing.T) {
	r := parseThreatJSON([]byte(`not json`), "generic")
	if len(r.Tags) != 0 || r.Score != 0 || r.Provider != "generic" {
		t.Fatalf("invalid json should yield empty result, got %+v", r)
	}
}

func TestParseThreatJSONDedupSort(t *testing.T) {
	r := parseThreatJSON([]byte(`{"tor":true,"tags":["tor","TOR","Botnet","botnet"]}`), "generic")
	if !reflect.DeepEqual(r.Tags, []string{"botnet", "tor"}) {
		t.Fatalf("dedup/sort = %v", r.Tags)
	}
}

func threatTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "threat.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestGenericProviderLookup(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"proxy":true,"threat_score":66}`))
	}))
	defer srv.Close()
	g := &genericProvider{name: "generic", key: "secret-key", url: srv.URL + "/ip/{ip}", client: srv.Client()}
	r, err := g.Lookup("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/ip/1.2.3.4" {
		t.Fatalf("ip not substituted: %s", gotPath)
	}
	if gotAuth != "Bearer secret-key" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if !reflect.DeepEqual(r.Tags, []string{"proxy"}) || r.Score != 66 {
		t.Fatalf("result = %+v", r)
	}
}

func TestGenericProviderHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	g := &genericProvider{name: "generic", key: "k", url: srv.URL + "/{ip}", client: srv.Client()}
	if _, err := g.Lookup("9.9.9.9"); err == nil {
		t.Fatal("expected error on non-200")
	}
}

func TestThreatIntelOffByDefault(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"proxy":true}`))
	}))
	defer srv.Close()
	st := threatTestStore(t)
	ti := NewThreatIntel(st)
	if ti.Enabled() {
		t.Fatal("should be off with no config")
	}
	if r := ti.Lookup("1.2.3.4"); len(r.Tags) != 0 || r.Provider != "" {
		t.Fatalf("off lookup should be empty, got %+v", r)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("off mode must make zero network calls")
	}
}

func TestThreatIntelEnabledRequiresKeyAndURL(t *testing.T) {
	st := threatTestStore(t)
	ti := NewThreatIntel(st)
	st.SetSetting("intel_provider", "generic")
	if ti.Enabled() {
		t.Fatal("missing key/url should stay disabled")
	}
	st.SetSetting("intel_api_key", "k")
	if ti.Enabled() {
		t.Fatal("missing url should stay disabled")
	}
	st.SetSetting("intel_api_url", "http://x/{ip}")
	if !ti.Enabled() {
		t.Fatal("provider+key+url should enable")
	}
}

func TestThreatIntelLookupCaches(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"botnet":true,"score":70}`))
	}))
	defer srv.Close()
	st := threatTestStore(t)
	st.SetSetting("intel_provider", "generic")
	st.SetSetting("intel_api_key", "k")
	st.SetSetting("intel_api_url", srv.URL+"/{ip}")
	ti := NewThreatIntel(st)
	ti.client = srv.Client()

	r1 := ti.Lookup("5.6.7.8")
	if !reflect.DeepEqual(r1.Tags, []string{"botnet"}) || r1.Score != 70 || r1.Provider != "generic" {
		t.Fatalf("first lookup = %+v", r1)
	}
	r2 := ti.Lookup("5.6.7.8")
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("cached result differs: %+v vs %+v", r1, r2)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 upstream hit (cached), got %d", hits)
	}
	if st := ti.Status(); st["cache_size"].(int) != 1 || st["enabled"].(bool) != true {
		t.Fatalf("status = %+v", st)
	}
}

func TestThreatIntelErrorShortCache(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	st := threatTestStore(t)
	st.SetSetting("intel_provider", "generic")
	st.SetSetting("intel_api_key", "k")
	st.SetSetting("intel_api_url", srv.URL+"/{ip}")
	ti := NewThreatIntel(st)
	ti.client = srv.Client()

	r := ti.Lookup("8.8.8.8")
	if len(r.Tags) != 0 || r.Provider != "generic" {
		t.Fatalf("error lookup should be empty with provider, got %+v", r)
	}
	ti.Lookup("8.8.8.8")
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("error should be short-cached, got %d hits", hits)
	}
}

func TestThreatIntelNilSafe(t *testing.T) {
	var ti *ThreatIntel
	if ti.Enabled() {
		t.Fatal("nil should be disabled")
	}
	p, k, u := ti.config()
	if p != "off" || k != "" || u != "" {
		t.Fatalf("nil config = %s/%s/%s", p, k, u)
	}
}