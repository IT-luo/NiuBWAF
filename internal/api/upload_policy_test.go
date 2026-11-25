package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"niubwaf/internal/store"
)

func TestAdminUploadPolicyLifecycle(t *testing.T) {
	a := fullTestAPI(t)
	request := adminJSONRequests(t, a)
	site := store.Site{Domain: "upload.test", Name: "Uploads", Upstream: "http://127.0.0.1:1", Enabled: true}
	if err := a.Store.CreateSite(&site); err != nil {
		t.Fatal(err)
	}
	path := "/api/sites/" + strconv.FormatInt(site.ID, 10) + "/upload-policy"
	if permitConsoleRequest(roleOperator, http.MethodPut, path) || permitConsoleRequest(roleViewer, http.MethodGet, path) {
		t.Fatal("upload policies must be restricted to administrators")
	}
	policy := store.UploadPolicy{Method: http.MethodPost, Path: "/api/upload", MaxBodyMiB: 64, MaxConcurrent: 2}
	set := func(policies []store.UploadPolicy, want int) {
		t.Helper()
		rec := request(http.MethodPut, path, map[string]any{"policies": policies})
		if rec.Code != want {
			t.Fatalf("policy save got %d, want %d: %s", rec.Code, want, rec.Body)
		}
	}
	set([]store.UploadPolicy{policy}, http.StatusOK)
	set([]store.UploadPolicy{policy, policy}, http.StatusBadRequest)
	set(nil, http.StatusBadRequest)
	bad := policy
	bad.Path = "/api/*"
	set([]store.UploadPolicy{bad}, http.StatusBadRequest)
	bad = policy
	bad.MaxBodyMiB = 65
	set([]store.UploadPolicy{bad}, http.StatusBadRequest)
	rec := request(http.MethodGet, path, nil)
	var response struct{ Policies []store.UploadPolicy }
	if err := json.Unmarshal(rec.Body.Bytes(), &response); rec.Code != 200 || err != nil || len(response.Policies) != 1 || response.Policies[0] != policy {
		t.Fatalf("persisted policy response unexpected: %d %s", rec.Code, rec.Body)
	}
	set([]store.UploadPolicy{}, http.StatusOK)
	if saved, err := a.Store.UploadPolicies(site.ID); err != nil || len(saved) != 0 {
		t.Fatalf("cleared policy still exists: %v %v", saved, err)
	}
	set([]store.UploadPolicy{policy}, http.StatusOK)
	if err := a.Store.DeleteSite(site.ID); err != nil {
		t.Fatal(err)
	}
	if saved, err := a.Store.UploadPolicies(site.ID); err != nil || len(saved) != 0 {
		t.Fatalf("deleting site left policies: %v %v", saved, err)
	}
}
