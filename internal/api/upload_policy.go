package api

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"niubwaf/internal/engine"
	"niubwaf/internal/store"
)

func (a *API) siteUploadPolicy(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/sites/"), "/upload-policy")
	siteID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || siteID <= 0 {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	site, err := a.Store.GetSite(siteID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取站点失败")
		return
	}
	switch r.Method {
	case http.MethodGet:
		policies, err := a.Store.UploadPolicies(siteID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取上传策略失败")
			return
		}
		writeJSON(w, map[string]any{
			"policies": policies, "max_policies": store.MaxSiteUploadPolicies,
			"max_body_mib": engine.MaxUploadBodyMiB, "max_concurrent": store.MaxUploadConcurrency,
		})
	case http.MethodPut:
		var input struct {
			Policies *[]store.UploadPolicy `json:"policies"`
		}
		if !decodeJSON(w, r, &input, loginBodyLimit) {
			return
		}
		if input.Policies == nil {
			writeErr(w, http.StatusBadRequest, "请提供上传策略列表")
			return
		}
		policies := *input.Policies
		if err := store.ValidateUploadPolicies(policies); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := a.Store.SetUploadPolicies(siteID, policies); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeErr(w, http.StatusNotFound, "站点不存在")
			} else {
				writeErr(w, http.StatusInternalServerError, "保存上传策略失败")
			}
			return
		}
		a.audit(r, "修改上传策略", fmt.Sprintf("%s count=%d", site.Domain, len(policies)))
		a.Proxy.Reload()
		writeJSON(w, map[string]string{"ok": "true"})
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeErr(w, http.StatusMethodNotAllowed, "请求方法不受支持")
	}
}
