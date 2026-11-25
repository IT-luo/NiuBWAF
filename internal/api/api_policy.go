package api

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"niubwaf/internal/apispec"
	"niubwaf/internal/store"
)

func (a *API) siteAPIPolicy(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/sites/"), "/api-policy")
	siteID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || siteID <= 0 {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	site, err := a.Store.GetSite(siteID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "站点不存在")
		} else {
			writeErr(w, http.StatusInternalServerError, "读取站点失败")
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		config, err := a.Store.APIPolicy(siteID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取 API 契约失败")
			return
		}
		a.writeAPIPolicy(w, r, config)
	case http.MethodPut:
		var config store.APIPolicy
		if !decodeJSON(w, r, &config, jsonBodyLimit) {
			return
		}
		config.Prefix = strings.TrimSpace(config.Prefix)
		compiled, err := apispec.Compile(r.Context(), config.Mode, config.Prefix, config.Document)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := a.Store.SetAPIPolicy(siteID, config); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeErr(w, http.StatusNotFound, "站点不存在")
			} else {
				writeErr(w, http.StatusInternalServerError, "保存 API 契约失败")
			}
			return
		}
		a.audit(r, "修改 API 契约", fmt.Sprintf("%s %s %s", site.Domain, config.Mode, config.Prefix))
		a.Proxy.Reload()
		writeJSON(w, apiPolicyResponse{config, compiled.Endpoints})
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeErr(w, http.StatusMethodNotAllowed, "请求方法不受支持")
	}
}

type apiPolicyResponse struct {
	store.APIPolicy
	Endpoints []apispec.Endpoint `json:"endpoints"`
}

func (a *API) writeAPIPolicy(w http.ResponseWriter, r *http.Request, config store.APIPolicy) {
	policy, err := apispec.Compile(r.Context(), config.Mode, config.Prefix, config.Document)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "已存 API 契约无法载入")
		return
	}
	writeJSON(w, apiPolicyResponse{config, policy.Endpoints})
}
