package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"niubwaf/internal/proxy"
)

func (a *API) siteIngressVerification(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/sites/"), "/ingress-verification")
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
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.Proxy.SiteIngressStatus(site.ID, site.Domain))
	case http.MethodPost:
		var input proxy.IngressVerificationOptions
		if !decodeJSON(w, r, &input, loginBodyLimit) {
			return
		}
		result, err := a.Proxy.StartIngressVerification(site.ID, site.Domain, input)
		if errors.Is(err, proxy.ErrIngressSiteUnavailable) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "开始站点接入验收", site.Domain)
		writeJSON(w, result)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeErr(w, http.StatusMethodNotAllowed, "请求方法不受支持")
	}
}
