package api

import (
	"net/http"
	"strconv"

	"niubwaf/internal/certmgr"
)

func (a *API) managedCertificates(w http.ResponseWriter, r *http.Request) {
	m := a.Certificates
	if m == nil {
		writeErr(w, http.StatusServiceUnavailable, "托管证书模块不可用")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/api/certificates" && r.Method == http.MethodGet:
		accounts, err := m.Accounts()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取 DNS 账号失败")
			return
		}
		certs, err := m.Certificates()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取证书列表失败")
			return
		}
		bindings, err := m.Bindings()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取证书绑定失败")
			return
		}
		writeJSON(w, map[string]any{"accounts": accounts, "certificates": certs, "bindings": bindings})
	case r.URL.Path == "/api/certificates/accounts" && r.Method == http.MethodPut:
		var input struct {
			certmgr.Account
			Key    string `json:"key"`
			Secret string `json:"secret"`
		}
		if !decodeJSON(w, r, &input, 32<<10) {
			return
		}
		if err := m.SaveAccount(input.Account, input.Key, input.Secret); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "保存 DNS 证书账号", input.Name)
		writeJSON(w, map[string]bool{"ok": true})
	case r.URL.Path == "/api/certificates" && r.Method == http.MethodPost:
		var input struct {
			certmgr.Certificate
			AcceptTerms bool `json:"accept_terms"`
		}
		if !decodeJSON(w, r, &input, 32<<10) {
			return
		}
		if !input.AcceptTerms {
			writeErr(w, http.StatusBadRequest, "申请前需同意 Let's Encrypt 服务协议")
			return
		}
		if err := m.Queue(input.Certificate); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "加入 DNS 证书签发队列", strconv.FormatInt(input.AccountID, 10))
		w.WriteHeader(http.StatusAccepted)
	case r.URL.Path == "/api/certificates/retry" && r.Method == http.MethodPost:
		var input struct {
			ID int64 `json:"id"`
		}
		if !decodeJSON(w, r, &input, 4096) {
			return
		}
		if err := m.Retry(input.ID); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		a.audit(r, "重新签发托管证书", strconv.FormatInt(input.ID, 10))
		w.WriteHeader(http.StatusAccepted)
	case r.URL.Path == "/api/certificates/binding" && r.Method == http.MethodPut:
		var input certmgr.Binding
		if !decodeJSON(w, r, &input, 4096) {
			return
		}
		if input.SiteID <= 0 || input.CertificateID < 0 {
			writeErr(w, http.StatusBadRequest, "站点或证书编号无效")
			return
		}
		if err := m.Bind(input.SiteID, input.CertificateID); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "更新站点托管证书绑定", strconv.FormatInt(input.SiteID, 10))
		writeJSON(w, map[string]bool{"ok": true})
	default:
		http.NotFound(w, r)
	}
}
