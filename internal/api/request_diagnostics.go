package api

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"niubwaf/internal/proxy"
)

var requestDiagnosticID = regexp.MustCompile(`^[0-9a-f]{12}$`)

func (a *API) requestDiagnostics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("id")))
	if !requestDiagnosticID.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "请求 ID 应为 12 位十六进制字符")
		return
	}
	if a.Proxy != nil {
		if d, found := a.Proxy.FindRequestDiagnostic(id); found {
			writeJSON(w, d)
			return
		}
	}

	d, err := a.historicalRequestDiagnostic(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "未找到该请求。近期诊断仅保留在接收请求的节点内存中，过期或服务重启后只可查询留存的防护事件")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取请求诊断失败")
		return
	}
	writeJSON(w, d)
}

func (a *API) historicalRequestDiagnostic(r *http.Request, id string) (proxy.RequestDiagnostic, error) {
	d := proxy.RequestDiagnostic{ReqID: id, Historical: true, Source: "waf"}
	var ts string
	var challenged bool
	err := a.Store.DB.QueryRowContext(r.Context(), `SELECT COALESCE(ts,''), COALESCE(domain,''), COALESCE(method,''),
		COALESCE(action,''), COALESCE(rule_id,0), COALESCE(status,0),
		COALESCE(msg LIKE '%触发人机验证%', 0)
		FROM attack_logs WHERE req_id=? ORDER BY CASE WHEN status=200 THEN 1 ELSE 0 END, id DESC LIMIT 1`, id).
		Scan(&ts, &d.Domain, &d.Method, &d.Module, &d.RuleID, &d.Status, &challenged)
	if err != nil {
		return d, err
	}
	d.TS, _ = time.ParseInLocation(time.DateTime, ts, time.Local)
	d.Outcome = "blocked"
	d.Reason = proxy.DiagnosticRuleReason(d.Module, d.Status)
	switch {
	case d.Status == http.StatusOK:
		d.Source, d.Outcome, d.Status = "unknown", "observed", 0
		d.Reason = "仅留存规则观察事件，最终响应和回源状态没有记录"
		d.Observations = []proxy.DiagnosticObservation{{Module: d.Module, RuleID: d.RuleID}}
		d.Module, d.RuleID = "", 0
	case d.Status >= 300 && d.Status < 400:
		d.Outcome = "redirected"
	case d.Status == http.StatusTooManyRequests && challenged:
		d.Outcome = "challenged"
	case d.Status == 0:
		d.Source, d.Outcome = "unknown", "unknown"
	}
	if d.Module == "resp" {
		d.UpstreamAttempted = true
	}
	return d, nil
}
