package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const auditFeedHashKey = "audit_feed_hash"

var auditTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{24,256}$`)

func (a *API) auditFeedSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]bool{"enabled": a.Store.GetSetting(auditFeedHashKey) != ""})
		return
	}
	var body struct{ Token string }
	if !decodeJSON(w, r, &body, loginBodyLimit) {
		return
	}
	value := ""
	if body.Token != "" {
		if !auditTokenPattern.MatchString(body.Token) {
			writeErr(w, http.StatusBadRequest, "采集令牌须为 24–256 位字母、数字、下划线或连字符")
			return
		}
		digest := sha256.Sum256([]byte(body.Token))
		value = hex.EncodeToString(digest[:])
	}
	if err := a.Store.SetSetting(auditFeedHashKey, value); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存审计采集设置失败")
		return
	}
	detail := "停用"
	if value != "" {
		detail = "启用或轮换采集令牌"
	}
	a.audit(r, "更新审计采集设置", detail)
	writeJSON(w, map[string]bool{"enabled": value != ""})
}

func (a *API) auditFeed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	expected, err := hex.DecodeString(a.Store.GetSetting(auditFeedHashKey))
	if err != nil || len(expected) != sha256.Size {
		writeErr(w, http.StatusNotFound, "审计采集未启用")
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	got := sha256.Sum256([]byte(token))
	if !ok || subtle.ConstantTimeCompare(expected, got[:]) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeErr(w, http.StatusUnauthorized, "审计采集令牌无效")
		return
	}
	var after int64
	if value := r.URL.Query().Get("after_id"); value != "" {
		after, err = strconv.ParseInt(value, 10, 64)
		if err != nil || after < 0 {
			writeErr(w, http.StatusBadRequest, "after_id 须为非负整数")
			return
		}
	}
	limit := 200
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 1000 {
			writeErr(w, http.StatusBadRequest, "limit 须在 1–1000 之间")
			return
		}
	}
	entries, err := a.Store.AuditAfter(after, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取审计日志失败")
		return
	}
	if len(entries) > 0 {
		after = entries[len(entries)-1].ID
	}
	w.Header().Set("X-NiuB-Audit-Next-ID", strconv.FormatInt(after, 10))
	w.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(w)
	for _, item := range entries {
		if item.Action == "新增站点" {
			item.Detail, _, _ = strings.Cut(item.Detail, " -> ")
		}
		if err := encoder.Encode(item); err != nil {
			return
		}
	}
}
