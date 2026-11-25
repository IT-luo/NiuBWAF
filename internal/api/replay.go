package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"niubwaf/internal/engine"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

const (
	replayDefaultLimit       = 1000
	replayMaxLimit           = 10000
	replayDefaultSampleLimit = 20
	replayMaxSampleLimit     = 100
	replayMaxWindow          = 168 * time.Hour
	replayTimeout            = 10 * time.Second
)

// 容量 1 且非阻塞获取：历史回放是按需管理操作，不排队堆积任务。
var replaySlots = make(chan struct{}, 1)

type replayRuleRequest struct {
	Rule        store.CustomRule `json:"rule"`
	From        string           `json:"from"`
	To          string           `json:"to"`
	Domain      string           `json:"domain"`
	IP          string           `json:"ip"`
	Action      string           `json:"action"`
	Limit       int              `json:"limit"`
	SampleLimit int              `json:"sample_limit"`
}

type replaySample struct {
	Result string          `json:"result"`
	Log    store.AttackLog `json:"log"`
}

type replayRuleResponse struct {
	Source            string         `json:"source"`
	Scope             string         `json:"scope"`
	UnavailableFields []string       `json:"unavailable_fields"`
	From              string         `json:"from"`
	To                string         `json:"to"`
	Domain            string         `json:"domain"`
	IP                string         `json:"ip"`
	Action            string         `json:"action"`
	Scanned           int            `json:"scanned"`
	Matched           int            `json:"matched"`
	NotMatched        int            `json:"not_matched"`
	Indeterminate     int            `json:"indeterminate"`
	Invalid           int            `json:"invalid"`
	Truncated         bool           `json:"truncated"`
	Samples           []replaySample `json:"samples"`
}

func (a *API) listShadowRules(w http.ResponseWriter, r *http.Request) {
	if a.Proxy == nil {
		writeErr(w, http.StatusServiceUnavailable, "代理尚未初始化")
		return
	}
	writeJSON(w, a.Proxy.ShadowSnapshot())
}

func (a *API) replayRule(w http.ResponseWriter, r *http.Request) {
	var req replayRuleRequest
	if !decodeJSON(w, r, &req, jsonBodyLimit) {
		return
	}
	compiled, ok := compileReplayDraft(w, &req.Rule)
	if !ok {
		return
	}
	if req.Rule.SiteID != 0 {
		site, err := a.Store.GetSite(req.Rule.SiteID)
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusBadRequest, "规则所属站点不存在")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// 站点专属规则不能通过 domain 参数越界回放其他站点日志。
		req.Domain = site.Domain
	}

	to := time.Now()
	from := to.Add(-24 * time.Hour)
	var err error
	if strings.TrimSpace(req.To) != "" {
		to, err = parseReplayTime(req.To)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "to 时间格式无效")
			return
		}
		from = to.Add(-24 * time.Hour)
	}
	if strings.TrimSpace(req.From) != "" {
		from, err = parseReplayTime(req.From)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "from 时间格式无效")
			return
		}
	}
	if !from.Before(to) {
		writeErr(w, http.StatusBadRequest, "from 必须早于 to")
		return
	}
	if to.Sub(from) > replayMaxWindow {
		writeErr(w, http.StatusBadRequest, "回放时间范围不能超过 168 小时")
		return
	}
	if req.Limit == 0 {
		req.Limit = replayDefaultLimit
	}
	if req.Limit < 0 || req.Limit > replayMaxLimit {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("limit 需在 1–%d 之间", replayMaxLimit))
		return
	}
	if req.SampleLimit == 0 {
		req.SampleLimit = replayDefaultSampleLimit
	}
	if req.SampleLimit < 0 || req.SampleLimit > replayMaxSampleLimit {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("sample_limit 需在 1–%d 之间", replayMaxSampleLimit))
		return
	}

	select {
	case replaySlots <- struct{}{}:
		defer func() { <-replaySlots }()
	default:
		writeErr(w, http.StatusTooManyRequests, "已有历史回放正在运行，请稍后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), replayTimeout)
	defer cancel()

	resp := replayRuleResponse{
		Source: "attack_logs", Scope: "logged_security_events_only",
		UnavailableFields: []string{"header", "body"},
		From:              from.Format("2006-01-02 15:04:05"), To: to.Format("2006-01-02 15:04:05"),
		Domain: req.Domain, IP: req.IP, Action: req.Action,
		Samples: make([]replaySample, 0),
	}
	query := store.ReplayLogQuery{
		From: resp.From, To: resp.To, SiteID: req.Rule.SiteID, IP: req.IP, Domain: req.Domain,
		Action: req.Action, Limit: req.Limit,
	}
	truncated, err := a.Store.QueryContext(ctx, query, func(l *store.AttackLog) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp.Scanned++
		if l.QueryRedacted && len(resp.UnavailableFields) == 2 {
			resp.UnavailableFields = append(resp.UnavailableFields, "param", "url")
		}
		result := "invalid"
		u, parseErr := url.ParseRequestURI(l.URL)
		if parseErr == nil && u.Path != "" {
			in := &engine.RuleInput{
				ClientIP: l.ClientIP, Method: l.Method, Path: u.Path, URL: l.URL,
				Query: u.Query(), Country: l.Country, QueryRedacted: l.QueryRedacted,
			}
			switch compiled.MatchReplay(in) {
			case engine.MatchTrue:
				result = "matched"
				resp.Matched++
			case engine.MatchUnknown:
				result = "indeterminate"
				resp.Indeterminate++
			default:
				result = "not_matched"
				resp.NotMatched++
			}
		} else {
			resp.Invalid++
		}
		if len(resp.Samples) < req.SampleLimit {
			l.RedactQuery()
			resp.Samples = append(resp.Samples, replaySample{Result: result, Log: *l})
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			writeErr(w, http.StatusGatewayTimeout, "历史回放在 10 秒后已取消")
		case errors.Is(err, context.Canceled):
			writeErr(w, http.StatusRequestTimeout, "历史回放已取消")
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	resp.Truncated = truncated
	writeJSON(w, resp)
}

func compileReplayDraft(w http.ResponseWriter, cr *store.CustomRule) (engine.CompiledRule, bool) {
	cr.Name = strings.TrimSpace(cr.Name)
	cr.Note = strings.TrimSpace(cr.Note)
	cr.ActionParam = strings.TrimSpace(cr.ActionParam)
	if cr.Name == "" {
		writeErr(w, http.StatusBadRequest, "规则名称不能为空")
		return engine.CompiledRule{}, false
	}
	if cr.SiteID < 0 {
		writeErr(w, http.StatusBadRequest, "site_id 无效（0=全局）")
		return engine.CompiledRule{}, false
	}
	if cr.Priority < 0 || cr.Priority > 100000 {
		writeErr(w, http.StatusBadRequest, "priority 需在 0–100000 之间")
		return engine.CompiledRule{}, false
	}
	switch cr.Action {
	case "allow", "block", "captcha", "log", "redirect", engine.RuleActionRateLimit:
	default:
		writeErr(w, http.StatusBadRequest, "action 必须是 allow/block/captcha/log/redirect/rate_limit")
		return engine.CompiledRule{}, false
	}
	if cr.Logic != "and" && cr.Logic != "or" {
		cr.Logic = "and"
	}
	if cr.Action == "redirect" && proxy.SafeRedirect(cr.ActionParam) == "" {
		writeErr(w, http.StatusBadRequest, "重定向地址无效")
		return engine.CompiledRule{}, false
	}
	compiled, err := engine.CompileRule(engine.RuleDef{
		ID: cr.ID, SiteID: cr.SiteID, Name: cr.Name, Priority: cr.Priority,
		Logic: cr.Logic, Conditions: cr.Conditions, Action: cr.Action,
		ActionParam: cr.ActionParam, Shadow: cr.Shadow,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return engine.CompiledRule{}, false
	}
	return compiled, true
}

func parseReplayTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.Local(), nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析时间 %q", raw)
}
