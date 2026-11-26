package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"niubwaf/internal/store"
)

const (
	rootAccount  = "admin"
	roleAdmin    = "admin"
	roleOperator = "operator"
	roleViewer   = "viewer"
)

type consoleIdentity struct {
	Username   string `json:"username"`
	Role       string `json:"role"`
	MustChange bool   `json:"must_change"`
}

type consoleContextKey struct{}

func consoleUser(r *http.Request) consoleIdentity {
	if identity, ok := r.Context().Value(consoleContextKey{}).(consoleIdentity); ok {
		return identity
	}
	return consoleIdentity{Username: rootAccount, Role: roleAdmin}
}

func withConsoleUser(r *http.Request, identity consoleIdentity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), consoleContextKey{}, identity))
}

func (a *API) audit(r *http.Request, action, detail string) {
	a.Store.Audit(consoleUser(r).Username, action, detail)
}

func (a *API) lookupConsoleAccount(name string) (store.ConsoleAccount, error) {
	if name == rootAccount {
		return store.ConsoleAccount{
			Username: name, Role: roleAdmin, Enabled: true,
			PasswordHash: a.Store.GetSetting("admin_pass"),
			MustChange:   a.Store.GetSetting("must_change_pass") == "on",
		}, nil
	}
	return a.Store.ConsoleAccount(name)
}

func permitConsoleRequest(role, method, path string) bool {
	if role == roleAdmin {
		return true
	}
	if role != roleOperator && role != roleViewer {
		return false
	}
	if method == http.MethodGet {
		switch path {
		case "/api/me", "/api/csrf", "/api/stats", "/api/trend", "/api/analytics", "/api/qps",
			"/api/top/ips", "/api/top/rules", "/api/top/countries", "/api/top/domains", "/api/logs",
			"/api/logs/export", "/api/ips", "/api/exclusions", "/api/events", "/api/rules",
			"/api/rules/shadow", "/api/sites", "/api/upstreams", "/api/request-diagnostics":
			return true
		}
		if strings.HasPrefix(path, "/api/sites/") && strings.HasSuffix(path, "/ingress-verification") {
			return true
		}
		return role == roleOperator && strings.HasPrefix(path, "/api/sites/") && strings.HasSuffix(path, "/api-policy")
	}
	if method == http.MethodPut && path == "/api/password" {
		return true
	}
	if role != roleOperator {
		return false
	}
	switch method {
	case http.MethodPost:
		return path == "/api/rules" || path == "/api/rules/replay" || path == "/api/exclusions" || path == "/api/ips"
	case http.MethodPut:
		return strings.HasPrefix(path, "/api/rules/") ||
			(strings.HasPrefix(path, "/api/sites/") && strings.HasSuffix(path, "/api-policy"))
	case http.MethodDelete:
		return strings.HasPrefix(path, "/api/rules/") || strings.HasPrefix(path, "/api/exclusions/") || strings.HasPrefix(path, "/api/ips/")
	default:
		return false
	}
}

var accountName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,47}$`)

func validConsoleRole(role string) bool {
	return role == roleAdmin || role == roleOperator || role == roleViewer
}

func validConsolePassword(pass string) bool {
	return len(pass) >= 8 && len(pass) <= 256 && pass != "admin123" &&
		strings.ContainsAny(pass, "0123456789") &&
		strings.ContainsAny(pass, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func (a *API) listOrCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		users, err := a.Store.ConsoleAccounts()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取账号失败")
			return
		}
		writeJSON(w, users)
		return
	}
	var input struct{ Username, Role, Password string }
	if !decodeJSON(w, r, &input, loginBodyLimit) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(input.Username))
	if !accountName.MatchString(name) || name == rootAccount || !validConsoleRole(input.Role) || !validConsolePassword(input.Password) {
		writeErr(w, http.StatusBadRequest, "账号名、角色或临时密码无效")
		return
	}
	user := store.ConsoleAccount{Username: name, Role: input.Role, PasswordHash: store.HashPass(input.Password), Enabled: true, MustChange: true}
	a.accountMu.Lock()
	defer a.accountMu.Unlock()
	if _, err := a.Store.ConsoleAccount(name); !errors.Is(err, sql.ErrNoRows) {
		if err == nil {
			writeErr(w, http.StatusConflict, "账号已存在")
		} else {
			writeErr(w, http.StatusInternalServerError, "读取账号失败")
		}
		return
	}
	if err := a.Store.CreateConsoleAccount(user); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建账号失败")
		return
	}
	a.audit(r, "创建控制台账号", name+" "+user.Role)
	writeJSON(w, user)
}

func (a *API) updateConsoleAccount(w http.ResponseWriter, r *http.Request, name string) {
	if !accountName.MatchString(name) || name == rootAccount || name == consoleUser(r).Username {
		writeErr(w, http.StatusBadRequest, "该账号不可从账号管理页修改或删除")
		return
	}
	var input struct {
		Role, Password string
		Enabled        *bool
	}
	if r.Method == http.MethodPut && !decodeJSON(w, r, &input, loginBodyLimit) {
		return
	}
	var passwordHash string
	if input.Password != "" {
		if !validConsolePassword(input.Password) {
			writeErr(w, http.StatusBadRequest, "临时密码须为 8–256 字节并含字母和数字")
			return
		}
		passwordHash = store.HashPass(input.Password)
	}
	a.accountMu.Lock()
	defer a.accountMu.Unlock()
	user, err := a.Store.ConsoleAccount(name)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "账号不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取账号失败")
		return
	}
	if r.Method == http.MethodDelete {
		if err := a.Store.DeleteConsoleAccount(name); err != nil {
			writeErr(w, http.StatusInternalServerError, "删除账号失败")
			return
		}
		a.revokeConsoleSessions(name)
		a.audit(r, "删除控制台账号", name)
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	if input.Role != "" {
		if !validConsoleRole(input.Role) {
			writeErr(w, http.StatusBadRequest, "角色无效")
			return
		}
		user.Role = input.Role
	}
	if input.Enabled != nil {
		user.Enabled = *input.Enabled
	}
	if passwordHash != "" {
		user.PasswordHash = passwordHash
		user.MustChange = true
	}
	if err := a.Store.UpdateConsoleAccount(user); err != nil {
		writeErr(w, http.StatusInternalServerError, "更新账号失败")
		return
	}
	a.revokeConsoleSessions(name)
	a.audit(r, "更新控制台账号", name+" "+user.Role)
	writeJSON(w, user)
}
