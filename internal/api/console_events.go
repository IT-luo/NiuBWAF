package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// eventSession verifies the session at subscription time. Local sessions also
// have a revocation channel. Shared sessions are checked against the database
// before each event or heartbeat.
func (a *API) eventSession(r *http.Request) (<-chan struct{}, time.Time, bool) {
	cookie, err := r.Cookie("niub_admin")
	if err != nil {
		return nil, time.Time{}, false
	}
	if a.ConsoleSessionScope != "" {
		session, err := a.Store.ConsoleSession(a.ConsoleSessionScope, cookie.Value)
		return nil, session.Expires, err == nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[cookie.Value]
	if !ok || !time.Now().Before(expires) {
		a.deleteSessionLocked(cookie.Value)
		return nil, time.Time{}, false
	}
	if a.eventDone == nil {
		a.eventDone = make(map[string]chan struct{})
	}
	done := a.eventDone[cookie.Value]
	if done == nil {
		done = make(chan struct{})
		a.eventDone[cookie.Value] = done
	}
	return done, expires, true
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		writeErr(w, http.StatusInternalServerError, "不支持 SSE")
		return
	}
	revoked, expires, ok := a.eventSession(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "会话已过期或撤销")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	defer controller.SetWriteDeadline(time.Time{})
	send := func(format string, args ...any) bool {
		select {
		case <-revoked:
			return false
		case <-r.Context().Done():
			return false
		default:
		}
		now := time.Now()
		if !now.Before(expires) {
			return false
		}
		if a.ConsoleSessionScope != "" && !a.authed(r) {
			return false
		}
		deadline := now.Add(5 * time.Second)
		if expires.Before(deadline) {
			deadline = expires
		}
		if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		_, err := fmt.Fprintf(w, format, args...)
		return err == nil && controller.Flush() == nil
	}
	ch := a.Proxy.Hub.Subscribe()
	defer a.Proxy.Hub.Unsubscribe(ch)
	if !send("data: {\"type\":\"hello\"}\n\n") {
		return
	}
	expiry := time.NewTimer(time.Until(expires))
	defer expiry.Stop()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-revoked:
			return
		case <-expiry.C:
			return
		case <-r.Context().Done():
			return
		case data := <-ch:
			if !send("data: %s\n\n", data) {
				return
			}
		case <-ping.C:
			if !send(": ping\n\n") {
				return
			}
		}
	}
}
