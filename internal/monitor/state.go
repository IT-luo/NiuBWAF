package monitor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type alertState struct {
	Finding          Finding `json:"finding"`
	NotifiedSeverity string  `json:"notified_severity,omitempty"`
}

type pendingState struct {
	Count int
	First time.Time
}

type observation struct {
	finding  Finding
	required int
	fields   map[string]any
}

type collection struct {
	observations map[string]observation
	covered      []string
	errors       []CheckError
}

type notification struct {
	finding Finding
	fields  map[string]any
}

func (n notification) event() string { return "monitor." + n.finding.Kind }

func (m *Monitor) reconcile(now time.Time, settings inspectionSettings, collected *collection) ([]notification, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	dirty := false
	for key := range m.alerts {
		if !coveredKey(collected.covered, key) {
			continue
		}
		if _, stillPresent := collected.observations[key]; !stillPresent {
			delete(m.alerts, key)
			dirty = true
		}
	}

	keys := make([]string, 0, len(collected.observations))
	for key := range collected.observations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	nextPending := map[string]*pendingState{}
	notifications := []notification{}
	for _, key := range keys {
		obs := collected.observations[key]
		required := obs.required
		if required < 1 {
			required = 1
		}
		first := now
		count := 1
		if required > 1 {
			if previous := m.pending[key]; previous != nil {
				count = previous.Count + 1
				first = previous.First
				if count > required {
					count = required
				}
			}
			if first.IsZero() {
				first = now
			}
			nextPending[key] = &pendingState{Count: count, First: first}
		}

		state := m.alerts[key]
		if state == nil && count < required {
			continue
		}
		if state == nil {
			candidate := obs.finding
			candidate.First = first
			candidate.Last = now
			state = &alertState{Finding: candidate}
			m.alerts[key] = state
			dirty = true
		} else {
			previous := state.Finding
			candidate := obs.finding
			candidate.First = previous.First
			if candidate.First.IsZero() {
				candidate.First = first
			}
			candidate.Last = now
			candidate.LastNotified = previous.LastNotified
			if findingContentChanged(previous, candidate) {
				dirty = true
			}
			state.Finding = candidate
		}

		if shouldNotify(state, now, settings.cooldown) {
			fields := cloneFields(obs.fields)
			if fields == nil {
				fields = map[string]any{}
			}
			fields["key"] = state.Finding.Key
			fields["kind"] = state.Finding.Kind
			fields["severity"] = state.Finding.Severity
			fields["resource"] = state.Finding.Resource
			fields["first"] = state.Finding.First.UTC().Format(time.RFC3339)
			fields["last"] = state.Finding.Last.UTC().Format(time.RFC3339)
			notifications = append(notifications, notification{
				finding: state.Finding, fields: fields,
			})
		}
	}
	m.pending = nextPending
	return notifications, dirty
}

func findingContentChanged(a, b Finding) bool {
	return a.Key != b.Key || a.Kind != b.Kind || a.Severity != b.Severity ||
		a.Resource != b.Resource || a.Message != b.Message || !a.First.Equal(b.First)
}

func shouldNotify(state *alertState, now time.Time, cooldown time.Duration) bool {
	if state.Finding.LastNotified.IsZero() {
		return true
	}
	if severityRank(state.Finding.Severity) > severityRank(state.NotifiedSeverity) {
		return true
	}
	return !now.Before(state.Finding.LastNotified.Add(cooldown))
}

func severityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}

func coveredKey(prefixes []string, key string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func (m *Monitor) persistAlerts() error {
	m.mu.RLock()
	data, err := json.Marshal(m.alerts)
	m.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("encode inspection state: %w", err)
	}
	if err := m.store.SetSetting(alertStateSetting, string(data)); err != nil {
		return fmt.Errorf("persist inspection state: %w", err)
	}
	return nil
}
