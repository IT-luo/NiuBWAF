package store

import "maps"

// RefreshSharedSettings makes edits from the other worker visible during a
// handoff. A local commit that raced the read takes precedence over the snapshot.
func (s *Store) RefreshSharedSettings() (bool, error) {
	s.setMu.RLock()
	revision := s.settingsRevision
	s.setMu.RUnlock()
	settings, err := readAllConfigSettings(s.DB)
	if err != nil {
		return false, err
	}
	s.setMu.Lock()
	defer s.setMu.Unlock()
	if revision != s.settingsRevision || maps.Equal(s.settings, settings) {
		return false, nil
	}
	s.settings = settings
	s.settingsRevision++
	return true, nil
}
