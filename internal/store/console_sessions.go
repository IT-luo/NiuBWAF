package store

import (
	"crypto/sha256"
	"time"
)

type ConsoleSession struct {
	Username, Role, CSRF string
	MustChange           bool
	Expires              time.Time
}

// Console sessions are shared by workers during a version handoff. The
// database stores a digest of the bearer cookie, not the cookie itself.
func (s *Store) SaveConsoleSession(scope, token string, session ConsoleSession, passwordHash string) error {
	digest := consoleSessionDigest(scope, token)
	result, err := s.DB.Exec(`INSERT INTO console_sessions(token,username,role,csrf,must_change,expires)
		SELECT ?,?,?,?,?,?
		WHERE (?='admin' AND EXISTS (SELECT 1 FROM settings WHERE key='admin_pass' AND value=?)
			AND ?=COALESCE((SELECT value='on' FROM settings WHERE key='must_change_pass'),0))
		OR (?<>'admin' AND EXISTS (SELECT 1 FROM console_accounts
			WHERE username=? AND role=? AND password_hash=? AND enabled=1 AND must_change=?))`,
		digest[:], session.Username, session.Role, session.CSRF, session.MustChange, session.Expires.Unix(),
		session.Username, passwordHash, session.MustChange,
		session.Username, session.Username, session.Role, passwordHash, session.MustChange)
	return requireConsoleRow(result, err)
}

func (s *Store) ConsoleSession(scope, token string) (ConsoleSession, error) {
	digest := consoleSessionDigest(scope, token)
	var session ConsoleSession
	var expires int64
	err := s.DB.QueryRow(`SELECT username,role,csrf,must_change,expires FROM console_sessions
		WHERE token=? AND expires>?`, digest[:], time.Now().Unix()).
		Scan(&session.Username, &session.Role, &session.CSRF, &session.MustChange, &expires)
	session.Expires = time.Unix(expires, 0)
	return session, err
}

func (s *Store) DeleteConsoleSession(scope, token string) error {
	digest := consoleSessionDigest(scope, token)
	_, err := s.DB.Exec(`DELETE FROM console_sessions WHERE token=?`, digest[:])
	return err
}

func (s *Store) PurgeConsoleSessions() error {
	_, err := s.DB.Exec(`DELETE FROM console_sessions WHERE expires<=?`, time.Now().Unix())
	return err
}

// A cold start gets a new random scope, so restoring an older database cannot
// resurrect login cookies cached before the restore.
func consoleSessionDigest(scope, token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(scope + "\x00" + token))
}
