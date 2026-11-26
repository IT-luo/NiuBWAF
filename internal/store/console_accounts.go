package store

import "database/sql"

type ConsoleAccount struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	PasswordHash string `json:"-"`
	Enabled      bool   `json:"enabled"`
	MustChange   bool   `json:"must_change"`
}

func (s *Store) ConsoleAccount(username string) (ConsoleAccount, error) {
	var a ConsoleAccount
	err := s.DB.QueryRow(`SELECT username,role,password_hash,enabled,must_change FROM console_accounts WHERE username=?`, username).
		Scan(&a.Username, &a.Role, &a.PasswordHash, &a.Enabled, &a.MustChange)
	return a, err
}

func (s *Store) ConsoleAccounts() ([]ConsoleAccount, error) {
	rows, err := s.DB.Query(`SELECT username,role,enabled,must_change FROM console_accounts ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConsoleAccount{}
	for rows.Next() {
		var a ConsoleAccount
		if err := rows.Scan(&a.Username, &a.Role, &a.Enabled, &a.MustChange); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) CreateConsoleAccount(a ConsoleAccount) error {
	_, err := s.DB.Exec(`INSERT INTO console_accounts(username,role,password_hash,enabled,must_change) VALUES(?,?,?,?,?)`,
		a.Username, a.Role, a.PasswordHash, a.Enabled, a.MustChange)
	return err
}

func (s *Store) UpdateConsoleAccount(a ConsoleAccount) error {
	_, err := s.DB.Exec(`UPDATE console_accounts SET role=?,password_hash=?,enabled=?,must_change=? WHERE username=?`,
		a.Role, a.PasswordHash, a.Enabled, a.MustChange, a.Username)
	return err
}

func (s *Store) DeleteConsoleAccount(username string) error {
	_, err := s.DB.Exec(`DELETE FROM console_accounts WHERE username=?`, username)
	return err
}

// ReplaceRootConsolePassword changes the password only if the verified hash is
// still current. It also handles transparent legacy hash upgrades.
func (s *Store) ReplaceRootConsolePassword(expectedHash, hash string, clearMustChange bool) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE settings SET value=? WHERE key='admin_pass' AND value=?`, hash, expectedHash)
	if err := requireConsoleRow(result, err); err != nil {
		return err
	}
	if clearMustChange {
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES('must_change_pass','off')
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
			return err
		}
	}
	s.setMu.Lock()
	defer s.setMu.Unlock()
	if err := tx.Commit(); err != nil {
		return err
	}
	s.settings["admin_pass"] = hash
	s.settingsRevision++
	if clearMustChange {
		s.settings["must_change_pass"] = "off"
	}
	return nil
}

func (s *Store) ReplaceConsoleAccountPassword(username, expectedHash, hash string) error {
	result, err := s.DB.Exec(`UPDATE console_accounts SET password_hash=?,must_change=0
		WHERE username=? AND password_hash=? AND enabled=1`, hash, username, expectedHash)
	return requireConsoleRow(result, err)
}

func requireConsoleRow(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return sql.ErrNoRows
	}
	return err
}
