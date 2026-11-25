package store

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

func (s *Store) ChangeRootConsolePassword(hash string) error {
	return s.SetSettings(map[string]string{"admin_pass": hash, "must_change_pass": "off"})
}
