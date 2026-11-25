package store

func (s *Store) AuditAfter(id int64, limit int) ([]AuditLog, error) {
	rows, err := s.DB.Query(`SELECT id,ts,user,action,detail FROM audit_logs WHERE id>? ORDER BY id LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []AuditLog{}
	for rows.Next() {
		var item AuditLog
		if err := rows.Scan(&item.ID, &item.Ts, &item.User, &item.Action, &item.Detail); err != nil {
			return nil, err
		}
		entries = append(entries, item)
	}
	return entries, rows.Err()
}
