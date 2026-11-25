package store

import (
	"database/sql"
	"errors"
)

type APIPolicy struct {
	Mode     string `json:"mode"`
	Prefix   string `json:"prefix"`
	Document string `json:"document"`
}

func (s *Store) APIPolicy(siteID int64) (APIPolicy, error) {
	p := APIPolicy{Mode: "off", Prefix: "/api"}
	err := s.DB.QueryRow(`SELECT mode,prefix,document FROM site_api_policies WHERE site_id=?`, siteID).
		Scan(&p.Mode, &p.Prefix, &p.Document)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return p, err
}

func (s *Store) SetAPIPolicy(siteID int64, p APIPolicy) error {
	result, err := s.DB.Exec(`INSERT INTO site_api_policies(site_id,mode,prefix,document)
		SELECT id,?,?,? FROM sites WHERE id=?
		ON CONFLICT(site_id) DO UPDATE SET mode=excluded.mode,prefix=excluded.prefix,document=excluded.document`,
		p.Mode, p.Prefix, p.Document, siteID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}

func (s *Store) EnabledAPIPolicies() (map[int64]APIPolicy, error) {
	rows, err := s.DB.Query(`SELECT site_id,mode,prefix,document FROM site_api_policies WHERE mode != 'off'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := map[int64]APIPolicy{}
	for rows.Next() {
		var id int64
		var p APIPolicy
		if err := rows.Scan(&id, &p.Mode, &p.Prefix, &p.Document); err != nil {
			return nil, err
		}
		policies[id] = p
	}
	return policies, rows.Err()
}
