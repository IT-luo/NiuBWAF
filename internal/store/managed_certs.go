package store

import "time"

func (s *Store) migrateManagedCertificates() error {
	_, err := s.DB.Exec(`
		CREATE TABLE IF NOT EXISTS dns_certificate_accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE, provider TEXT NOT NULL, credentials BLOB NOT NULL
		);
		CREATE TABLE IF NOT EXISTS managed_certificates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id INTEGER NOT NULL, domains TEXT NOT NULL, email TEXT NOT NULL, staging INTEGER NOT NULL,
			account_key BLOB NOT NULL, cert_pem TEXT NOT NULL DEFAULT '', key_pem TEXT NOT NULL DEFAULT '',
			expires_at INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued',
			last_error TEXT NOT NULL DEFAULT '', next_attempt INTEGER NOT NULL DEFAULT 0,
			lease TEXT NOT NULL DEFAULT '', UNIQUE(account_id, domains, staging)
		);
		CREATE TABLE IF NOT EXISTS managed_certificate_sites (
			site_id INTEGER PRIMARY KEY, certificate_id INTEGER NOT NULL, domain TEXT NOT NULL
		);
		CREATE TRIGGER IF NOT EXISTS remove_managed_certificate_binding AFTER DELETE ON sites
		BEGIN DELETE FROM managed_certificate_sites WHERE site_id=OLD.id; END;
		CREATE TRIGGER IF NOT EXISTS remove_renamed_certificate_binding AFTER UPDATE OF domain ON sites
		WHEN NEW.domain<>OLD.domain
		BEGIN DELETE FROM managed_certificate_sites WHERE site_id=OLD.id; END;
		CREATE TRIGGER IF NOT EXISTS managed_cert_rotated AFTER UPDATE OF cert_pem ON managed_certificates
		WHEN NEW.staging=0 AND NEW.cert_pem<>OLD.cert_pem
		BEGIN INSERT OR REPLACE INTO settings(key,value) VALUES('managed_cert_revision',lower(hex(randomblob(16)))); END;
		CREATE TRIGGER IF NOT EXISTS managed_cert_bound AFTER INSERT ON managed_certificate_sites
		BEGIN INSERT OR REPLACE INTO settings(key,value) VALUES('managed_cert_revision',lower(hex(randomblob(16)))); END;
		CREATE TRIGGER IF NOT EXISTS managed_cert_rebound AFTER UPDATE ON managed_certificate_sites
		BEGIN INSERT OR REPLACE INTO settings(key,value) VALUES('managed_cert_revision',lower(hex(randomblob(16)))); END;
		CREATE TRIGGER IF NOT EXISTS managed_cert_unbound AFTER DELETE ON managed_certificate_sites
		BEGIN INSERT OR REPLACE INTO settings(key,value) VALUES('managed_cert_revision',lower(hex(randomblob(16)))); END;
	`)
	return err
}

type ManagedSiteCertificate struct {
	Domain  string
	CertPEM string
	KeyPEM  string
}

func (s *Store) ManagedSiteCertificates() ([]ManagedSiteCertificate, error) {
	rows, err := s.DB.Query(`SELECT s.domain,c.cert_pem,c.key_pem
		FROM managed_certificate_sites b JOIN sites s ON s.id=b.site_id AND s.domain=b.domain
		JOIN managed_certificates c ON c.id=b.certificate_id
		WHERE c.staging=0 AND c.expires_at>?`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManagedSiteCertificate
	for rows.Next() {
		var cert ManagedSiteCertificate
		if err := rows.Scan(&cert.Domain, &cert.CertPEM, &cert.KeyPEM); err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	return out, rows.Err()
}
