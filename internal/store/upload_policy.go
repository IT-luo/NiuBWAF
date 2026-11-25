package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"niubwaf/internal/engine"
)

const MaxSiteUploadPolicies = 16
const MaxUploadConcurrency = 4

type UploadPolicy struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	MaxBodyMiB    int    `json:"max_body_mib"`
	MaxConcurrent int    `json:"max_concurrent"`
}

func ValidateUploadPolicies(policies []UploadPolicy) error {
	if len(policies) > MaxSiteUploadPolicies {
		return fmt.Errorf("每个站点最多配置 %d 条上传策略", MaxSiteUploadPolicies)
	}
	seen := make(map[string]bool, len(policies))
	for _, p := range policies {
		switch p.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
		default:
			return errors.New("上传方法须为 POST、PUT 或 PATCH")
		}
		parsed, err := url.ParseRequestURI(p.Path)
		if err != nil || len(p.Path) > 512 || p.Path == "/" || !strings.HasPrefix(p.Path, "/") ||
			strings.ContainsAny(p.Path, "?#%\\*{}") || parsed.EscapedPath() != p.Path ||
			path.Clean(p.Path) != strings.TrimSuffix(p.Path, "/") {
			return errors.New("请输入精确上传路径，例如 /api/upload")
		}
		if p.MaxBodyMiB < 1 || p.MaxBodyMiB > engine.MaxUploadBodyMiB {
			return fmt.Errorf("上传请求上限须为 1–%d MiB", engine.MaxUploadBodyMiB)
		}
		if p.MaxConcurrent < 1 || p.MaxConcurrent > MaxUploadConcurrency {
			return fmt.Errorf("上传并发数须为 1–%d", MaxUploadConcurrency)
		}
		key := p.Method + " " + p.Path
		if seen[key] {
			return errors.New("同一请求方法和路径只能配置一条上传策略")
		}
		seen[key] = true
	}
	return nil
}

func (s *Store) UploadPolicies(siteID int64) ([]UploadPolicy, error) {
	var document string
	err := s.DB.QueryRow(`SELECT policies FROM site_upload_policies WHERE site_id=?`, siteID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return []UploadPolicy{}, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeUploadPolicies(document)
}

func (s *Store) UploadPoliciesBySite() (map[int64][]UploadPolicy, error) {
	rows, err := s.DB.Query(`SELECT site_id, policies FROM site_upload_policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[int64][]UploadPolicy{}
	for rows.Next() {
		var siteID int64
		var document string
		if err := rows.Scan(&siteID, &document); err != nil {
			return nil, err
		}
		policies, err := decodeUploadPolicies(document)
		if err != nil {
			return nil, fmt.Errorf("站点 %d 上传策略: %w", siteID, err)
		}
		result[siteID] = policies
	}
	return result, rows.Err()
}

func decodeUploadPolicies(document string) ([]UploadPolicy, error) {
	var policies []UploadPolicy
	if err := json.Unmarshal([]byte(document), &policies); err != nil {
		return nil, err
	}
	if policies == nil {
		policies = []UploadPolicy{}
	}
	return policies, ValidateUploadPolicies(policies)
}

func (s *Store) SetUploadPolicies(siteID int64, policies []UploadPolicy) error {
	if err := ValidateUploadPolicies(policies); err != nil {
		return err
	}
	if policies == nil {
		policies = []UploadPolicy{}
	}
	document, err := json.Marshal(policies)
	if err != nil {
		return err
	}
	result, err := s.DB.Exec(`INSERT INTO site_upload_policies(site_id,policies)
		SELECT id,? FROM sites WHERE id=?
		ON CONFLICT(site_id) DO UPDATE SET policies=excluded.policies`, string(document), siteID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}
