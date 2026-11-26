package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"niubwaf/internal/api"
	"niubwaf/internal/proxy"
	"niubwaf/internal/store"
)

func watchSharedSettings(ctx context.Context, st *store.Store, p *proxy.Proxy) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				changed, err := st.RefreshSharedSettings()
				if err != nil {
					log.Printf("同步进程间配置失败: %v", err)
				} else if changed {
					p.Reload()
				}
			}
		}
	}()
	return done
}

// The supervisor reserves port 80 only when HTTP-01 is configured at startup.
func upgradeChallengeAddress(dbPath, addr string) (string, error) {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	path := filepath.ToSlash(abs)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return "", err
	}
	defer db.Close()
	var table int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='settings'`).Scan(&table); err != nil || table == 0 {
		return "", err
	}
	var enabled, domains string
	err = db.QueryRow(`SELECT COALESCE((SELECT value FROM settings WHERE key='acme_enabled'),''),
		COALESCE((SELECT value FROM settings WHERE key='acme_domains'),'')`).Scan(&enabled, &domains)
	if err == nil && enabled == "on" && strings.Trim(domains, ", \r\n\t") != "" {
		return addr, nil
	}
	return "", err
}

func runMaintenance(ctx context.Context, st *store.Store, a *api.API) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(6 * time.Hour)
		defer tick.Stop()
		for ctx.Err() == nil {
			days := 30
			if v := st.GetSetting("log_retention_days"); v != "" {
				fmt.Sscanf(v, "%d", &days)
			}
			if days > 0 {
				st.CleanupLogs(days)
			}
			a.PurgeExpiredSessions()
			if name, err := a.RunBackup(); err != nil {
				log.Printf("数据库自动备份失败: %v", err)
			} else {
				log.Printf("数据库自动备份完成: backups/%s", name)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return done
}
