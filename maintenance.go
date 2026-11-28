package main

import (
	"context"
	"fmt"
	"log"
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
