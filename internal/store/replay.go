package store

import (
	"context"
	"fmt"
)

// ReplayLogQuery 描述历史安全事件回放的只读查询范围。
type ReplayLogQuery struct {
	From   string
	To     string
	SiteID int64 // 非 0 时强制实际站点范围，避免仅靠域名匹配越界
	IP     string
	Domain string
	Action string
	Limit  int
}

// QueryContext 按 id 倒序流式读取攻击日志。SQL 多取一行，用 LIMIT max+1
// 判断是否还有更多数据；额外的该行不会传给回调，也不需要在内存累积结果。
func (s *Store) QueryContext(ctx context.Context, q ReplayLogQuery, fn func(*AttackLog) error) (bool, error) {
	if q.Limit < 0 {
		return false, fmt.Errorf("limit 不能为负数")
	}
	where, args := logWhere(q.IP, q.Domain, q.Action)
	if q.SiteID != 0 {
		where += " AND site_id=?"
		args = append(args, q.SiteID)
	}
	where += " AND ts>=? AND ts<=?"
	args = append(args, q.From, q.To, q.Limit+1)
	rows, err := s.DB.QueryContext(ctx, `SELECT id,ts,site_id,domain,client_ip,country,method,url,action,rule_id,msg,severity,status,req_id,query_redacted
		FROM attack_logs`+where+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	seen := 0
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		var l AttackLog
		if err := rows.Scan(&l.ID, &l.Ts, &l.SiteID, &l.Domain, &l.ClientIP, &l.Country, &l.Method, &l.URL, &l.Action, &l.RuleID, &l.Msg, &l.Severity, &l.Status, &l.ReqID, &l.QueryRedacted); err != nil {
			return false, err
		}
		if seen == q.Limit {
			return true, nil
		}
		seen++
		if err := fn(&l); err != nil {
			return false, err
		}
	}
	return false, rows.Err()
}
