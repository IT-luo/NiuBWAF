package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var alertClient = &http.Client{Timeout: 6 * time.Second}

// alertLoop 周期检测攻击激增并按冷却间隔推送告警
func (p *Proxy) alertLoop(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if ctx.Err() == nil {
				p.checkAlert()
			}
		}
	}
}

func (p *Proxy) checkAlert() {
	if p.Store.GetSetting("alert_enabled") != "on" {
		return
	}
	window := repSettingInt(p.Store, "alert_window", 60, 10, 3600)
	threshold := repSettingInt(p.Store, "alert_threshold", 50, 1, 1000000)
	cooldown := repSettingInt(p.Store, "alert_cooldown", 300, 10, 86400)
	p.alertMu.Lock()
	if time.Since(p.lastAlert) < time.Duration(cooldown)*time.Second {
		p.alertMu.Unlock()
		return
	}
	p.alertMu.Unlock()
	since := time.Now().Add(-time.Duration(window) * time.Second).Format("2006-01-02 15:04:05")
	count := p.Store.AttackCountSince(since)
	if count < threshold {
		return
	}
	p.alertMu.Lock()
	p.lastAlert = time.Now()
	p.alertMu.Unlock()
	msg := fmt.Sprintf("牛B WAF 告警：近 %d 秒检测到 %d 次攻击事件，超过阈值 %d，请及时处置。", window, count, threshold)
	p.dispatchAlert(msg, count, window, threshold)
	p.Store.Audit("system", "触发告警", msg)
	p.Hub.Broadcast(map[string]any{"type": "alert", "ts": nowStr(), "message": msg, "count": count})
}

func (p *Proxy) dispatchAlert(msg string, count, window, threshold int) {
	ts := nowStr()
	if u := strings.TrimSpace(p.Store.GetSetting("alert_webhook")); u != "" {
		go p.postJSON(u, map[string]any{"event": "attack_spike", "message": msg, "count": count, "window": window, "threshold": threshold, "ts": ts})
	}
	text := map[string]any{"msgtype": "text", "text": map[string]string{"content": msg}}
	if u := strings.TrimSpace(p.Store.GetSetting("alert_dingtalk")); u != "" {
		go p.postJSON(u, text)
	}
	if u := strings.TrimSpace(p.Store.GetSetting("alert_wecom")); u != "" {
		go p.postJSON(u, text)
	}
}

// Notify 实现巡检通知接口。只要一个通道接收成功就视为已送达；部分通道失败
// 不返回错误，避免 monitor 重试时向已成功的通道重复推送。
func (p *Proxy) Notify(ctx context.Context, event, message string, fields map[string]any) (delivered bool, err error) {
	if p.Store.GetSetting("alert_enabled") != "on" {
		return false, nil
	}

	webhook := make(map[string]any, len(fields)+3)
	for key, value := range fields {
		webhook[key] = value
	}
	// 保留通知自身的语义，调用方 fields 不能覆盖这些固定字段。
	webhook["event"] = event
	webhook["message"] = message
	webhook["ts"] = nowStr()
	text := map[string]any{"msgtype": "text", "text": map[string]string{"content": message}}

	channels := []struct {
		name    string
		url     string
		payload any
	}{
		{name: "webhook", url: strings.TrimSpace(p.Store.GetSetting("alert_webhook")), payload: webhook},
		{name: "dingtalk", url: strings.TrimSpace(p.Store.GetSetting("alert_dingtalk")), payload: text},
		{name: "wecom", url: strings.TrimSpace(p.Store.GetSetting("alert_wecom")), payload: text},
	}
	configured := 0
	var failures []error
	for _, channel := range channels {
		if channel.url == "" {
			continue
		}
		configured++
		if err := p.postJSONContext(ctx, channel.url, channel.payload); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", channel.name, err))
			continue
		}
		delivered = true
	}
	if configured == 0 {
		return false, nil
	}
	if delivered {
		return true, nil
	}
	return false, errors.Join(failures...)
}

func (p *Proxy) postJSON(rawURL string, payload any) error {
	return p.postJSONContext(context.Background(), rawURL, payload)
}

func (p *Proxy) postJSONContext(ctx context.Context, rawURL string, payload any) error {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return fmt.Errorf("告警地址必须以 http(s):// 开头")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("告警地址无效")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := alertClient.Do(req)
	if err != nil {
		// http.Client errors can include the full URL and its access token.
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("告警请求超时")
		}
		return errors.New("告警请求失败，请检查连接和证书")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("告警推送返回 %d", resp.StatusCode)
	}
	return nil
}

// AlertTest 同步向已配置通道发送测试消息，返回各通道结果，供控制台验证连通性
func (p *Proxy) AlertTest() map[string]string {
	msg := "牛B WAF 告警测试：通知通道连通性验证。"
	out := map[string]string{}
	for _, name := range []string{"webhook", "dingtalk", "wecom"} {
		u := strings.TrimSpace(p.Store.GetSetting("alert_" + name))
		if u == "" {
			out[name] = "未配置"
			continue
		}
		var payload any
		if name == "webhook" {
			payload = map[string]any{"event": "test", "message": msg, "ts": nowStr()}
		} else {
			payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": msg}}
		}
		if err := p.postJSON(u, payload); err != nil {
			out[name] = "失败: " + err.Error()
		} else {
			out[name] = "成功"
		}
	}
	return out
}
