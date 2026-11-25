package proxy

import (
	"path/filepath"
	"testing"

	"niubwaf/internal/store"
)

func TestBodyInspectLimit(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "body.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	defer st.Close()
	p := &Proxy{Store: st}

	// 未配置 → 默认 2MB
	if got := p.bodyInspectLimit(); got != 2048<<10 {
		t.Fatalf("默认上限应为 2MB, got %d", got)
	}
	// 合法设置生效
	st.SetSetting("body_inspect_kb", "4096")
	if got := p.bodyInspectLimit(); got != 4096<<10 {
		t.Fatalf("应采纳设置 4096KB, got %d", got)
	}
	// 非法/非正数 → 回退默认
	st.SetSetting("body_inspect_kb", "abc")
	if got := p.bodyInspectLimit(); got != 2048<<10 {
		t.Fatalf("非数字应回退默认, got %d", got)
	}
	st.SetSetting("body_inspect_kb", "0")
	if got := p.bodyInspectLimit(); got != 2048<<10 {
		t.Fatalf("0 应回退默认, got %d", got)
	}
	st.SetSetting("body_inspect_kb", "-5")
	if got := p.bodyInspectLimit(); got != 2048<<10 {
		t.Fatalf("负数应回退默认, got %d", got)
	}
}
