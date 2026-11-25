package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"niubwaf/internal/store"
)

func securityDynHeaderRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://dynamic.test/submit", nil)
	r.Header.Set("X-NiuB-Dyn-Token", token)
	return r
}

func TestSecurityDynamicTokenBindsNonceAndConsumesOnce(t *testing.T) {
	p := &Proxy{dynSecret: []byte("nonce-security-test")}
	token := p.issueDynToken("192.0.2.20", 7)
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[1]) != 48 {
		t.Fatalf("令牌必须包含 expiry/nonce/signature: %q", token)
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		t.Fatalf("解析过期时间失败: %v", err)
	}
	remaining := expiry - time.Now().Unix()
	if remaining <= 0 || remaining > int64((dynTokenTTL+time.Second)/time.Second) {
		t.Fatalf("令牌 TTL = %d 秒, 期望短时且不超过 %s", remaining, dynTokenTTL)
	}
	if p.consumeDynToken(securityDynHeaderRequest(token), nil, "192.0.2.21", 7) {
		t.Fatal("跨 IP 使用必须拒绝")
	}
	if p.consumeDynToken(securityDynHeaderRequest(token), nil, "192.0.2.20", 8) {
		t.Fatal("跨站点使用必须拒绝")
	}
	if !p.consumeDynToken(securityDynHeaderRequest(token), nil, "192.0.2.20", 7) {
		t.Fatal("错误的绑定尝试不应误消费；首次正确使用应成功")
	}
	if p.consumeDynToken(securityDynHeaderRequest(token), nil, "192.0.2.20", 7) {
		t.Fatal("同一令牌第二次使用必须拒绝")
	}
	if p.consumeDynTokenValue(token, "192.0.2.20", 7) {
		t.Fatal("已消费 nonce 不应再通过校验")
	}

	direct := p.issueDynToken("192.0.2.20", 7)
	if !p.consumeDynTokenValue(direct, "192.0.2.20", 7) {
		t.Fatal("单令牌接口首次校验应成功")
	}
	if p.consumeDynTokenValue(direct, "192.0.2.20", 7) {
		t.Fatal("单令牌接口第二次校验必须拒绝重放")
	}
}

func TestSecurityDynamicTokenConcurrentConsumptionHasOneWinner(t *testing.T) {
	p := &Proxy{dynSecret: []byte("nonce-concurrency-test")}
	token := p.issueDynToken("192.0.2.30", 9)
	const contenders = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	wg.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			defer wg.Done()
			<-start
			if p.consumeDynToken(securityDynHeaderRequest(token), nil, "192.0.2.30", 9) {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("并发消费成功数 = %d, 期望恰好 1", got)
	}
}

func TestSecurityDynamicNonceCacheBoundedAndExpires(t *testing.T) {
	p := &Proxy{dynSecret: []byte("nonce-capacity-test")}
	const firstIP = "192.0.2.40"
	firstToken := p.issueDynToken(firstIP, 1)
	pool := p.dynPools[1]
	pool.nonces["expired"] = dynNonce{ip: firstIP, expiry: time.Now().Add(-time.Minute).Unix()}
	pool.ipCount[firstIP]++
	pool.lastClean--
	for i := 1; i < dynIPLimit; i++ {
		if p.issueDynToken(firstIP, 1) == "" {
			t.Fatalf("第 %d 个有效令牌签发失败", i+1)
		}
	}
	if p.issueDynToken(firstIP, 1) != "" {
		t.Fatal("同一客户端达到额度后仍签发令牌")
	}
	if _, exists := pool.nonces["expired"]; exists {
		t.Fatal("过期令牌未清理")
	}
	for i := dynIPLimit; i < dynNonceLimit; i++ {
		ip := "client-" + strconv.Itoa(i/dynIPLimit)
		if p.issueDynToken(ip, 1) == "" {
			t.Fatalf("站点额度尚未用完时签发失败: %d", i)
		}
	}
	if p.issueDynToken("other-client", 1) != "" {
		t.Fatal("站点额度已用完")
	}
	if p.issueDynToken(firstIP, 2) == "" {
		t.Fatal("站点一的请求不得占用站点二的令牌额度")
	}
	if !p.consumeDynTokenValue(firstToken, firstIP, 1) || p.issueDynToken(firstIP, 1) == "" {
		t.Fatal("额度满时应保留未过期令牌，并在消费后释放额度")
	}
}

func TestSecurityDynamicTokenRotationSupportsSequentialWrites(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-NiuB-Dyn-Token", "upstream-controlled")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	p := newSecurityTestProxy(t, store.Site{
		Name: "dynamic-next", Domain: "dynamic-next.test", Upstream: upstream.URL, Enabled: true,
		WAFMode: "balanced", DynamicMode: "block",
	}, map[string]string{"semantic_mode": "off"})
	siteID := p.sites["dynamic-next.test"].ID
	token := p.issueDynToken("192.0.2.1", siteID)
	consumed := ""

	for i := 0; i < 3; i++ {
		consumed = token
		rec := httptest.NewRecorder()
		req := securityDynHeaderRequest(token)
		req.Host = "dynamic-next.test"
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("第 %d 次合法写操作状态码 = %d, 期望 200; body=%s", i+1, rec.Code, rec.Body.String())
		}
		next := rec.Header().Get("X-NiuB-Dyn-Token")
		if next == "" || next == token || next == "upstream-controlled" {
			t.Fatalf("第 %d 次响应未续发独立的新令牌: %q", i+1, next)
		}
		token = next
	}

	replay := httptest.NewRecorder()
	replayReq := securityDynHeaderRequest(consumed)
	replayReq.Host = "dynamic-next.test"
	p.ServeHTTP(replay, replayReq)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("已消费的最新令牌重放状态码 = %d, 期望 403", replay.Code)
	}
	if next := replay.Header().Get("X-NiuB-Dyn-Token"); next != "" {
		t.Fatal("重放被拒绝时不应续发有效令牌")
	}
	if got := upstreamHits.Load(); got != 3 {
		t.Fatalf("上游命中数 = %d, 期望三次合法写操作且重放不到达", got)
	}
}

func TestSecurityDynamicTokenReplayBlockedOnRealRequestPath(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "accepted")
	}))
	defer upstream.Close()
	p := newSecurityTestProxy(t, store.Site{
		Name: "dynamic", Domain: "dynamic.test", Upstream: upstream.URL, Enabled: true,
		WAFMode: "balanced", DynamicMode: "block",
	}, map[string]string{"semantic_mode": "off"})
	// httptest.NewRequest 默认 RemoteAddr 为 192.0.2.1:1234。
	token := p.issueDynToken("192.0.2.1", p.sites["dynamic.test"].ID)

	first := httptest.NewRecorder()
	p.ServeHTTP(first, securityDynHeaderRequest(token))
	if first.Code != http.StatusOK || first.Body.String() != "accepted" {
		t.Fatalf("首次有效写操作应放行: code=%d body=%q", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	p.ServeHTTP(second, securityDynHeaderRequest(token))
	if second.Code != http.StatusForbidden {
		t.Fatalf("重放写操作状态码 = %d, 期望 403; body=%s", second.Code, second.Body.String())
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("上游命中数 = %d, 期望只有首次请求到达", got)
	}
}
