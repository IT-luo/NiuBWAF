package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"niubwaf/internal/store"
)

// dynRuleID 动态防护日志规则号，避开 CRS/语义/自定义规则号段
const (
	dynRuleID     = 100300
	dynTokenTTL   = 2 * time.Minute
	dynNonceLimit = 8192 // 每个站点独立计数
	dynIPLimit    = 32
)

type dynNonce struct {
	ip     string
	expiry int64
}

type dynNoncePool struct {
	nonces    map[string]dynNonce
	ipCount   map[string]int
	lastClean int64
}

// dynBodyRe 从请求体提取动态令牌：兼容 urlencoded / multipart / JSON 三种承载形式
var dynBodyRe = regexp.MustCompile(`niub_dyn_token["'\s:=]+(\d{1,20}\.[0-9a-f]{48}\.[0-9a-f]{64})`)

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// dynSign 与 captcha 签名做域分隔（"dyn|" 前缀），令牌与验证 cookie 不可互相复用。
func (p *Proxy) dynSign(ip string, siteID int64, expiry int64, nonce string) string {
	mac := hmac.New(sha256.New, p.dynSecret)
	fmt.Fprintf(mac, "dyn|%s|%d|%d|%s", ip, siteID, expiry, nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

func (pool *dynNoncePool) remove(nonce string, entry dynNonce) {
	delete(pool.nonces, nonce)
	if pool.ipCount[entry.ip] <= 1 {
		delete(pool.ipCount, entry.ip)
	} else {
		pool.ipCount[entry.ip]--
	}
}

func (pool *dynNoncePool) clean(now int64) {
	if pool.lastClean == now {
		return
	}
	pool.lastClean = now
	for nonce, entry := range pool.nonces {
		if entry.expiry <= now {
			pool.remove(nonce, entry)
		}
	}
}

func (p *Proxy) pruneDynPools(sites map[string]*cachedSite) {
	p.dynMu.Lock()
	defer p.dynMu.Unlock()
	active := make(map[int64]bool, len(sites))
	for _, site := range sites {
		active[site.ID] = site.Enabled && (site.DynamicMode == "observe" || site.DynamicMode == "block")
	}
	for id := range p.dynPools {
		if !active[id] {
			delete(p.dynPools, id)
		}
	}
}

func (p *Proxy) issueDynToken(ip string, siteID int64) string {
	issuedAt := time.Now()
	now := issuedAt.Unix()
	expiry := issuedAt.Add(dynTokenTTL).Unix()

	p.dynMu.Lock()
	defer p.dynMu.Unlock()
	if p.dynPools == nil {
		p.dynPools = map[int64]*dynNoncePool{}
	}
	pool := p.dynPools[siteID]
	if pool == nil {
		pool = &dynNoncePool{nonces: map[string]dynNonce{}, ipCount: map[string]int{}}
		p.dynPools[siteID] = pool
	}
	pool.clean(now)
	if len(pool.nonces) >= dynNonceLimit || pool.ipCount[ip] >= dynIPLimit {
		return ""
	}
	nonce := store.RandToken()
	pool.nonces[nonce] = dynNonce{ip: ip, expiry: expiry}
	pool.ipCount[ip]++
	return fmt.Sprintf("%d.%s.%s", expiry, nonce, p.dynSign(ip, siteID, expiry, nonce))
}

// consumeDynTokenValue 校验签名、IP/站点/有效期及服务端 nonce，并在同一锁内原子消费。
func (p *Proxy) consumeDynTokenValue(token, ip string, siteID int64) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[1]) != 48 || len(parts[2]) != sha256.Size*2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	now := time.Now().Unix()
	if err != nil || now >= expiry {
		return false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(p.dynSign(ip, siteID, expiry, parts[1]))) {
		return false
	}

	p.dynMu.Lock()
	defer p.dynMu.Unlock()
	pool := p.dynPools[siteID]
	if pool == nil {
		return false
	}
	entry, ok := pool.nonces[parts[1]]
	if !ok {
		return false
	}
	if entry.expiry <= now {
		pool.remove(parts[1], entry)
		return false
	}
	if entry.ip != ip || entry.expiry != expiry {
		return false
	}
	pool.remove(parts[1], entry)
	return true
}

// consumeDynToken 优先取请求头，其次扫描请求体隐藏字段。
func (p *Proxy) consumeDynToken(r *http.Request, body []byte, ip string, siteID int64) bool {
	if t := r.Header.Get("X-NiuB-Dyn-Token"); t != "" && p.consumeDynTokenValue(t, ip, siteID) {
		return true
	}
	if m := dynBodyRe.FindSubmatch(body); m != nil {
		return p.consumeDynTokenValue(string(m[1]), ip, siteID)
	}
	return false
}

// injectDynamic 在 HTML 响应 </body> 前植入混淆脚本，向后续写操作自动附带动态令牌
func (p *Proxy) injectDynamic(body []byte, ip string, siteID int64) []byte {
	token := p.issueDynToken(ip, siteID)
	if token == "" {
		return body
	}
	script := dynScript(token)
	idx := bytes.LastIndex(bytes.ToLower(body), []byte("</body>"))
	if idx < 0 {
		return append(body, script...)
	}
	out := make([]byte, 0, len(body)+len(script))
	out = append(out, body[:idx]...)
	out = append(out, script...)
	out = append(out, body[idx:]...)
	return out
}

// dynScript 复用 captcha 的字符码数组混淆，正则爬虫拿不到明文令牌与算法。
// 静态 JS 的字符码在 init 预计算，每请求仅编码令牌，避免重复编码 ~2KB 脚本。
func dynScript(token string) []byte {
	vn := fmt.Sprintf("_0x%x", rand.Int63())
	inner := fmt.Sprintf("var %s=[%s,%s,%s];var %s=String.fromCharCode.apply(null,%s);(0,eval)(%s);",
		vn, dynPrefixCSV, csvCodes(token), dynSuffixCSV, vn+"s", vn, vn+"s")
	return []byte("<script>" + inner + "</script>")
}

func csvCodes(s string) string {
	codes := make([]string, len(s))
	for i := range s {
		codes[i] = strconv.Itoa(int(s[i]))
	}
	return strings.Join(codes, ",")
}

var dynPrefixCSV, dynSuffixCSV string

func init() {
	i := strings.Index(dynCoreJS, "%s")
	dynPrefixCSV = csvCodes(dynCoreJS[:i])
	dynSuffixCSV = csvCodes(dynCoreJS[i+2:])
}

// dynCoreJS 仅加固写操作（fetch/XHR/表单），不改写既有字段，最大限度避免误伤正常站点。
// 令牌仅附带到同源请求，杜绝跨站泄露；IIFE 包裹使顶层 return 合法。
const dynCoreJS = `(function(){if(window.__niubDyn)return;window.__niubDyn=1;
var T='%s';
function so(u){try{var s=typeof u==='string'?u:(u&&u.url)||'';if(!s)return false;if(s.charAt(0)==='/'&&s.charAt(1)!=='/')return true;return new URL(s,location.href).origin===location.origin;}catch(e){return false;}}
function at(f){try{if(!f||f.querySelector('input[name="niub_dyn_token"]'))return;var i=document.createElement('input');i.type='hidden';i.name='niub_dyn_token';i.value=T;f.appendChild(i);}catch(e){}}
function af(){var fs=document.getElementsByTagName('form');for(var i=0;i<fs.length;i++)at(fs[i]);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',af);else af();
document.addEventListener('submit',function(e){at(e.target);},true);
var os=HTMLFormElement.prototype.submit;HTMLFormElement.prototype.submit=function(){at(this);return os.apply(this,arguments);};
function nt(r){try{var n=r.headers.get('X-NiuB-Dyn-Token');if(n)T=n;}catch(e){}return r;}
var of=window.fetch;if(of)window.fetch=function(u,o){try{o=o||{};var m=(o.method||(u&&u.method)||'GET').toUpperCase();if(m!=='GET'&&m!=='HEAD'&&so(u)){var h=new Headers(o.headers||(u&&u.headers)||{});h.set('X-NiuB-Dyn-Token',T);o.headers=h;}return of.call(this,u,o).then(nt);}catch(e){return of.call(this,u,o);}};
var oo=XMLHttpRequest.prototype.open,osend=XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open=function(m,u){this.__m=(m||'GET').toUpperCase();this.__u=u;return oo.apply(this,arguments);};
XMLHttpRequest.prototype.send=function(b){try{var x=this;if(!x.__nl){x.__nl=1;x.addEventListener('load',function(){try{var n=x.getResponseHeader('X-NiuB-Dyn-Token');if(n)T=n;}catch(e){}});}if(this.__m&&this.__m!=='GET'&&this.__m!=='HEAD'&&so(this.__u)){this.setRequestHeader('X-NiuB-Dyn-Token',T);if(typeof b==='string'&&b.indexOf('niub_dyn_token')<0)b=(b?b+'&':'')+'niub_dyn_token='+encodeURIComponent(T);}}catch(e){}return osend.call(this,b);};
try{new MutationObserver(function(ms){for(var i=0;i<ms.length;i++){var ns=ms[i].addedNodes;for(var j=0;j<ns.length;j++){var n=ns[j];if(n.nodeType===1){if(n.tagName==='FORM')at(n);if(n.getElementsByTagName){var fs=n.getElementsByTagName('form');for(var k=0;k<fs.length;k++)at(fs[k]);}}}}}).observe(document.documentElement,{childList:true,subtree:true});}catch(e){}
})();`
