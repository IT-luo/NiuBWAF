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
)

// dynRuleID 动态防护日志规则号，避开 CRS/语义/自定义规则号段
const dynRuleID = 100300

// dynBodyRe 从请求体提取动态令牌：兼容 urlencoded / multipart / JSON 三种承载形式
var dynBodyRe = regexp.MustCompile(`niub_dyn_token["'\s:=]+(\d{1,20}\.[0-9a-f]{64})`)

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// dynSign 与 captcha 签名做域分隔（"dyn|" 前缀），令牌与验证 cookie 不可互相复用
func (p *Proxy) dynSign(ip string, siteID int64, expiry int64) string {
	mac := hmac.New(sha256.New, p.dynSecret)
	fmt.Fprintf(mac, "dyn|%s|%d|%d", ip, siteID, expiry)
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *Proxy) issueDynToken(ip string, siteID int64) string {
	expiry := time.Now().Add(30 * time.Minute).Unix()
	return fmt.Sprintf("%d.%s", expiry, p.dynSign(ip, siteID, expiry))
}

func (p *Proxy) validDynToken(token, ip string, siteID int64) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(p.dynSign(ip, siteID, expiry)))
}

// hasValidDynToken 优先取请求头，其次扫描请求体隐藏字段
func (p *Proxy) hasValidDynToken(r *http.Request, body []byte, ip string, siteID int64) bool {
	if t := r.Header.Get("X-NiuB-Dyn-Token"); t != "" && p.validDynToken(t, ip, siteID) {
		return true
	}
	if m := dynBodyRe.FindSubmatch(body); m != nil {
		return p.validDynToken(string(m[1]), ip, siteID)
	}
	return false
}

// injectDynamic 在 HTML 响应 </body> 前植入混淆脚本，向后续写操作自动附带动态令牌
func (p *Proxy) injectDynamic(body []byte, ip string, siteID int64) []byte {
	script := dynScript(p.issueDynToken(ip, siteID))
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
		vn, dynPrefixCSV, csvCodes(jsEsc(token)), dynSuffixCSV, vn+"s", vn, vn+"s")
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
var of=window.fetch;if(of)window.fetch=function(u,o){try{o=o||{};var m=(o.method||(u&&u.method)||'GET').toUpperCase();if(m!=='GET'&&m!=='HEAD'&&so(u)){var h=new Headers(o.headers||(u&&u.headers)||{});h.set('X-NiuB-Dyn-Token',T);o.headers=h;}return of.call(this,u,o);}catch(e){return of.call(this,u,o);}};
var oo=XMLHttpRequest.prototype.open,osend=XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open=function(m,u){this.__m=(m||'GET').toUpperCase();this.__u=u;return oo.apply(this,arguments);};
XMLHttpRequest.prototype.send=function(b){try{if(this.__m&&this.__m!=='GET'&&this.__m!=='HEAD'&&so(this.__u)){this.setRequestHeader('X-NiuB-Dyn-Token',T);if(typeof b==='string'&&b.indexOf('niub_dyn_token')<0)b=(b?b+'&':'')+'niub_dyn_token='+encodeURIComponent(T);}}catch(e){}return osend.call(this,b);};
try{new MutationObserver(function(ms){for(var i=0;i<ms.length;i++){var ns=ms[i].addedNodes;for(var j=0;j<ns.length;j++){var n=ns[j];if(n.nodeType===1){if(n.tagName==='FORM')at(n);if(n.getElementsByTagName){var fs=n.getElementsByTagName('form');for(var k=0;k<fs.length;k++)at(fs[k]);}}}}}).observe(document.documentElement,{childList:true,subtree:true});}catch(e){}
})();`