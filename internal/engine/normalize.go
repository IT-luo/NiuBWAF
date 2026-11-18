package engine

import (
	"encoding/base64"
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const maxFieldScan = 16 << 10

var (
	reMySQLExecComment = regexp.MustCompile(`(?s)/\*!\d*(.*?)\*/`)
	reBlockComment     = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reBase64           = regexp.MustCompile(`^[A-Za-z0-9+/_-]{16,}={0,2}$`)
	reJSEscape         = regexp.MustCompile(`\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|[0-7]{1,3})`)
)

// Normalize 生成检测变体：递归 URL/%u/HTML 实体解码、NFKC 全角折叠、
// SQL 注释还原、base64 还原。仅用于检测，不修改转发请求。
func Normalize(s string) []string {
	if s == "" {
		return nil
	}
	s = truncUTF8(s, maxFieldScan)
	seen := map[string]bool{s: true}
	variants := []string{s}
	push := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			variants = append(variants, v)
		}
	}
	cur := s
	for i := 0; i < 3; i++ {
		next := html.UnescapeString(percentDecode(cur))
		if next == cur {
			break
		}
		cur = next
		push(cur)
	}
	push(foldComments(norm.NFKC.String(cur)))
	// JS 字符串转义还原（\xNN / \uNNNN / \u{NNNN} / 八进制 \NNN），
	// 暴露 parent['\x65\x76\x61\x6c'] → parent['eval'] 一类混淆 XSS
	if j := jsUnescape(cur); j != cur {
		push(j)
		push(foldComments(norm.NFKC.String(j)))
	}
	if b, ok := tryBase64(strings.TrimSpace(cur)); ok {
		push(b)
		// 双层 base64（webshell 载荷常见包装）再还原一层
		if b2, ok2 := tryBase64(strings.TrimSpace(b)); ok2 {
			push(b2)
		}
	}
	return variants
}

// jsUnescape 解码 JavaScript 字符串转义序列；非法序列原样保留。
// 仅用于生成检测变体，不修改转发请求。
func jsUnescape(s string) string {
	if !strings.Contains(s, "\\") || !reJSEscape.MatchString(s) {
		return s
	}
	return reJSEscape.ReplaceAllStringFunc(s, func(m string) string {
		body := m[1:]
		switch body[0] {
		case 'x', 'X':
			if v, ok := hexVal(body[1:3]); ok {
				return string(rune(v))
			}
		case 'u', 'U':
			h := body[1:]
			if strings.HasPrefix(h, "{") {
				h = h[1 : len(h)-1]
			}
			if v, err := strconv.ParseUint(h, 16, 32); err == nil && v <= 0x10FFFF && utf8.ValidRune(rune(v)) && v != 0 {
				return string(rune(v))
			}
		default: // 八进制
			if v, err := strconv.ParseUint(body, 8, 32); err == nil && v <= 0x7F && v != 0 {
				return string(rune(v))
			}
		}
		return m
	})
}

// percentDecode 宽松百分号解码，兼容 %XX 与 IIS 风格 %uXXXX，非法序列原样保留
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if v, ok := hexVal(s[i+2 : i+6]); ok {
				b.WriteRune(rune(v))
				i += 5
				continue
			}
		}
		if i+2 < len(s) {
			if v, ok := hexVal(s[i+1 : i+3]); ok {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func hexVal(s string) (int, bool) {
	v := 0
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// foldComments 块注释折叠为空格（MySQL 语义）；/*!...*/ 可执行注释保留内容
func foldComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	s = reMySQLExecComment.ReplaceAllString(s, "$1")
	return reBlockComment.ReplaceAllString(s, " ")
}

func tryBase64(s string) (string, bool) {
	if !reBase64.MatchString(s) {
		return "", false
	}
	// 兼容 base64url 字母表与被截断的载荷（裁到 4 字节对齐）
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	s = s[:len(s)-len(s)%4]
	if len(s) < 16 {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return "", false
		}
	}
	if len(b) == 0 || !utf8.Valid(b) {
		return "", false
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' || c >= 0x80 {
			printable++
		}
	}
	if printable*10 < len(b)*9 {
		return "", false
	}
	return string(b), true
}

func truncUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}