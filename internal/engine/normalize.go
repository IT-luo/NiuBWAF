package engine

import (
	"encoding/base64"
	"html"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const maxFieldScan = 16 << 10

var (
	reMySQLExecComment = regexp.MustCompile(`(?s)/\*!\d*(.*?)\*/`)
	reBlockComment     = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reBase64           = regexp.MustCompile(`^[A-Za-z0-9+/]{24,}={0,2}$`)
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
	if b, ok := tryBase64(strings.TrimSpace(cur)); ok {
		push(b)
	}
	return variants
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