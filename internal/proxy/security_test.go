package proxy

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"testing"
)

func TestSafeOrigURL(t *testing.T) {
	allow := map[string]string{
		"/":            "/",
		"/login":       "/login",
		"/a/b?x=1&y=2": "/a/b?x=1&y=2",
		"/中文":         "/中文",
		"  /trim  ":    "/trim",
	}
	for in, want := range allow {
		if got := safeOrigURL(in); got != want {
			t.Errorf("safeOrigURL(%q)=%q, 期望 %q", in, got, want)
		}
	}
	deny := []string{"", "//evil.com", "/\\evil.com", "https://evil.com", "http://evil.com/x", "javascript:alert(1)", "ftp://x", "example.com", "\t//evil.com"}
	for _, in := range deny {
		if got := safeOrigURL(in); got != "/" {
			t.Errorf("safeOrigURL(%q)=%q, 危险输入应回退 /", in, got)
		}
	}
}

// flushRW 仅实现 Flusher，不支持 Hijack
type flushRW struct {
	header  http.Header
	flushed int
	written bytes.Buffer
	status  int
}

func (m *flushRW) Header() http.Header {
	if m.header == nil {
		m.header = http.Header{}
	}
	return m.header
}
func (m *flushRW) Write(b []byte) (int, error) { return m.written.Write(b) }
func (m *flushRW) WriteHeader(s int)           { m.status = s }
func (m *flushRW) Flush()                      { m.flushed++ }

// hijackRW 额外支持 Hijack（WebSocket/Upgrade）
type hijackRW struct {
	flushRW
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (m *hijackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.rw, nil
}

func TestCountWriterFlushHijackUnwrap(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	brw := bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1))
	base := &hijackRW{conn: c1, rw: brw}
	cw := &countWriter{ResponseWriter: base}

	// Write 计数透传
	n, err := cw.Write([]byte("hello"))
	if err != nil || n != 5 || cw.n != 5 || base.written.String() != "hello" {
		t.Fatalf("Write 计数/透传错误: n=%d err=%v cw.n=%d body=%q", n, err, cw.n, base.written.String())
	}
	// Flush 透传（SSE）
	cw.Flush()
	cw.Flush()
	if base.flushed != 2 {
		t.Errorf("Flush 应透传 2 次, got %d", base.flushed)
	}
	// Hijack 透传（WebSocket）
	conn, rw, err := cw.Hijack()
	if err != nil || conn != c1 || rw != brw {
		t.Fatalf("Hijack 应返回底层 conn/rw: conn=%v err=%v", conn, err)
	}
	// Unwrap 暴露底层
	if cw.Unwrap() != base {
		t.Error("Unwrap 应返回底层 ResponseWriter")
	}
	// ResponseController 穿透包装层
	rc := http.NewResponseController(cw)
	if err := rc.Flush(); err != nil {
		t.Errorf("ResponseController.Flush 失败: %v", err)
	}
	if _, _, err := rc.Hijack(); err != nil {
		t.Errorf("ResponseController.Hijack 失败: %v", err)
	}
}

func TestCountWriterHijackUnsupported(t *testing.T) {
	base := &flushRW{}
	cw := &countWriter{ResponseWriter: base}
	cw.Flush()
	if base.flushed != 1 {
		t.Errorf("Flush 应透传, got %d", base.flushed)
	}
	if _, _, err := cw.Hijack(); err == nil {
		t.Error("底层不支持 Hijack 时应返回错误")
	}
}