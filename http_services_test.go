package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

type testServiceUpgrade struct {
	listener net.Listener
	retire   chan struct{}
}

func (u testServiceUpgrade) Listener(int) (net.Listener, error) { return u.listener, nil }
func (u testServiceUpgrade) Ready() error                       { return nil }
func (u testServiceUpgrade) Retire() <-chan struct{}            { return u.retire }

func TestHTTPServiceRetirementKeepsEstablishedConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	upgrade := testServiceUpgrade{listener: listener, retire: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	emit := make(chan string, 1)
	handler := http.NewServeMux()
	handler.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintln(w, "data: connected")
		w.(http.Flusher).Flush()
		for {
			select {
			case value := <-emit:
				fmt.Fprintf(w, "data: %s\n", value)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	handler.Handle("/ws", websocket.Handler(func(conn *websocket.Conn) {
		for {
			var message string
			if err := websocket.Message.Receive(conn, &message); err != nil {
				return
			}
			if err := websocket.Message.Send(conn, message); err != nil {
				return
			}
		}
	}))
	handler.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	})
	active := make(chan struct{})
	retired := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		// All three slots are occupied when retirement begins.
		services := []httpService{{name: "test", server: &http.Server{Handler: handler}, maxConnections: 3}}
		done <- runHTTPServices(ctx, services, upgrade, func() { close(active) }, func() { close(retired) })
	}()
	select {
	case <-active:
	case <-ctx.Done():
		t.Fatal("worker never became ready")
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+address+"/events", nil)
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	stream := bufio.NewReader(response.Body)
	assertEvent := func(want string) {
		line, err := stream.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "data: "+want {
			t.Fatalf("SSE got %q, %v, want %q", line, err, want)
		}
	}
	assertEvent("connected")
	ws, err := websocket.Dial("ws://"+address+"/ws", "", "http://"+address)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetDeadline(time.Now().Add(6 * time.Second))
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	httpReader := bufio.NewReader(conn)
	assertRequest := func() {
		if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", address); err != nil {
			t.Fatal(err)
		}
		result, err := http.ReadResponse(httpReader, nil)
		if err != nil {
			t.Fatal(err)
		}
		result.Body.Close()
		if result.StatusCode != http.StatusOK {
			t.Fatalf("unexpected response status: %d", result.StatusCode)
		}
	}
	assertRequest()

	close(upgrade.retire)
	select {
	case <-retired:
	case <-ctx.Done():
		t.Fatal("old worker did not retire")
	}
	if fresh, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		fresh.Close()
		t.Fatal("retired worker still accepts new TCP connections")
	}
	select {
	case err := <-done:
		t.Fatalf("worker exited with established connections: %v", err)
	default:
	}
	assertRequest()
	if err := websocket.Message.Send(ws, "after retirement"); err != nil {
		t.Fatal(err)
	}
	var echo string
	if err := websocket.Message.Receive(ws, &echo); err != nil || echo != "after retirement" {
		t.Fatalf("WebSocket got %q, %v", echo, err)
	}
	emit <- "after retirement"
	assertEvent("after retirement")
	conn.Close()
	ws.Close()
	response.Body.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("retired worker did not exit after connections drained")
	}
}
