package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestUpgradeListenerPreservesAcceptedConnection(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	active, retired := make(chan struct{}), make(chan struct{})
	listener := &upgradeListener{
		Listener: tcp, active: active, retired: retired, closed: make(chan struct{}),
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn, err}
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case result := <-accepted:
		if result.conn != nil {
			result.conn.Close()
		}
		t.Fatalf("upgraded listener accepted before activation: %v", result.err)
	case <-time.After(30 * time.Millisecond):
	}
	close(active)
	var server net.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		server = result.conn
	case <-time.After(2 * time.Second):
		t.Fatal("activated listener did not accept pending connection")
	}
	defer server.Close()

	close(retired)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("retired listener accepted a new connection")
	}
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write([]byte("still open")); err != nil {
		t.Fatal(err)
	}
	want := "still open"
	reply := make([]byte, len(want))
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != want {
		t.Fatalf("retirement interrupted the accepted connection: reply=%q err=%v", reply, err)
	}
}
