package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

const upgradeTestWorkerEnv = "NIUBWAF_HOT_UPGRADE_TEST_WORKER"

func TestLinuxHotUpgradePreservesConnectionsAndRollsBack(t *testing.T) {
	socket, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := socket.Addr().String()
	inherited, err := socket.File()
	_ = socket.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer inherited.Close()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := func(version string) (*upgradeProcess, error) {
		return launchUpgradeProcess(ctx, path, []string{"-test.run=^TestLinuxHotUpgradeWorker$"}, []string{
			upgradeListenersEnv + "=1",
			upgradeScopeEnv + "=" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			upgradeTestWorkerEnv + "=" + version,
		}, []*os.File{inherited})
	}
	old, err := start("old")
	if err != nil {
		t.Fatal(err)
	}
	defer old.kill()
	dial := func() (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn, bufio.NewReader(conn)
	}
	request := func(conn net.Conn, reader *bufio.Reader, message string) string {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(conn, message); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	conn, reader := dial()
	defer conn.Close()
	if got := request(conn, reader, "ping"); got != "old:ping\n" {
		t.Fatalf("first worker replied %q", got)
	}
	failed, err := start("fail")
	if err == nil {
		failed.kill()
		t.Fatal("invalid candidate was activated")
	}
	if got := request(conn, reader, "ping"); got != "old:ping\n" {
		t.Fatalf("failed upgrade interrupted old worker: %q", got)
	}
	newWorker, err := start("new")
	if err != nil {
		t.Fatal(err)
	}
	defer newWorker.kill()
	if err := old.send(upgradeRetire); err != nil {
		t.Fatal(err)
	}
	if got := request(conn, reader, "await-retirement"); got != "old:await-retirement\n" {
		t.Fatalf("successful upgrade interrupted the old connection: %q", got)
	}
	newConn, newReader := dial()
	if got := request(newConn, newReader, "ping"); got != "new:ping\n" {
		t.Fatalf("new worker did not serve alongside the retiring worker: %q", got)
	}
	// After the old worker drains and exits, the inherited socket keeps
	// accepting new connections without rebinding the port.
	conn.Close()
	select {
	case <-old.done:
	case <-ctx.Done():
		t.Fatal("old worker did not exit after its connection closed")
	}
	if got := request(newConn, newReader, "ping"); got != "new:ping\n" {
		t.Fatalf("new worker replied %q", got)
	}
}

func TestLinuxHotUpgradeWorker(t *testing.T) {
	version := os.Getenv(upgradeTestWorkerEnv)
	if version == "" {
		return
	}
	if version == "fail" {
		os.Exit(1)
	}
	worker, err := openUpgradeWorker(os.Getenv(upgradeListenersEnv), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	listener, err := worker.Listener(0)
	if err != nil {
		t.Fatal(err)
	}
	listenerClosed := make(chan struct{})
	go func() {
		<-worker.Retire()
		listener.Close()
		close(listenerClosed)
	}()
	if err := worker.Ready(); err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		connections.Go(func() {
			defer conn.Close()
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				if scanner.Text() == "await-retirement" {
					<-listenerClosed
				}
				if _, err := fmt.Fprintf(conn, "%s:%s\n", version, scanner.Text()); err != nil {
					return
				}
			}
		})
	}
	connections.Wait()
}
