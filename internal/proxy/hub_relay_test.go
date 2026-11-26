package proxy

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestHubRelayKeepsRetiredSubscribers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay := &hubRelayServer{peers: make(map[*hubRelayPeer]struct{})}
	old, current := NewHub(), NewHub()
	for _, hub := range []*Hub{old, current} {
		workerConn, relayConn := net.Pipe()
		if !relay.addPeer(relayConn) {
			t.Fatal("relay refused a worker")
		}
		if err := hub.connectRelay(ctx, workerConn); err != nil {
			t.Fatal(err)
		}
	}
	verifyRelayHandoff(t, old, current)
}

func TestHubRelayUnixSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix socket relay runs on Linux")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, closeRelay, err := NewHubRelay(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRelay()
	if fi, err := os.Stat(filepath.Dir(address)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0700 {
		t.Fatalf("relay directory mode = %v, want 0700", fi.Mode().Perm())
	}
	old, current := NewHub(), NewHub()
	for _, hub := range []*Hub{old, current} {
		if err := hub.ConnectRelay(ctx, address); err != nil {
			t.Fatal(err)
		}
	}
	verifyRelayHandoff(t, old, current)
}

func verifyRelayHandoff(t *testing.T, old, current *Hub) {
	t.Helper()
	retiredStream := old.Subscribe()
	currentStream := current.Subscribe()
	old.Retire()
	old.Broadcast(map[string]any{"type": "qps"})

	// Both subscribers see the current worker's rate frame. The old one's
	// frame must not precede it, and the new one must not be echoed.
	current.Broadcast(map[string]any{"type": "qps", "qps": 12})
	const currentRate = `{"qps":12,"type":"qps"}`
	requireRelayEvent(t, retiredStream, currentRate)
	requireRelayEvent(t, currentStream, currentRate)

	// Existing proxied connections may still emit attack events on the old
	// worker. Preserve these without re-broadcasting an event to its sender.
	old.Broadcast(map[string]any{"type": "attack"})
	requireRelayEvent(t, retiredStream, `{"type":"attack"}`)
	requireRelayEvent(t, currentStream, `{"type":"attack"}`)
	current.Broadcast(map[string]any{"type": "alert"})
	requireRelayEvent(t, retiredStream, `{"type":"alert"}`)
	requireRelayEvent(t, currentStream, `{"type":"alert"}`)
}

func TestHubRelayBoundsFramesWithoutBlockingPublisher(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	peer := newHubRelayPeer(left)
	defer peer.close()
	hub := NewHub()
	hub.relay = peer
	large := make([]byte, hubRelayMaxEvent+1)
	peer.enqueue(large)
	if len(peer.pending) != 0 {
		t.Fatal("oversize relay event was enqueued")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < hubRelayQueue*2; i++ {
			hub.Broadcast(map[string]any{"type": "attack"})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher waited for a relay peer to catch up")
	}
	if queued := len(peer.pending); queued != hubRelayQueue {
		t.Fatalf("outgoing queue length = %d, want %d", queued, hubRelayQueue)
	}
}

func requireRelayEvent(t *testing.T, stream <-chan []byte, want string) {
	t.Helper()
	select {
	case event := <-stream:
		if string(event) != want {
			t.Fatalf("event = %s, want %s", event, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", want)
	}
}
