package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	hubRelayMaxEvent = 32 << 10
	hubRelayQueue    = 64
	hubRelayTimeout  = 5 * time.Second
	hubRelayReady    = 1
)

type hubRelayPeer struct {
	conn      net.Conn
	pending   chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func newHubRelayPeer(conn net.Conn) *hubRelayPeer {
	return &hubRelayPeer{conn: conn, pending: make(chan []byte, hubRelayQueue), done: make(chan struct{})}
}

func (p *hubRelayPeer) close() {
	p.closeOnce.Do(func() {
		close(p.done)
		p.conn.Close()
	})
}

func (p *hubRelayPeer) enqueue(data []byte) {
	if len(data) == 0 || len(data) > hubRelayMaxEvent {
		return
	}
	select {
	case p.pending <- data:
	default: // A slow peer cannot block the proxy or other SSE subscribers.
	}
}

func (p *hubRelayPeer) writeFrames() {
	defer p.close()
	var header [4]byte
	for {
		select {
		case <-p.done:
			return
		case data := <-p.pending:
			binary.BigEndian.PutUint32(header[:], uint32(len(data)))
			if err := p.conn.SetWriteDeadline(time.Now().Add(hubRelayTimeout)); err != nil {
				return
			}
			buffers := net.Buffers{header[:], data}
			if _, err := buffers.WriteTo(p.conn); err != nil {
				return
			}
		}
	}
}

func (p *hubRelayPeer) run(receive func([]byte)) {
	defer p.close()
	go p.writeFrames()
	var header [4]byte
	for {
		if _, err := io.ReadFull(p.conn, header[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > hubRelayMaxEvent {
			return
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(p.conn, data); err != nil || !json.Valid(data) {
			return
		}
		receive(data)
	}
}

type hubRelayServer struct {
	mu     sync.Mutex
	peers  map[*hubRelayPeer]struct{}
	closed bool
}

// NewHubRelay opens a local, same-user event relay for the worker generations.
// The supervisor owns the socket and keeps it available during handoff.
func NewHubRelay(ctx context.Context) (address string, closeRelay func(), err error) {
	if runtime.GOOS != "linux" {
		return "", nil, errors.New("进程间事件转发仅支持 Linux")
	}
	dir, err := os.MkdirTemp("", "niubwaf-hub-")
	if err != nil {
		return "", nil, err
	}
	address = filepath.Join(dir, "events.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		os.Remove(dir)
		return "", nil, err
	}
	s := &hubRelayServer{peers: make(map[*hubRelayPeer]struct{})}
	var closeOnce sync.Once
	closeRelay = func() {
		closeOnce.Do(func() {
			listener.Close()
			s.mu.Lock()
			s.closed = true
			for p := range s.peers {
				p.close()
			}
			s.mu.Unlock()
			os.Remove(dir)
		})
	}
	stop := context.AfterFunc(ctx, closeRelay)
	go func() {
		defer stop()
		defer closeRelay()
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			if !s.addPeer(conn) {
				return
			}
		}
	}()
	return address, closeRelay, nil
}

func (s *hubRelayServer) addPeer(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		conn.Close()
		return false
	}
	p := newHubRelayPeer(conn)
	s.peers[p] = struct{}{}
	go s.runPeer(p)
	return true
}

func (s *hubRelayServer) runPeer(p *hubRelayPeer) {
	defer func() {
		s.mu.Lock()
		delete(s.peers, p)
		s.mu.Unlock()
		p.close()
	}()
	if err := p.conn.SetWriteDeadline(time.Now().Add(hubRelayTimeout)); err != nil {
		return
	}
	if _, err := p.conn.Write([]byte{hubRelayReady}); err != nil {
		return
	}
	p.run(func(data []byte) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for target := range s.peers {
			if target != p {
				target.enqueue(data)
			}
		}
	})
}

// ConnectRelay connects this worker before it begins serving. Remote events
// are delivered locally without being published back to the relay.
func (h *Hub) ConnectRelay(ctx context.Context, address string) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", address)
	if err != nil {
		return err
	}
	return h.connectRelay(ctx, conn)
}

func (h *Hub) connectRelay(ctx context.Context, conn net.Conn) error {
	p := newHubRelayPeer(conn)
	stop := context.AfterFunc(ctx, p.close)
	if err := waitHubRelayReady(conn); err != nil {
		stop()
		p.close()
		return fmt.Errorf("事件转发服务握手失败: %w", err)
	}
	h.mu.Lock()
	if h.relay != nil {
		h.mu.Unlock()
		stop()
		p.close()
		return errors.New("已连接事件转发服务")
	}
	h.relay = p
	h.mu.Unlock()
	go func() {
		defer stop()
		defer func() {
			h.mu.Lock()
			h.relay = nil
			h.mu.Unlock()
		}()
		p.run(func(data []byte) {
			h.mu.Lock()
			h.broadcastLocked(data)
			h.mu.Unlock()
		})
	}()
	return nil
}

func waitHubRelayReady(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(hubRelayTimeout)); err != nil {
		return err
	}
	var ready [1]byte
	if _, err := io.ReadFull(conn, ready[:]); err != nil {
		return err
	}
	if ready[0] != hubRelayReady {
		return errors.New("无效的事件转发握手")
	}
	return conn.SetReadDeadline(time.Time{})
}

// Retire stops the local rate feed after connection acceptance is handed off.
// The old worker still publishes events and receives frames for its open SSEs.
func (h *Hub) Retire() {
	h.pauseRateFeed(true)
}

func (h *Hub) pauseRateFeed(paused bool) {
	h.mu.Lock()
	h.ratePaused = paused
	h.mu.Unlock()
}
