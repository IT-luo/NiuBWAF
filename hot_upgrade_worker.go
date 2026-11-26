package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

const (
	upgradeReady    byte = 'R'
	upgradeActivate byte = 'A'
	upgradeRetire   byte = 'D'
)

// An upgrade worker may initialize its listeners and HTTP servers immediately.
// Accept waits at the activation gate until the supervisor has received Ready.
type upgradeWorker struct {
	listeners []*upgradeListener
	ready     *os.File
	control   *os.File
	scope     string
	relay     string
	active    chan struct{}
	retired   chan struct{}
}

func (w *upgradeWorker) Listener(index int) (net.Listener, error) {
	if index < 0 || index >= len(w.listeners) {
		return nil, fmt.Errorf("升级监听器索引无效: %d", index)
	}
	if w.listeners[index] == nil {
		return nil, nil
	}
	return w.listeners[index], nil
}

func (w *upgradeWorker) SessionScope() string    { return w.scope }
func (w *upgradeWorker) HubRelayAddress() string { return w.relay }
func (w *upgradeWorker) Retire() <-chan struct{} { return w.retired }

func (w *upgradeWorker) Ready() error {
	_, err := w.ready.Write([]byte{upgradeReady})
	if err != nil {
		return fmt.Errorf("通知热升级就绪失败: %w", err)
	}
	select {
	case <-w.active:
		return nil
	case <-w.retired:
		select {
		case <-w.active:
			// A second upgrade may retire this worker as Ready returns.
			return nil
		default:
			return fmt.Errorf("工作进程就绪后未收到激活信号")
		}
	}
}

func (w *upgradeWorker) Close() {
	_ = w.ready.Close()
	_ = w.control.Close()
	for _, listener := range w.listeners {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

func (w *upgradeWorker) receiveCommands() {
	// Supervisor loss also stops this worker from taking new connections.
	defer close(w.retired)
	var cmd [1]byte
	if _, err := io.ReadFull(w.control, cmd[:]); err != nil || cmd[0] != upgradeActivate {
		return
	}
	_, err := w.ready.Write([]byte{upgradeActivate})
	_ = w.ready.Close()
	if err != nil {
		return
	}
	close(w.active)
	// The only following command is retirement. EOF takes the same path.
	_, _ = io.ReadFull(w.control, cmd[:])
}

type upgradeListener struct {
	net.Listener
	active  <-chan struct{}
	retired <-chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (l *upgradeListener) Accept() (net.Conn, error) {
	select {
	case <-l.active:
	case <-l.retired:
		return nil, net.ErrClosed
	case <-l.closed:
		return nil, net.ErrClosed
	}
	select {
	case <-l.retired:
		return nil, net.ErrClosed
	default:
		return l.Listener.Accept()
	}
}

func (l *upgradeListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.Listener.Close()
	})
	return err
}
