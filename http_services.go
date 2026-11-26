package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"
)

type httpService struct {
	name           string
	server         *http.Server
	useTLS         bool
	certFile       string
	keyFile        string
	maxConnections int
	optional       bool
}

type serviceUpgrade interface {
	Listener(index int) (net.Listener, error)
	Ready() error
	Retire() <-chan struct{}
}

type boundService struct {
	httpService
	listener net.Listener
	limited  net.Listener
}

type acceptedConnections struct {
	mu    sync.Mutex
	open  map[*trackedConn]struct{}
	count sync.WaitGroup
}

type trackedConn struct {
	net.Conn
	all  *acceptedConnections
	once sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.all.mu.Lock()
		delete(c.all.open, c)
		c.all.mu.Unlock()
		c.all.count.Done()
	})
	return err
}

func (c *acceptedConnections) close() {
	c.mu.Lock()
	open := make([]*trackedConn, 0, len(c.open))
	for conn := range c.open {
		open = append(open, conn)
	}
	c.mu.Unlock()
	for _, conn := range open {
		conn.Close()
	}
}

type trackingListener struct {
	net.Listener
	all       *acceptedConnections
	first     sync.Once
	accepting func()
}

func (l *trackingListener) Accept() (net.Conn, error) {
	l.first.Do(l.accepting)
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &trackedConn{Conn: conn, all: l.all}
	l.all.count.Add(1)
	l.all.mu.Lock()
	l.all.open[tracked] = struct{}{}
	l.all.mu.Unlock()
	return tracked, nil
}

func (s boundService) serve(l net.Listener) error {
	var err error
	if s.useTLS {
		err = s.server.ServeTLS(l, s.certFile, s.keyFile)
	} else {
		err = s.server.Serve(l)
	}
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("%s服务失败: %w", s.name, err)
}

func runHTTPServices(ctx context.Context, services []httpService, upgrade serviceUpgrade, onActive, onRetire func()) error {
	var bound []boundService
	closeListeners := func() {
		for _, service := range bound {
			if service.limited != nil {
				service.limited.Close()
			} else {
				service.listener.Close()
			}
		}
	}
	defer closeListeners()
	for i, service := range services {
		var listener net.Listener
		var err error
		if upgrade != nil {
			listener, err = upgrade.Listener(i)
		} else {
			listener, err = net.Listen("tcp", service.server.Addr)
			if err != nil && service.optional {
				log.Printf("%s监听失败: %v", service.name, err)
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("%s监听 %s 失败: %w", service.name, service.server.Addr, err)
		}
		if listener == nil {
			if service.optional {
				continue
			}
			return fmt.Errorf("%s缺少继承的监听器", service.name)
		}
		bound = append(bound, boundService{httpService: service, listener: listener})
	}
	if len(bound) == 0 {
		return errors.New("没有可用的 HTTP 监听器")
	}

	all := &acceptedConnections{open: make(map[*trackedConn]struct{})}
	ready := make(chan struct{})
	var waiting atomic.Int32
	waiting.Store(int32(len(bound)))
	results := make(chan error, len(bound))
	for i := range bound {
		service := &bound[i]
		tracked := &trackingListener{Listener: service.listener, all: all, accepting: func() {
			if waiting.Add(-1) == 0 {
				close(ready)
			}
		}}
		service.limited = netutil.LimitListener(tracked, service.maxConnections)
		go func() {
			defer service.limited.Close()
			results <- service.serve(service.limited)
		}()
	}

	var retire <-chan struct{}
	if upgrade != nil {
		retire = upgrade.Retire()
	}
	remaining, retired, runErr := waitForServiceChange(ctx, upgrade, ready, retire, results, len(bound), onActive)
	if retired {
		// Closing listeners stops Accept without canceling any accepted TCP
		// connection, including HTTP/2 and hijacked WebSocket connections.
		closeListeners()
		onRetire()
		for ; remaining > 0; remaining-- {
			runErr = errors.Join(runErr, <-results)
		}
		drained := make(chan struct{})
		go func() {
			all.count.Wait()
			close(drained)
		}()
		select {
		case <-drained:
			return runErr
		case <-ctx.Done():
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdown := make(chan struct{}, len(bound))
	for _, service := range bound {
		go func() {
			if err := service.server.Shutdown(shutdownCtx); err != nil {
				log.Printf("%s停机等待超时: %v", service.name, err)
				service.server.Close()
			}
			shutdown <- struct{}{}
		}()
	}
	for ; remaining > 0; remaining-- {
		runErr = errors.Join(runErr, <-results)
	}
	for range bound {
		<-shutdown
	}
	// http.Server does not own connections that a handler hijacked.
	all.close()
	return runErr
}

func waitForServiceChange(ctx context.Context, upgrade serviceUpgrade, ready, retire <-chan struct{}, results <-chan error, remaining int, onActive func()) (int, bool, error) {
	for {
		select {
		case <-ctx.Done():
			return remaining, false, nil
		case <-ready:
			ready = nil
			if upgrade != nil {
				if err := upgrade.Ready(); err != nil {
					return remaining, false, err
				}
			}
			onActive()
		case <-retire:
			return remaining, true, nil
		case err := <-results:
			select {
			case <-retire:
				return remaining - 1, true, err
			case <-ctx.Done():
				return remaining - 1, false, err
			default:
			}
			if err == nil {
				err = errors.New("HTTP 服务意外停止")
			}
			return remaining - 1, false, err
		}
	}
}
