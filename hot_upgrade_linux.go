package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"niubwaf/internal/proxy"
)

const (
	upgradeListenersEnv = "NIUBWAF_HOT_UPGRADE_LISTENERS"
	upgradeScopeEnv     = "NIUBWAF_HOT_UPGRADE_SCOPE"
	upgradeHubEnv       = "NIUBWAF_HOT_UPGRADE_HUB"
	upgradeReadyFD      = 3
	upgradeCommandFD    = 4
	upgradeFirstFD      = 5
	upgradeStartLimit   = 90 * time.Second
	upgradeStopLimit    = 15 * time.Second
)

// The first process keeps the listening sockets and its PID for the lifetime of
// the service. Workers inherit duplicates, so closing a retiring worker's
// listener leaves the accept queue and existing TCP connections intact.
func startHotUpgrade(enabled bool, addresses []string) (*upgradeWorker, bool, error) {
	if layout, inherited := os.LookupEnv(upgradeListenersEnv); inherited {
		if !enabled {
			return nil, false, errors.New("收到继承的监听器但未启用进程热升级")
		}
		worker, err := openUpgradeWorker(layout, len(addresses))
		return worker, false, err
	}
	if !enabled {
		return nil, false, nil
	}
	path, err := os.Executable()
	if err != nil {
		return nil, true, fmt.Errorf("定位热升级程序失败: %w", err)
	}
	// Capture the name before replacing the file, rather than resolving the
	// supervisor's /proc/self/exe on each update.
	if launchPath, lookupErr := exec.LookPath(os.Args[0]); lookupErr == nil {
		running, runningErr := os.Stat(path)
		launched, launchErr := os.Stat(launchPath)
		if runningErr == nil && launchErr == nil && os.SameFile(running, launched) {
			path = launchPath
		}
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, true, fmt.Errorf("解析热升级程序路径失败: %w", err)
	}
	return nil, true, superviseHotUpgrades(path, os.Args[1:], addresses)
}

func openUpgradeWorker(layout string, count int) (*upgradeWorker, error) {
	scope := os.Getenv(upgradeScopeEnv)
	decodedScope, err := base64.RawURLEncoding.DecodeString(scope)
	if len(layout) != count || err != nil || len(decodedScope) != 32 {
		return nil, errors.New("热升级监听器布局或会话标识无效")
	}
	w := &upgradeWorker{
		listeners: make([]*upgradeListener, count),
		ready:     os.NewFile(upgradeReadyFD, "hot-upgrade-ready"),
		control:   os.NewFile(upgradeCommandFD, "hot-upgrade-command"),
		scope:     scope,
		relay:     os.Getenv(upgradeHubEnv),
		active:    make(chan struct{}),
		retired:   make(chan struct{}),
	}
	syscall.CloseOnExec(upgradeReadyFD)
	syscall.CloseOnExec(upgradeCommandFD)
	fd := uintptr(upgradeFirstFD)
	for i, slot := range layout {
		if slot == '0' {
			continue
		}
		if slot != '1' {
			w.Close()
			return nil, errors.New("热升级监听器布局无效")
		}
		inherited := os.NewFile(fd, "hot-upgrade-listener")
		syscall.CloseOnExec(int(fd))
		fd++
		listener, err := net.FileListener(inherited)
		_ = inherited.Close()
		if err != nil {
			w.Close()
			return nil, fmt.Errorf("读取继承的监听器 %d 失败: %w", i, err)
		}
		w.listeners[i] = &upgradeListener{
			Listener: listener, active: w.active, retired: w.retired, closed: make(chan struct{}),
		}
	}
	// Only the supervisor acts on HUP. Workers retire through the pipe.
	signal.Ignore(syscall.SIGHUP)
	go w.receiveCommands()
	return w, nil
}

type upgradeProcess struct {
	cmd     *exec.Cmd
	control *os.File
	done    chan struct{}
	waitErr error
}

func (p *upgradeProcess) send(command byte) error {
	_, err := p.control.Write([]byte{command})
	return err
}

func (p *upgradeProcess) kill() {
	_ = p.cmd.Process.Kill()
	<-p.done
}

func superviseHotUpgrades(path string, args, addresses []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)

	var layout strings.Builder
	var sockets []*os.File
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	for _, address := range addresses {
		if address == "" {
			layout.WriteByte('0')
			continue
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("热升级监听 %s 失败: %w", address, err)
		}
		socket, err := listener.(*net.TCPListener).File()
		_ = listener.Close()
		if err != nil {
			return fmt.Errorf("复制热升级监听 %s 失败: %w", address, err)
		}
		sockets = append(sockets, socket)
		layout.WriteByte('1')
	}

	var randomScope [32]byte
	rand.Read(randomScope[:])
	relay, stopRelay, err := proxy.NewHubRelay(ctx)
	if err != nil {
		return fmt.Errorf("启动热升级事件中继失败: %w", err)
	}
	defer stopRelay()
	env := []string{
		upgradeListenersEnv + "=" + layout.String(),
		upgradeScopeEnv + "=" + base64.RawURLEncoding.EncodeToString(randomScope[:]),
		upgradeHubEnv + "=" + relay,
	}
	start := func() (*upgradeProcess, error) {
		return launchUpgradeProcess(ctx, path, args, env, sockets)
	}
	active, err := start()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("启动首个热升级工作进程失败: %w", err)
	}
	log.Printf("热升级工作进程已就绪 pid=%d", active.cmd.Process.Pid)
	var draining []*upgradeProcess
	defer func() {
		stopUpgradeProcesses(append(draining, active))
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-active.done:
			if ctx.Err() != nil {
				return nil
			}
			if active.waitErr != nil {
				return fmt.Errorf("当前工作进程意外退出: %w", active.waitErr)
			}
			return errors.New("当前工作进程意外退出")
		case <-reload:
			alive := draining[:0]
			for _, retiring := range draining {
				select {
				case <-retiring.done:
				default:
					alive = append(alive, retiring)
				}
			}
			draining = alive
			candidate, err := start()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				log.Printf("热升级失败，继续使用当前工作进程 pid=%d: %v", active.cmd.Process.Pid, err)
				continue
			}
			draining = append(draining, active)
			oldPID := active.cmd.Process.Pid
			if err := active.send(upgradeRetire); err != nil {
				log.Printf("通知旧工作进程 pid=%d 停止接收新连接失败: %v", oldPID, err)
			}
			active = candidate
			log.Printf("工作进程 pid=%d 已接管新连接，旧进程 pid=%d 保留现有连接", active.cmd.Process.Pid, oldPID)
		}
	}
}

func launchUpgradeProcess(ctx context.Context, path string, args, env []string, sockets []*os.File) (*upgradeProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ready, childReady, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer ready.Close()

	childCommand, command, err := os.Pipe()
	if err != nil {
		_ = childReady.Close()
		return nil, err
	}
	cmd := exec.Command(path, args...)
	cmd.Env = append(cmd.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = append([]*os.File{childReady, childCommand}, sockets...)
	err = cmd.Start()
	_ = childReady.Close()
	_ = childCommand.Close()
	if err != nil {
		_ = command.Close()
		return nil, err
	}
	process := &upgradeProcess{cmd: cmd, control: command, done: make(chan struct{})}
	go func() {
		process.waitErr = cmd.Wait()
		_ = process.control.Close()
		close(process.done)
	}()
	timer := time.NewTimer(upgradeStartLimit)
	defer timer.Stop()
	waitReply := func(expected byte) error {
		reply := make(chan error, 1)
		go func() {
			var message [1]byte
			_, err := io.ReadFull(ready, message[:])
			if err == nil && message[0] != expected {
				err = fmt.Errorf("无效的热升级工作进程信号: %q", message[0])
			}
			reply <- err
		}()
		select {
		case err := <-reply:
			return err
		case <-timer.C:
			return errors.New("等待工作进程就绪或激活超时")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	err = waitReply(upgradeReady)
	if err == nil {
		err = process.send(upgradeActivate)
	}
	if err == nil {
		err = waitReply(upgradeActivate)
	}
	if err != nil {
		process.kill()
		return nil, err
	}
	return process, nil
}

func stopUpgradeProcesses(processes []*upgradeProcess) {
	for _, process := range processes {
		_ = process.cmd.Process.Signal(syscall.SIGTERM)
	}
	deadline := time.NewTimer(upgradeStopLimit)
	defer deadline.Stop()
	for i, process := range processes {
		select {
		case <-process.done:
		case <-deadline.C:
			for _, remaining := range processes[i:] {
				_ = remaining.cmd.Process.Kill()
			}
			for _, remaining := range processes[i:] {
				<-remaining.done
			}
			return
		}
	}
}
