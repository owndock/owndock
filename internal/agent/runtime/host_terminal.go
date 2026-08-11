package agentruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const maximumHostTerminalTerminationGrace = 30 * time.Second

var ErrHostTerminalConfiguration = errors.New("Agent host terminal configuration is invalid")

// HostTerminalConfig is local, trusted Agent configuration. None of these
// values are accepted from the Server or browser.
type HostTerminalConfig struct {
	User             string
	Shell            string
	TerminationGrace time.Duration
}

type HostTerminalExecutor struct {
	user             *user.User
	shell            string
	terminationGrace time.Duration
}

func NewHostTerminalExecutor(config HostTerminalConfig) (*HostTerminalExecutor, error) {
	return newHostTerminalExecutor(config, user.Current)
}

func newHostTerminalExecutor(
	config HostTerminalConfig,
	currentUser func() (*user.User, error),
) (*HostTerminalExecutor, error) {
	if currentUser == nil || config.TerminationGrace <= 0 ||
		config.TerminationGrace > maximumHostTerminalTerminationGrace ||
		!supportedHostTerminalShell(config.Shell) {
		return nil, ErrHostTerminalConfiguration
	}
	account, err := currentUser()
	if err != nil || account == nil || account.Username != config.User ||
		account.Uid == "" || !filepath.IsAbs(account.HomeDir) {
		return nil, ErrHostTerminalConfiguration
	}
	resolved, err := filepath.EvalSymlinks(config.Shell)
	if err != nil {
		return nil, ErrHostTerminalConfiguration
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, ErrHostTerminalConfiguration
	}
	return &HostTerminalExecutor{
		user: account, shell: config.Shell,
		terminationGrace: config.TerminationGrace,
	}, nil
}

func supportedHostTerminalShell(value string) bool {
	switch value {
	case "/bin/sh", "/bin/bash", "/bin/ash":
		return true
	default:
		return false
	}
}

// OpenHostTerminal starts exactly the locally configured shell as the Agent's
// effective operating-system user. The Agent never switches identity and
// never accepts a command, user, environment, directory, or shell from the
// control channel.
func (e *HostTerminalExecutor) OpenHostTerminal(
	ctx context.Context,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if open.Kind != agentprotocol.TerminalKindHost || open.Validate() != nil {
		return nil, ErrTerminalTargetUnavailable
	}
	command := exec.Command(e.shell)
	command.Args = []string{e.shell}
	command.Dir = e.user.HomeDir
	command.Env = []string{
		"HOME=" + e.user.HomeDir,
		"USER=" + e.user.Username,
		"LOGNAME=" + e.user.Username,
		"SHELL=" + e.shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm-256color",
		"LANG=C.UTF-8",
	}
	terminal, err := pty.StartWithSize(command, &pty.Winsize{
		Rows: open.Rows,
		Cols: open.Columns,
	})
	if err != nil {
		return nil, ErrTerminalStreamUnavailable
	}
	stream := &hostTerminalStream{
		terminal: terminal,
		process:  command.Process,
		grace:    e.terminationGrace,
		exited:   make(chan struct{}),
	}
	go func() {
		_ = command.Wait()
		close(stream.exited)
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-stream.exited:
		}
	}()
	return stream, nil
}

type hostTerminalStream struct {
	terminal  *os.File
	process   *os.Process
	grace     time.Duration
	exited    chan struct{}
	closeOnce sync.Once
}

func (s *hostTerminalStream) Read(payload []byte) (int, error) {
	read, err := s.terminal.Read(payload)
	if errors.Is(err, syscall.EIO) {
		err = io.EOF
	}
	return read, err
}

func (s *hostTerminalStream) Write(payload []byte) (int, error) {
	return s.terminal.Write(payload)
}

func (s *hostTerminalStream) Resize(
	ctx context.Context,
	columns, rows uint16,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if columns < 1 || rows < 1 || columns > agentprotocol.MaximumTerminalColumns ||
		rows > agentprotocol.MaximumTerminalRows {
		return agentprotocol.ErrTerminalFrameInvalid
	}
	select {
	case <-s.exited:
		return ErrTerminalStreamUnavailable
	default:
	}
	if err := pty.Setsize(s.terminal, &pty.Winsize{Rows: rows, Cols: columns}); err != nil {
		return ErrTerminalStreamUnavailable
	}
	return nil
}

func (s *hostTerminalStream) Close() error {
	s.closeOnce.Do(func() {
		select {
		case <-s.exited:
		default:
			signalProcessTree(s.process, syscall.SIGTERM)
			// Closing the controlling PTY delivers hangup semantics to the
			// foreground job and prevents descendants from keeping the session
			// alive merely by retaining the terminal file descriptor.
			_ = s.terminal.Close()
			timer := time.NewTimer(s.grace)
			select {
			case <-s.exited:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
				signalProcessTree(s.process, syscall.SIGKILL)
				<-s.exited
			}
		}
		_ = s.terminal.Close()
	})
	return nil
}

func signalProcessTree(process *os.Process, signal syscall.Signal) {
	if process == nil {
		return
	}
	_ = terminateProcessGroup(process.Pid, signal)
	if signal == syscall.SIGKILL {
		_ = process.Kill()
		return
	}
	_ = process.Signal(signal)
}

func terminateProcessGroup(pid int, signal syscall.Signal) error {
	if pid < 1 {
		return fmt.Errorf("%w: process", ErrHostTerminalConfiguration)
	}
	err := syscall.Kill(-pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

var _ agentprotocol.TerminalStream = (*hostTerminalStream)(nil)
