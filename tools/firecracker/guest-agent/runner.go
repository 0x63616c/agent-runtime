package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	guestCommandVersion            = "agent-runtime.guest-command/v1"
	maximumGuestArgv               = 64
	maximumGuestArgumentBytes      = 4096
	maximumGuestCommandOutputBytes = 32 << 10
)

// guestCommand is the typed, guest-only command contract. It deliberately has
// no shell, inherited environment, secret bytes, host path, mount, or network
// configuration surface.
type guestCommand struct {
	Version          string   `json:"version"`
	Argv             []string `json:"argv"`
	WorkingDirectory string   `json:"working_directory"`
}

type guestCommandResult struct {
	stdout, stderr []byte
	terminal       *guestCommandTerminal
}

// guestCommandTerminal records only facts available to the guest after it
// reaps the child it started. It deliberately contains neither sandbox state
// nor host cgroup/retention/cleanup counters.
type guestCommandTerminal struct {
	guestPID   int
	startedAt  time.Time
	finishedAt time.Time
	exitCode   *int32
	signal     string
	reason     string
}

func runGuestCommand(ctx context.Context, payload []byte) (guestCommandResult, error) {
	command, err := decodeGuestCommand(payload)
	if err != nil {
		return guestCommandResult{}, err
	}
	process := exec.Command(command.Argv[0], command.Argv[1:]...)
	process.Dir = command.WorkingDirectory
	process.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr boundedGuestOutput
	process.Stdout, process.Stderr = &stdout, &stderr
	startedAt := time.Now().UTC()
	if err := process.Start(); err != nil {
		return guestCommandResult{}, fmt.Errorf("start typed guest command: %w", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- process.Wait() }()
	select {
	case err := <-waited:
		result := guestCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), terminal: terminalGuestCommand(process, startedAt, time.Now().UTC())}
		if err != nil {
			return result, fmt.Errorf("wait typed guest command: %w", err)
		}
	case <-ctx.Done():
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGTERM)
		reapContext, cancel := context.WithTimeout(context.Background(), maximumShutdownDuration)
		defer cancel()
		select {
		case <-waited:
		case <-reapContext.Done():
			_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
			<-waited
		}
		return guestCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), terminal: terminalGuestCommand(process, startedAt, time.Now().UTC())}, ctx.Err()
	}
	if stdout.overflow || stderr.overflow {
		// Do not return partial output after a bounded-output refusal, but retain
		// the independently reaped child outcome for the terminal frame.
		return guestCommandResult{terminal: terminalGuestCommand(process, startedAt, time.Now().UTC())}, fmt.Errorf("guest command output exceeded bounded limit")
	}
	return guestCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), terminal: terminalGuestCommand(process, startedAt, time.Now().UTC())}, nil
}

func terminalGuestCommand(process *exec.Cmd, startedAt, finishedAt time.Time) *guestCommandTerminal {
	if process == nil || process.Process == nil || process.ProcessState == nil {
		return nil
	}
	terminal := &guestCommandTerminal{guestPID: process.Process.Pid, startedAt: startedAt.UTC(), finishedAt: finishedAt.UTC(), reason: "exited"}
	if status, ok := process.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		terminal.reason, terminal.signal = "signaled", guestSignalName(status.Signal())
		return terminal
	}
	exitCode := int32(process.ProcessState.ExitCode())
	terminal.exitCode = &exitCode
	return terminal
}

func guestSignalName(signal syscall.Signal) string {
	switch signal {
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGQUIT:
		return "SIGQUIT"
	case syscall.SIGILL:
		return "SIGILL"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGFPE:
		return "SIGFPE"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGSEGV:
		return "SIGSEGV"
	case syscall.SIGPIPE:
		return "SIGPIPE"
	case syscall.SIGALRM:
		return "SIGALRM"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGTRAP:
		return "SIGTRAP"
	case syscall.SIGBUS:
		return "SIGBUS"
	case syscall.SIGUSR1:
		return "SIGUSR1"
	case syscall.SIGUSR2:
		return "SIGUSR2"
	case syscall.SIGCHLD:
		return "SIGCHLD"
	case syscall.SIGCONT:
		return "SIGCONT"
	case syscall.SIGSTOP:
		return "SIGSTOP"
	case syscall.SIGTSTP:
		return "SIGTSTP"
	case syscall.SIGTTIN:
		return "SIGTTIN"
	case syscall.SIGTTOU:
		return "SIGTTOU"
	default:
		return ""
	}
}

func decodeGuestCommand(payload []byte) (guestCommand, error) {
	if len(payload) == 0 || len(payload) > 64<<10 {
		return guestCommand{}, fmt.Errorf("invalid bounded guest command")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var command guestCommand
	if err := decoder.Decode(&command); err != nil {
		return guestCommand{}, fmt.Errorf("invalid guest command")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return guestCommand{}, fmt.Errorf("invalid guest command")
	}
	if command.Version != guestCommandVersion || len(command.Argv) == 0 || len(command.Argv) > maximumGuestArgv || !validGuestWorkdir(command.WorkingDirectory) {
		return guestCommand{}, fmt.Errorf("invalid guest command")
	}
	for _, argument := range command.Argv {
		if argument == "" || len(argument) > maximumGuestArgumentBytes || strings.IndexByte(argument, 0) >= 0 {
			return guestCommand{}, fmt.Errorf("invalid guest command")
		}
	}
	return command, nil
}

func validGuestWorkdir(directory string) bool {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return false
	}
	for _, reserved := range []string{"/proc", "/sys", "/dev", "/run"} {
		if directory == reserved || strings.HasPrefix(directory, reserved+"/") {
			return false
		}
	}
	return true
}

type boundedGuestOutput struct {
	bytes.Buffer
	overflow bool
}

func (output *boundedGuestOutput) Write(value []byte) (int, error) {
	if output.Len()+len(value) > maximumGuestCommandOutputBytes {
		remaining := maximumGuestCommandOutputBytes - output.Len()
		if remaining > 0 {
			_, _ = output.Buffer.Write(value[:remaining])
		}
		output.overflow = true
		return len(value), nil
	}
	return output.Buffer.Write(value)
}
