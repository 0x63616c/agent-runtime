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

type guestCommandResult struct{ stdout, stderr []byte }

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
	if err := process.Start(); err != nil {
		return guestCommandResult{}, fmt.Errorf("start typed guest command: %w", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- process.Wait() }()
	select {
	case err := <-waited:
		if err != nil {
			return guestCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}, fmt.Errorf("wait typed guest command: %w", err)
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
		return guestCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}, ctx.Err()
	}
	if stdout.overflow || stderr.overflow {
		return guestCommandResult{}, fmt.Errorf("guest command output exceeded bounded limit")
	}
	return guestCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}, nil
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
	return filepath.IsAbs(directory) && filepath.Clean(directory) == directory && directory != "/" && !strings.HasPrefix(directory, "/proc/") && !strings.HasPrefix(directory, "/sys/") && !strings.HasPrefix(directory, "/dev/") && !strings.HasPrefix(directory, "/run/")
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
