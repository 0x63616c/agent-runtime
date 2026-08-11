//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
)

// runGuestCommandWithSecret consumes a previously authenticated contextual
// secret only through guestSecretSink's fixed sealed descriptor path. Any
// launch failure before binding aborts delivery; after Start it requires tree
// reaping, revocation, and manager zeroization before returning output.
func runGuestCommandWithSecret(ctx context.Context, payload []byte, manager *sandboxauthority.Manager, sink *guestSecretSink, request sandboxauthority.SecretRequest, now time.Time, verifier guestTreeReapVerifier) (guestCommandResult, error) {
	if ctx == nil || manager == nil || sink == nil || verifier == nil {
		return guestCommandResult{}, fmt.Errorf("run guest secret command: required lifecycle authority is absent")
	}
	containment, ok := verifier.(guestProcessContainmentVerifier)
	if !ok {
		return guestCommandResult{}, fmt.Errorf("run guest secret command: cgroup process containment verifier is required")
	}
	command, err := decodeGuestCommand(payload)
	if err != nil {
		return guestCommandResult{}, err
	}
	if err := manager.Deliver(ctx, request, now); err != nil {
		return guestCommandResult{}, fmt.Errorf("deliver guest command secret: %w", err)
	}
	abort := true
	defer func() {
		if abort {
			_ = manager.AbortBeforeStart(context.Background(), request.ProcessID)
		}
	}()

	process := exec.Command(command.Argv[0], command.Argv[1:]...)
	process.Dir = command.WorkingDirectory
	process.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr boundedGuestOutput
	process.Stdout, process.Stderr = &stdout, &stderr
	closeChild, err := sink.AttachToCommand(request, process)
	if err != nil {
		return guestCommandResult{}, err
	}
	if err := process.Start(); err != nil {
		_ = closeChild()
		return guestCommandResult{}, fmt.Errorf("start typed guest secret command: %w", err)
	}
	if err := closeChild(); err != nil {
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
		_ = process.Wait()
		return guestCommandResult{}, fmt.Errorf("close inherited guest secret fd: %w", err)
	}
	if err := containment.VerifyProcessContained(ctx, process.Process.Pid); err != nil {
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
		_ = process.Wait()
		abort = false // the descriptor may have reached the process; retain fail-closed ownership.
		return guestCommandResult{}, fmt.Errorf("contain typed guest secret command: %w", err)
	}
	if err := sink.BindRunningProcess(ctx, request, process.Process.Pid); err != nil {
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
		_ = process.Wait()
		abort = false // the descriptor may have reached the process; retain fail-closed ownership.
		return guestCommandResult{}, fmt.Errorf("bind typed guest secret command: %w", err)
	}
	abort = false
	processErr := waitForGuestSecretProcess(ctx, process)
	reapContext, cancel := context.WithTimeout(context.Background(), maximumShutdownDuration)
	defer cancel()
	if err := sink.ConfirmTreeReaped(reapContext, request, verifier); err != nil {
		return guestCommandResult{}, err
	}
	redactions := manager.RedactionValues(request.ProcessID)
	result := guestCommandResult{stdout: redactGuestSecretOutput(stdout.Bytes(), redactions), stderr: redactGuestSecretOutput(stderr.Bytes(), redactions)}
	for _, value := range redactions {
		zeroGuestSecretBytes(value)
	}
	if err := manager.RevokeAfterTreeReap(reapContext, request.ProcessID); err != nil {
		return guestCommandResult{}, err
	}
	if stdout.overflow || stderr.overflow {
		return guestCommandResult{}, fmt.Errorf("guest secret command output exceeded bounded limit")
	}
	if processErr != nil {
		return result, fmt.Errorf("wait typed guest secret command: %w", processErr)
	}
	return result, nil
}

func waitForGuestSecretProcess(ctx context.Context, process *exec.Cmd) error {
	waited := make(chan error, 1)
	go func() { waited <- process.Wait() }()
	select {
	case err := <-waited:
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGTERM)
		reapContext, cancel := context.WithTimeout(context.Background(), maximumShutdownDuration)
		defer cancel()
		select {
		case err := <-waited:
			return joinGuestSecretProcessError(ctx.Err(), err)
		case <-reapContext.Done():
			_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
			return joinGuestSecretProcessError(ctx.Err(), <-waited)
		}
	}
}

func redactGuestSecretOutput(output []byte, values [][]byte) []byte {
	redacted := append([]byte(nil), output...)
	for _, value := range values {
		if len(value) > 0 {
			redacted = bytes.ReplaceAll(redacted, value, []byte("[REDACTED]"))
		}
	}
	return redacted
}

func zeroGuestSecretBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func joinGuestSecretProcessError(left, right error) error {
	if left != nil {
		return left
	}
	return right
}
