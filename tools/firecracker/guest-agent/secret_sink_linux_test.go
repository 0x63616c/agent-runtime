//go:build linux

package main

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
)

func TestGuestSecretSinkDeliversOnlyASealedFDThenRequiresTreeReapProof(t *testing.T) {
	sink := newGuestSecretSink()
	request := guestSecretRequest()
	secret := []byte("transient-only")
	if err := sink.Deliver(context.Background(), request, secret); err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	child, err := sink.ChildSecretFile(request)
	if err != nil {
		t.Fatalf("ChildSecretFile() error = %v", err)
	}
	seals, err := unix.FcntlInt(child.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&(unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL) != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		t.Fatalf("secret fd seals = %d, %v", seals, err)
	}
	stdinReader, stdinWriter := io.Pipe()
	command := exec.Command("/bin/sh", "-c", "cat /proc/self/fd/3; cat")
	command.Stdin = stdinReader
	command.Stdout = new(bytes.Buffer)
	if err := child.Close(); err != nil {
		t.Fatalf("close manual fd before attach: %v", err)
	}
	closeChild, err := sink.AttachToCommand(request, command)
	if err != nil {
		t.Fatalf("AttachToCommand() error = %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := closeChild(); err != nil {
		t.Fatalf("close inherited child fd: %v", err)
	}
	if err := sink.BindRunningProcess(context.Background(), request, command.Process.Pid); err != nil {
		t.Fatalf("BindRunningProcess() error = %v", err)
	}
	if err := sink.RevokeAfterTreeReap(context.Background(), request); err == nil {
		t.Fatal("RevokeAfterTreeReap() accepted an unproved process tree")
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	verifier := guestTreeReapVerifierFunc(func(_ context.Context, pid, pidfd int) error {
		if pid != command.Process.Pid || pidfd < 0 {
			t.Fatalf("tree verification identity = (%d, %d)", pid, pidfd)
		}
		return nil
	})
	if err := sink.ConfirmTreeReaped(context.Background(), request, verifier); err != nil {
		t.Fatalf("ConfirmTreeReaped() error = %v", err)
	}
	if err := sink.RevokeAfterTreeReap(context.Background(), request); err != nil {
		t.Fatalf("RevokeAfterTreeReap() error = %v", err)
	}
}

func TestGuestSecretSinkRefusesAProcessWithoutTheFixedAnonymousDescriptor(t *testing.T) {
	sink := newGuestSecretSink()
	request := guestSecretRequest()
	if err := sink.Deliver(context.Background(), request, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/cat")
	stdinReader, stdinWriter := io.Pipe()
	command.Stdin = stdinReader
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	defer stdinWriter.Close()
	if err := sink.BindRunningProcess(context.Background(), request, command.Process.Pid); err == nil {
		t.Fatal("BindRunningProcess() accepted a process without the secret fd")
	}
}

type guestTreeReapVerifierFunc func(context.Context, int, int) error

func (verifier guestTreeReapVerifierFunc) VerifyTreeReaped(ctx context.Context, pid, pidfd int) error {
	return verifier(ctx, pid, pidfd)
}

func guestSecretRequest() sandboxauthority.SecretRequest {
	return sandboxauthority.SecretRequest{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", Binding: "binding-001", Purpose: "command", ExpiresAt: time.Date(2026, 8, 10, 0, 1, 0, 0, time.UTC)}
}
