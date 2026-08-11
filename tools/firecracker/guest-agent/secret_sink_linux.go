//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
)

const guestSecretChildDescriptor = 3

// guestSecretSink is the guest-only SecretSink implementation for a future
// certified profile. It delivers a sealed anonymous memfd, never an
// environment value, argv value, persistent path, mount, or host descriptor.
// It remains uncomposed until the Linux/KVM cgroup/proc/ptrace profile can
// prove the required complete-tree reaping and containment properties.
type guestSecretSink struct {
	mu     sync.Mutex
	active map[string]*guestSecretDelivery
}

type guestSecretDelivery struct {
	request sandboxauthority.SecretRequest
	memfd   *os.File
	pid     int
	pidfd   int
	bound   bool
	reaped  bool
}

// guestTreeReapVerifier is the future cgroup-aware reaper boundary. A pidfd
// proves only a leader's lifetime, so it is deliberately insufficient to mark
// a delivery reaped without a complete process-tree verifier.
type guestTreeReapVerifier interface {
	VerifyTreeReaped(context.Context, int, int) error
}

func newGuestSecretSink() *guestSecretSink {
	return &guestSecretSink{active: make(map[string]*guestSecretDelivery)}
}

// Deliver writes the supplied transient bytes once to a sealed anonymous
// memfd. It retains no Go copy and makes the descriptor unavailable until a
// separately controlled command launch requests a read-only duplicate.
func (sink *guestSecretSink) Deliver(ctx context.Context, request sandboxauthority.SecretRequest, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink == nil || !validGuestSecretRequest(request) || len(value) == 0 || len(value) > 64<<10 {
		return fmt.Errorf("deliver guest secret: secret authority denied")
	}
	sink.mu.Lock()
	if _, exists := sink.active[request.ProcessID]; exists {
		sink.mu.Unlock()
		return fmt.Errorf("deliver guest secret: duplicate process delivery")
	}
	sink.mu.Unlock()

	fd, err := unix.MemfdCreate("agent-runtime-secret", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return fmt.Errorf("create guest secret memfd: %w", err)
	}
	memfd := os.NewFile(uintptr(fd), "agent-runtime-secret")
	if err := writeGuestSecret(memfd, value); err != nil {
		_ = memfd.Close()
		return err
	}
	if _, err := memfd.Seek(0, 0); err != nil {
		_ = memfd.Close()
		return fmt.Errorf("rewind guest secret memfd: %w", err)
	}
	if _, err := unix.FcntlInt(memfd.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK); err != nil {
		_ = memfd.Close()
		return fmt.Errorf("seal guest secret memfd: %w", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if _, exists := sink.active[request.ProcessID]; exists {
		_ = memfd.Close()
		return fmt.Errorf("deliver guest secret: duplicate process delivery")
	}
	sink.active[request.ProcessID] = &guestSecretDelivery{request: request, memfd: memfd, pidfd: -1}
	return nil
}

// ChildSecretFile returns one read-only duplicate for exec.Cmd.ExtraFiles.
// Its fixed descriptor number is never put in the child environment or argv.
func (sink *guestSecretSink) ChildSecretFile(request sandboxauthority.SecretRequest) (*os.File, error) {
	if sink == nil {
		return nil, fmt.Errorf("duplicate guest secret fd: secret sink unavailable")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	delivery, ok := sink.active[request.ProcessID]
	if !ok || delivery.request != request || delivery.bound || delivery.reaped {
		return nil, fmt.Errorf("duplicate guest secret fd: secret lifecycle conflict")
	}
	path := "/proc/self/fd/" + strconv.Itoa(int(delivery.memfd.Fd()))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("duplicate guest secret fd: %w", err)
	}
	return os.NewFile(uintptr(fd), "agent-runtime-secret-child"), nil
}

// AttachToCommand makes the sealed secret available only as the first
// exec.Cmd.ExtraFiles descriptor. It rejects pre-existing inherited files so
// descriptor 3 cannot be confused or widened by ambient launch state. The
// caller closes the returned duplicate immediately after a successful Start.
func (sink *guestSecretSink) AttachToCommand(request sandboxauthority.SecretRequest, command *exec.Cmd) (func() error, error) {
	if command == nil || len(command.ExtraFiles) != 0 {
		return nil, fmt.Errorf("attach guest secret fd: ambient extra files are refused")
	}
	child, err := sink.ChildSecretFile(request)
	if err != nil {
		return nil, err
	}
	command.ExtraFiles = []*os.File{child}
	return child.Close, nil
}

// BindRunningProcess verifies the launched process inherited only the fixed
// anonymous descriptor, observes that it is not currently ptraced, and opens
// a pidfd. This is an observation/refusal seam, not a claim that Linux ptrace
// or /proc containment has been fully proven.
func (sink *guestSecretSink) BindRunningProcess(ctx context.Context, request sandboxauthority.SecretRequest, pid int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink == nil || pid <= 0 {
		return fmt.Errorf("bind guest secret process: secret lifecycle conflict")
	}
	sink.mu.Lock()
	delivery, ok := sink.active[request.ProcessID]
	if !ok || delivery.request != request || delivery.bound || delivery.reaped {
		sink.mu.Unlock()
		return fmt.Errorf("bind guest secret process: secret lifecycle conflict")
	}
	sink.mu.Unlock()

	path := "/proc/" + strconv.Itoa(pid) + "/fd/" + strconv.Itoa(guestSecretChildDescriptor)
	target, err := os.Readlink(path)
	if err != nil || !strings.HasPrefix(target, "/memfd:agent-runtime-secret") {
		return fmt.Errorf("bind guest secret process: expected anonymous secret descriptor")
	}
	if err := refuseTracedGuestProcess(pid); err != nil {
		return err
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("bind guest secret process pidfd: %w", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	current, ok := sink.active[request.ProcessID]
	if !ok || current != delivery || current.bound || current.reaped {
		_ = unix.Close(pidfd)
		return fmt.Errorf("bind guest secret process: secret lifecycle conflict")
	}
	current.pid = pid
	current.pidfd = pidfd
	current.bound = true
	return nil
}

// ConfirmTreeReaped marks a delivery revocable only after the injected
// cgroup-aware reaper has confirmed every process in its process tree exited.
func (sink *guestSecretSink) ConfirmTreeReaped(ctx context.Context, request sandboxauthority.SecretRequest, verifier guestTreeReapVerifier) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink == nil || verifier == nil {
		return fmt.Errorf("confirm guest secret tree reap: secret lifecycle conflict")
	}
	sink.mu.Lock()
	delivery, ok := sink.active[request.ProcessID]
	if !ok || delivery.request != request || !delivery.bound || delivery.reaped || delivery.pidfd < 0 {
		sink.mu.Unlock()
		return fmt.Errorf("confirm guest secret tree reap: secret lifecycle conflict")
	}
	pid, pidfd := delivery.pid, delivery.pidfd
	sink.mu.Unlock()
	if err := verifyGuestProcessLeaderExited(pidfd); err != nil {
		return err
	}
	if err := verifier.VerifyTreeReaped(ctx, pid, pidfd); err != nil {
		return fmt.Errorf("confirm guest secret tree reap: verifier did not prove complete tree reap")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	current, ok := sink.active[request.ProcessID]
	if !ok || current != delivery || current.reaped {
		return fmt.Errorf("confirm guest secret tree reap: secret lifecycle conflict")
	}
	current.reaped = true
	return nil
}

func verifyGuestProcessLeaderExited(pidfd int) error {
	ready, err := unix.Poll([]unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}, 0)
	if err != nil || ready != 1 {
		return fmt.Errorf("confirm guest secret tree reap: process leader has not exited")
	}
	return nil
}

// RevokeAfterTreeReap closes the sealed memfd and pidfd only after the
// cgroup-aware verifier marked the complete process tree reaped.
func (sink *guestSecretSink) RevokeAfterTreeReap(ctx context.Context, request sandboxauthority.SecretRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink == nil {
		return fmt.Errorf("revoke guest secret: secret lifecycle conflict")
	}
	sink.mu.Lock()
	delivery, ok := sink.active[request.ProcessID]
	if !ok || delivery.request != request || !delivery.reaped {
		sink.mu.Unlock()
		return fmt.Errorf("revoke guest secret: complete tree reap is unproven")
	}
	delete(sink.active, request.ProcessID)
	sink.mu.Unlock()
	if delivery.pidfd >= 0 {
		_ = unix.Close(delivery.pidfd)
	}
	if err := delivery.memfd.Close(); err != nil {
		return fmt.Errorf("revoke guest secret memfd: %w", err)
	}
	return nil
}

// AbortBeforeStart closes a sealed delivery only when no command process was
// ever bound. It is the sole cleanup path for a failed launch before a secret
// descriptor could reach a recipient process.
func (sink *guestSecretSink) AbortBeforeStart(ctx context.Context, request sandboxauthority.SecretRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink == nil {
		return fmt.Errorf("abort guest secret: secret lifecycle conflict")
	}
	sink.mu.Lock()
	delivery, ok := sink.active[request.ProcessID]
	if !ok || delivery.request != request || delivery.bound || delivery.reaped {
		sink.mu.Unlock()
		return fmt.Errorf("abort guest secret: recipient process state is not prestart")
	}
	delete(sink.active, request.ProcessID)
	sink.mu.Unlock()
	if err := delivery.memfd.Close(); err != nil {
		return fmt.Errorf("abort guest secret memfd: %w", err)
	}
	return nil
}

func writeGuestSecret(file *os.File, value []byte) error {
	for len(value) > 0 {
		written, err := file.Write(value)
		if err != nil {
			return fmt.Errorf("write guest secret memfd: %w", err)
		}
		if written <= 0 {
			return fmt.Errorf("write guest secret memfd: short write")
		}
		value = value[written:]
	}
	return nil
}

func refuseTracedGuestProcess(pid int) error {
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return fmt.Errorf("inspect guest secret process status: %w", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			tracer, parseErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:")))
			if parseErr != nil || tracer != 0 {
				return fmt.Errorf("bind guest secret process: traced process refused")
			}
			return nil
		}
	}
	return fmt.Errorf("bind guest secret process: missing ptrace status")
}

func validGuestSecretRequest(request sandboxauthority.SecretRequest) bool {
	return request.Principal != "" && request.SandboxID != "" && request.ProcessID != "" && request.OperationID != "" && request.Binding != "" && request.Purpose != "" && !request.ExpiresAt.IsZero()
}
