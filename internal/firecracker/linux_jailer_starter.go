package firecracker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	jailerCgroupRoot        = "/sys/fs/cgroup"
	maximumJailerOutputSize = 64 << 10
)

// LinuxJailerStarter starts a checked Linux Jailer process from a compiled execution authority and bound resource stage.
// It is an internal process port and does not itself provide protected-runner, Jailer, or KVM execution evidence.
type LinuxJailerStarter struct {
	goos               string
	kernelCapabilities func() error
	cgroupPrerequisite func(JailerExecutionAuthority) error
	trustArtifact      func(PinnedArtifact) error
	verifyArtifact     func(context.Context, PinnedArtifact) error
	trustStageRoot     func(string) error
	command            func(string, []string, string) jailerCommand
	removeNamespace    func(string) error
	removeCgroup       func(string) error
}

type jailerCommand interface {
	Start() error
	Wait() error
	Signal(os.Signal) error
}

type jailerSerialOutputCommand interface {
	jailerCommand
	SerialOutput() *boundedJailerOutput
}

// Start launches only the Jailer executable, argument vector, cgroup path, and jail namespace bound in request.
func (starter LinuxJailerStarter) Start(ctx context.Context, request JailerStartRequest) (JailerProcess, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if starter.hostOS() != "linux" {
		return nil, fmt.Errorf("%w: Linux Jailer execution requires linux, got %s", ErrCapabilityUnavailable, starter.hostOS())
	}
	if !validJailerExecutionStage(request.Authority, request.Stage) {
		return nil, fmt.Errorf("%w: exact execution authority and bound Jailer stage are required", ErrSmokeUnavailable)
	}
	capabilities := starter.capabilities()
	if err := capabilities(); err != nil {
		return nil, fmt.Errorf("%w: Linux Jailer kernel capabilities: %v", ErrCapabilityUnavailable, err)
	}
	if err := starter.cgroupAuthorityPrerequisite()(request.Authority); err != nil {
		return nil, fmt.Errorf("%w: declared Jailer cgroup authority: %v", ErrCapabilityUnavailable, err)
	}
	trustArtifact := starter.trustedArtifact()
	verifyArtifact := starter.verifyArtifact
	if verifyArtifact == nil {
		verifyArtifact = verifyRegularArtifact
	}
	for _, artifact := range []PinnedArtifact{request.Stage.Jailer, request.Stage.Firecracker.Source} {
		if err := trustArtifact(artifact); err != nil {
			return nil, fmt.Errorf("%w: immutable Jailer launch artifact: %v", ErrSmokeUnavailable, err)
		}
		if err := verifyArtifact(ctx, artifact); err != nil {
			return nil, fmt.Errorf("verify Jailer launch artifact: %w", err)
		}
	}
	trustStageRoot := starter.trustStageRoot
	if trustStageRoot == nil {
		trustStageRoot = trustedJailerDirectory
	}
	if err := trustStageRoot(request.Stage.JailRoot); err != nil {
		return nil, fmt.Errorf("%w: trusted staged Jailer root: %v", ErrSmokeUnavailable, err)
	}
	commandFactory := starter.command
	if commandFactory == nil {
		commandFactory = newOSJailerCommand
	}
	command := commandFactory(request.Stage.Jailer.Path, request.Authority.Arguments(), request.Stage.JailRoot)
	if command == nil {
		return nil, fmt.Errorf("%w: Jailer command factory is required", ErrSmokeUnavailable)
	}
	serialCommand, ok := command.(jailerSerialOutputCommand)
	if !ok || serialCommand.SerialOutput() == nil {
		return nil, fmt.Errorf("%w: bounded non-daemonized Jailer serial output is required", ErrSmokeUnavailable)
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start authority-bound Jailer: %w", err)
	}
	process := newLinuxJailerProcess(command, serialCommand.SerialOutput(), request.Authority.CgroupPath(), filepath.Dir(request.Stage.JailRoot), starter.namespaceRemover(), starter.cgroupRemover())
	if err := contextError(ctx); err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), maximumCleanupTimeout)
		defer cancel()
		terminateErr := process.Terminate(cleanupContext)
		_, cleanupErr := process.Cleanup(cleanupContext)
		return nil, errors.Join(err, terminateErr, cleanupErr)
	}
	return process, nil
}

func (starter LinuxJailerStarter) cgroupAuthorityPrerequisite() func(JailerExecutionAuthority) error {
	if starter.cgroupPrerequisite != nil {
		return starter.cgroupPrerequisite
	}
	return validateJailerCgroupPrerequisite
}

func (starter LinuxJailerStarter) trustedArtifact() func(PinnedArtifact) error {
	if starter.trustArtifact != nil {
		return starter.trustArtifact
	}
	return trustedJailerArtifact
}

func (starter LinuxJailerStarter) hostOS() string {
	if starter.goos != "" {
		return starter.goos
	}
	return runtime.GOOS
}

func (starter LinuxJailerStarter) capabilities() func() error {
	if starter.kernelCapabilities != nil {
		return starter.kernelCapabilities
	}
	return linuxJailerKernelCapabilities
}

func (starter LinuxJailerStarter) namespaceRemover() func(string) error {
	if starter.removeNamespace != nil {
		return starter.removeNamespace
	}
	return os.RemoveAll
}

func (starter LinuxJailerStarter) cgroupRemover() func(string) error {
	if starter.removeCgroup != nil {
		return starter.removeCgroup
	}
	return os.Remove
}

func linuxJailerKernelCapabilities() error {
	if os.Geteuid() != 0 {
		return errors.New("root Jailer identity is required")
	}
	device, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/kvm read/write: %w", err)
	}
	if err := device.Close(); err != nil {
		return fmt.Errorf("close /dev/kvm: %w", err)
	}
	return nil
}

func validateJailerCgroupPrerequisite(authority JailerExecutionAuthority) error {
	parent := filepath.Join(jailerCgroupRoot, authority.CgroupParent())
	if !safeAbsolutePath(parent) {
		return errors.New("absolute cgroup parent is required")
	}
	if err := trustedJailerDirectory(parent); err != nil {
		return fmt.Errorf("trusted cgroup parent: %w", err)
	}
	controllers, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup controllers: %w", err)
	}
	enabled, err := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control"))
	if err != nil {
		return fmt.Errorf("read cgroup subtree controllers: %w", err)
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		if !containsCgroupController(controllers, controller) || !containsCgroupController(enabled, controller) {
			return fmt.Errorf("cgroup parent does not delegate %s", controller)
		}
	}
	return nil
}

func containsCgroupController(value []byte, controller string) bool {
	for _, candidate := range strings.Fields(string(value)) {
		if candidate == controller {
			return true
		}
	}
	return false
}

func trustedJailerArtifact(artifact PinnedArtifact) error {
	if !validArtifact(artifact) {
		return errors.New("absolute SHA-256-pinned artifact is required")
	}
	if err := trustedJailerDirectory(filepath.Dir(artifact.Path)); err != nil {
		return errors.New("artifact ancestor is not trusted")
	}
	info, err := os.Lstat(artifact.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("artifact is not a non-writable regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("artifact is not owned by root")
	}
	return nil
}

type parsedJailerExecution struct {
	vmID         string
	execPath     string
	uid          uint32
	gid          uint32
	cgroupParent string
	apiSocket    string
}

func validJailerExecutionStage(authority JailerExecutionAuthority, stage JailedResourceStage) bool {
	parsed, ok := parseJailerExecutionArguments(authority.Arguments())
	if !ok || authority.version != jailerExecutionAuthorityVersion || !validStackResourceReference(authority.stackResource) || !validRelativeCgroupPath(authority.cgroupParent) || parsed.cgroupParent != authority.cgroupParent || authority.cgroupPath != authority.cgroupParent+"/"+parsed.vmID {
		return false
	}
	missing, invalid := validateExternalJailerLimitOwners(authority.external)
	if missing != "" || invalid != "" || !sameExternalJailerLimitOwners(authority.external, canonicalExternalJailerLimitOwners(authority.external)) {
		return false
	}
	if stage.BindingDigest != stage.bindingDigest() || !validArtifact(stage.Jailer) || !validArtifact(stage.Firecracker.Source) || parsed.execPath != stage.Firecracker.Source.Path || parsed.uid != stage.OwnerUID || parsed.gid != stage.OwnerGID || parsed.apiSocket != stage.APISocketPath {
		return false
	}
	base := jailerArgumentValue(authority.Arguments(), "--chroot-base-dir")
	if !approvedJailerBaseDirectory(base) || stage.JailRoot != filepath.Join(base, filepath.Base(parsed.execPath), parsed.vmID, "root") || stage.Firecracker.JailedPath != "/"+filepath.Base(parsed.execPath) {
		return false
	}
	return safeAbsolutePath(stage.JailRoot) && safeAbsolutePath(stage.APISocketPath) && safeAbsolutePath(stage.VSockUDSPath) && jailDestinationContained(stage.JailRoot, stage.Firecracker.JailedPath) && jailDestinationContained(stage.JailRoot, stage.Kernel.JailedPath) && jailDestinationContained(stage.JailRoot, stage.RootFS.JailedPath)
}

func parseJailerExecutionArguments(arguments []string) (parsedJailerExecution, bool) {
	if len(arguments) != 25 || arguments[0] != "--id" || arguments[2] != "--exec-file" || arguments[4] != "--uid" || arguments[6] != "--gid" || arguments[8] != "--chroot-base-dir" || !approvedJailerBaseDirectory(arguments[9]) || arguments[10] != "--cgroup-version" || arguments[11] != "2" || arguments[12] != "--parent-cgroup" || !validRelativeCgroupPath(arguments[13]) || arguments[14] != "--cgroup" || arguments[16] != "--cgroup" || arguments[18] != "--cgroup" || arguments[20] != "--resource-limit" || arguments[22] != "--" || arguments[23] != "--api-sock" {
		return parsedJailerExecution{}, false
	}
	uid, uidErr := strconv.ParseUint(arguments[5], 10, 32)
	gid, gidErr := strconv.ParseUint(arguments[7], 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || !validVMID(arguments[1]) || !safeAbsolutePath(arguments[3]) || !safeAbsolutePath(arguments[24]) || !validCPUGroup(arguments[15]) || !validUnsignedCgroup(arguments[17], "memory.max=") || !validUnsignedCgroup(arguments[19], "pids.max=") || !validUnsignedCgroup(arguments[21], "no-file=") {
		return parsedJailerExecution{}, false
	}
	return parsedJailerExecution{vmID: arguments[1], execPath: arguments[3], uid: uint32(uid), gid: uint32(gid), cgroupParent: arguments[13], apiSocket: arguments[24]}, true
}

func validCPUGroup(value string) bool {
	if !strings.HasPrefix(value, "cpu.max=") {
		return false
	}
	parts := strings.Fields(strings.TrimPrefix(value, "cpu.max="))
	if len(parts) != 2 {
		return false
	}
	quota, quotaErr := strconv.ParseUint(parts[0], 10, 64)
	period, periodErr := strconv.ParseUint(parts[1], 10, 64)
	return quotaErr == nil && periodErr == nil && quota > 0 && period > 0
}

func validUnsignedCgroup(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	limit, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 64)
	return err == nil && limit > 0
}

type linuxJailerProcess struct {
	command         jailerCommand
	serial          *boundedJailerOutput
	cgroupPath      string
	namespacePath   string
	removeNamespace func(string) error
	removeCgroup    func(string) error

	mu         sync.Mutex
	terminated bool
	// terminationDelivered records that this process sent the expected
	// terminal signal itself. A Jailer reports that normal shutdown as a
	// non-zero Wait result ("signal: terminated"); that result proves the
	// reaper ran, not that resource cleanup failed.
	terminationDelivered bool
	cleanupDone          bool
	cleanupProof         CleanupProof
	cleanupErr           error
	waitDone             chan struct{}
	waitErr              error
}

func newLinuxJailerProcess(command jailerCommand, serial *boundedJailerOutput, cgroupPath, namespacePath string, removeNamespace, removeCgroup func(string) error) *linuxJailerProcess {
	process := &linuxJailerProcess{command: command, serial: serial, cgroupPath: filepath.Join(jailerCgroupRoot, cgroupPath), namespacePath: namespacePath, removeNamespace: removeNamespace, removeCgroup: removeCgroup, waitDone: make(chan struct{})}
	go func() {
		waitErr := command.Wait()
		serial.Close()
		process.mu.Lock()
		process.waitErr = waitErr
		close(process.waitDone)
		process.mu.Unlock()
	}()
	return process
}

// AwaitSerial observes the exact marker emitted on this process's bounded non-daemonized stdout stream.
func (process *linuxJailerProcess) AwaitSerial(ctx context.Context, marker string) error {
	if process == nil || process.serial == nil {
		return fmt.Errorf("%w: Jailer serial output is required", ErrSmokeUnavailable)
	}
	return process.serial.AwaitSerial(ctx, marker)
}

// StartupDiagnostic returns a fixed classification derived from the bounded
// Jailer stderr stream only after the process has exited. It deliberately does
// not return stderr, an exit string, or a filesystem value: callers may retain
// this category in operator evidence without leaking host details.
func (process *linuxJailerProcess) StartupDiagnostic() JailerStartupDiagnostic {
	if process == nil || process.serial == nil {
		return JailerStartupDiagnosticUnavailable
	}
	select {
	case <-process.waitDone:
	default:
		return JailerStartupDiagnosticStillRunning
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	command, ok := process.command.(*osJailerCommand)
	if !ok || command.diagnostics == nil {
		return JailerStartupDiagnosticExited
	}
	return classifyJailerStartupDiagnostics(command.diagnostics.snapshot())
}

// Terminate sends SIGTERM to the one authority-bound Jailer process and waits only until ctx expires.
func (process *linuxJailerProcess) Terminate(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	process.mu.Lock()
	if process.terminated {
		process.mu.Unlock()
		return nil
	}
	process.terminated = true
	process.mu.Unlock()
	if err := process.command.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("terminate Jailer process: %w", err)
	} else if err == nil {
		process.mu.Lock()
		process.terminationDelivered = true
		process.mu.Unlock()
	}
	select {
	case <-process.waitDone:
		return nil
	case <-ctx.Done():
		killErr := process.command.Signal(syscall.SIGKILL)
		return errors.Join(ctx.Err(), fmt.Errorf("force-kill unreaped Jailer process: %w", killErr))
	}
}

// Wait waits for the authority-bound process reaper without changing the process lifetime.
func (process *linuxJailerProcess) Wait(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	select {
	case <-process.waitDone:
		process.mu.Lock()
		defer process.mu.Unlock()
		if process.terminationDelivered && expectedJailerTermination(process.waitErr) {
			return nil
		}
		return process.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// expectedJailerTermination recognizes only the OS exit status produced when
// this process delivered SIGTERM to its own Jailer. It deliberately does not
// accept arbitrary non-zero exits: those remain lifecycle failures, while the
// intentional signal is the expected completion of a bounded smoke run.
func expectedJailerTermination(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ProcessState == nil {
		return false
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGTERM
}

// Cleanup removes only the reaped authority-bound cgroup and per-VM Jailer namespace.
func (process *linuxJailerProcess) Cleanup(ctx context.Context) (CleanupProof, error) {
	if err := contextError(ctx); err != nil {
		return CleanupProof{Reason: "cleanup context is unavailable"}, err
	}
	select {
	case <-process.waitDone:
	case <-ctx.Done():
		return CleanupProof{Reason: "Jailer process has not reaped"}, ctx.Err()
	default:
		return CleanupProof{Reason: "Jailer process has not reaped"}, fmt.Errorf("%w: wait for Jailer process before cleanup", ErrSmokeUnavailable)
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.cleanupDone {
		return process.cleanupProof, process.cleanupErr
	}
	proof := CleanupProof{}
	var cleanupErr error
	if err := process.removeCgroup(process.cgroupPath); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove authority-bound Jailer cgroup: %w", err))
	} else {
		proof.Removed = append(proof.Removed, process.cgroupPath)
	}
	if err := process.removeNamespace(process.namespacePath); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove authority-bound Jailer namespace: %w", err))
	} else {
		proof.Removed = append(proof.Removed, process.namespacePath)
	}
	proof.Proved = cleanupErr == nil
	if cleanupErr != nil {
		proof.Reason = "Jailer cleanup did not complete"
	}
	process.cleanupDone, process.cleanupProof, process.cleanupErr = true, proof, cleanupErr
	return proof, cleanupErr
}

type osJailerCommand struct {
	command     *exec.Cmd
	serial      *boundedJailerOutput
	diagnostics *boundedJailerOutput
}

func newOSJailerCommand(path string, arguments []string, directory string) jailerCommand {
	serial := newBoundedJailerOutput(maximumJailerOutputSize)
	diagnostics := newBoundedJailerOutput(maximumJailerOutputSize)
	command := exec.Command(path, arguments...)
	command.Dir = directory
	command.Stdout = serial
	command.Stderr = diagnostics
	return &osJailerCommand{command: command, serial: serial, diagnostics: diagnostics}
}

func (command *osJailerCommand) Start() error { return command.command.Start() }
func (command *osJailerCommand) Wait() error {
	err := command.command.Wait()
	command.serial.Close()
	command.diagnostics.Close()
	return err
}
func (command *osJailerCommand) Signal(signal os.Signal) error {
	return command.command.Process.Signal(signal)
}

func (command *osJailerCommand) SerialOutput() *boundedJailerOutput { return command.serial }

func classifyJailerStartupDiagnostics(output []byte) JailerStartupDiagnostic {
	message := strings.ToLower(string(output))
	switch {
	case strings.Contains(message, "permission denied"):
		return JailerStartupDiagnosticPermissionDenied
	case strings.Contains(message, "kvm_create_vm"), strings.Contains(message, "failed to initialize kvm"), strings.Contains(message, "failed to create kvm"):
		return JailerStartupDiagnosticKVMInitialization
	case strings.Contains(message, "api socket"), strings.Contains(message, "api_sock"), strings.Contains(message, "api-sock"):
		return JailerStartupDiagnosticAPIInitialization
	default:
		return JailerStartupDiagnosticExited
	}
}

type boundedJailerOutput struct {
	mu        sync.Mutex
	remaining int
	data      []byte
	notify    chan struct{}
	closed    bool
}

func newBoundedJailerOutput(limit int) *boundedJailerOutput {
	return &boundedJailerOutput{remaining: limit, notify: make(chan struct{})}
}

func (output *boundedJailerOutput) Write(value []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.remaining > 0 {
		count := len(value)
		if count > output.remaining {
			count = output.remaining
		}
		output.data = append(output.data, value[:count]...)
		output.remaining -= count
	}
	output.signalLocked()
	return len(value), nil
}

// AwaitSerial waits for one exact, CRLF-tolerant guest serial marker line within the bounded process output.
func (output *boundedJailerOutput) AwaitSerial(ctx context.Context, marker string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if output == nil || !validGuestSerialMarker(marker) {
		return fmt.Errorf("%w: exact guest serial marker is required", ErrSmokeUnavailable)
	}
	for {
		output.mu.Lock()
		if containsGuestSerialMarker(output.data, marker) {
			output.mu.Unlock()
			return nil
		}
		if output.remaining == 0 {
			output.mu.Unlock()
			return fmt.Errorf("%w: bounded Jailer serial output exhausted before marker", ErrSmokeUnavailable)
		}
		if output.closed {
			output.mu.Unlock()
			return fmt.Errorf("%w: Jailer serial output closed before marker", ErrSmokeUnavailable)
		}
		notify := output.notify
		output.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-notify:
		}
	}
}

// Close marks the Jailer/Firecracker output stream terminal and wakes pending serial observers.
func (output *boundedJailerOutput) Close() {
	if output == nil {
		return
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.closed {
		return
	}
	output.closed = true
	output.signalLocked()
}

func (output *boundedJailerOutput) snapshot() []byte {
	if output == nil {
		return nil
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.data...)
}

func (output *boundedJailerOutput) signalLocked() {
	close(output.notify)
	output.notify = make(chan struct{})
}

func containsGuestSerialMarker(data []byte, marker string) bool {
	for len(data) > 0 {
		lineEnd := bytes.IndexByte(data, '\n')
		if lineEnd < 0 {
			return false
		}
		line := data[:lineEnd]
		if bytes.Equal(bytes.TrimSuffix(line, []byte{'\r'}), []byte(marker)) {
			return true
		}
		data = data[lineEnd+1:]
	}
	return false
}

func validGuestSerialMarker(marker string) bool {
	fields := strings.Fields(marker)
	return len(fields) == 4 && fields[0] == "AGENT_RUNTIME_FC_SMOKE" && validVMID(fields[1]) && validFixtureVersion(fields[2]) && fields[3] == "agent-runtime-firecracker-guest/v1" && strings.Join(fields, " ") == marker
}

var _ io.Writer = (*boundedJailerOutput)(nil)
