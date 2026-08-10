package firecracker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const defaultGuestCID = 3

var defaultJailedResourceStage = JailedResourceStage{
	KernelImagePath: "/kernel/vmlinux",
	RootDrivePath:   "/drives/rootfs.ext4",
	APISocketPath:   "/run/firecracker.socket",
	VSockUDSPath:    "/run/firecracker.vsock",
}

// JailerStartRequest is the complete Jailer invocation with its mandatory resource enforcement and jailed paths.
type JailerStartRequest struct {
	Path      string
	Arguments []string
	Resources ResourceEnforcement
	Stage     JailedResourceStage
}

// JailedResourceStage maps verified host fixtures to the paths visible inside one Jailer chroot.
type JailedResourceStage struct {
	KernelImagePath string
	RootDrivePath   string
	APISocketPath   string
	VSockUDSPath    string
}

// JailerResourceStager creates one per-VM jailed resource mapping before the Jailer process starts.
type JailerResourceStager interface {
	Stage(context.Context, Plan, FixtureSet, string) (JailedResourceStage, error)
}

// JailerStarter starts the Jailer only after the host has validated every launch prerequisite.
type JailerStarter interface {
	Start(context.Context, JailerStartRequest) (JailerProcess, error)
}

// JailerProcess owns the running Jailer and its exact per-VM cleanup.
type JailerProcess interface {
	Terminate(context.Context) error
	Wait(context.Context) error
	Cleanup(context.Context) (CleanupProof, error)
}

// FirecrackerHTTPPort sends one bounded JSON request over the exact private Firecracker API socket.
type FirecrackerHTTPPort interface {
	Bind(context.Context, string) error
	Put(context.Context, string, any) error
}

// GuestChannel carries the exact private guest serial observation and vsock control protocol.
type GuestChannel interface {
	Bind(context.Context, string) error
	AwaitSerial(context.Context, string) error
	Ping(context.Context, string) error
	Close(context.Context) error
}

// LinuxJailerHost is the Linux/KVM-only SmokeHost adapter composed from real host ports.
type LinuxJailerHost struct {
	PreflightState KVMPreflight
	RootFSCopyPath string
	Resources      JailerResourceStager
	Jailer         JailerStarter
	HTTP           FirecrackerHTTPPort
	Guest          GuestChannel

	mu           sync.Mutex
	preflight    bool
	prepared     bool
	launching    bool
	launched     bool
	cleaning     bool
	cleaned      bool
	process      JailerProcess
	plan         Plan
	request      LaunchRequest
	stage        JailedResourceStage
	launchDone   chan struct{}
	cleanupDone  chan struct{}
	cleanupProof CleanupProof
	cleanupErr   error
}

type firecrackerMachineConfig struct {
	VCPUCount uint32 `json:"vcpu_count"`
	MemoryMiB uint32 `json:"mem_size_mib"`
	SMT       bool   `json:"smt"`
}

type firecrackerBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type firecrackerRootDrive struct {
	DriveID    string `json:"drive_id"`
	PathOnHost string `json:"path_on_host"`
	RootDevice bool   `json:"is_root_device"`
	ReadOnly   bool   `json:"is_read_only"`
}

type firecrackerVSock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

type firecrackerAction struct {
	ActionType string `json:"action_type"`
}

// Preflight rejects all missing Linux/KVM, fixture, plan, resource-stage, and port prerequisites before launch.
func (host *LinuxJailerHost) Preflight(ctx context.Context, plan Plan, fixtures FixtureSet) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if host == nil || host.Resources == nil || host.Jailer == nil || host.HTTP == nil || host.Guest == nil || !safeAbsolutePath(host.RootFSCopyPath) || !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) {
		return fmt.Errorf("%w: Linux Jailer ports, resource stage, private rootfs copy, compiled plan, and verified fixtures are required", ErrSmokeUnavailable)
	}
	if err := host.PreflightState.Validate(); err != nil {
		return err
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.preflight || host.prepared || host.launching || host.launched || host.process != nil || host.cleaned {
		return fmt.Errorf("%w: Linux Jailer host is single-use", ErrSmokeUnavailable)
	}
	host.preflight = true
	return nil
}

// Prepare stages one verified jailed mapping and binds the verified fixture version and VM ID into init arguments.
func (host *LinuxJailerHost) Prepare(ctx context.Context, plan Plan, fixtures FixtureSet) (LaunchRequest, error) {
	if err := contextError(ctx); err != nil {
		return LaunchRequest{}, err
	}
	if host == nil || !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) {
		return LaunchRequest{}, fmt.Errorf("%w: compiled plan and verified fixtures are required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	if !host.preflight || host.prepared || host.launching || host.launched || host.process != nil || host.cleaned {
		host.mu.Unlock()
		return LaunchRequest{}, fmt.Errorf("%w: successful single-use preflight is required", ErrSmokeUnavailable)
	}
	stager := host.Resources
	rootFSCopyPath := host.RootFSCopyPath
	host.mu.Unlock()
	stage, err := stager.Stage(ctx, plan, fixtures, rootFSCopyPath)
	if err != nil {
		return LaunchRequest{}, fmt.Errorf("stage jailed resources: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return LaunchRequest{}, err
	}
	if !validJailedResourceStage(stage, plan) {
		return LaunchRequest{}, fmt.Errorf("%w: exact jailed kernel, root drive, API socket, and vsock paths are required", ErrSmokeUnavailable)
	}
	request, err := NewLaunchRequest(plan, rootFSCopyPath, BootInput{VMID: plan.VMID(), FixtureVersion: fixtures.FixtureVersion()})
	if err != nil {
		return LaunchRequest{}, err
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.preflight || host.prepared || host.launching || host.launched || host.process != nil || host.cleaned {
		return LaunchRequest{}, fmt.Errorf("%w: Linux Jailer host changed during preparation", ErrSmokeUnavailable)
	}
	host.request = cloneLaunchRequest(request)
	host.plan = plan
	host.stage = stage
	host.prepared = true
	return cloneLaunchRequest(request), nil
}

// Launch starts the Jailer and configures only the no-NIC Firecracker REST sequence.
func (host *LinuxJailerHost) Launch(ctx context.Context, request LaunchRequest) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	if !host.preflight || !host.prepared || host.launching || host.launched || host.process != nil || host.cleaned || !sameLaunchRequest(request, host.request) || !validLinuxLaunchRequest(request) || request.JailerPath != host.plan.Jailer().Path || !sameStrings(request.JailerArguments, host.plan.JailerArguments()) {
		host.mu.Unlock()
		return fmt.Errorf("%w: preflight-bound immutable launch request is required", ErrSmokeUnavailable)
	}
	host.launching = true
	host.launchDone = make(chan struct{})
	startRequest := JailerStartRequest{Path: request.JailerPath, Arguments: append([]string(nil), request.JailerArguments...), Resources: host.plan.Resources(), Stage: host.stage}
	jailer, http, guest, stage, plan := host.Jailer, host.HTTP, host.Guest, host.stage, host.plan
	host.mu.Unlock()

	if err := contextError(ctx); err != nil {
		return host.failLaunch(err)
	}
	process, startErr := jailer.Start(ctx, startRequest)
	if process != nil {
		host.mu.Lock()
		host.process = process
		host.mu.Unlock()
	}
	if err := contextError(ctx); err != nil {
		return host.failLaunch(err)
	}
	if startErr != nil || process == nil {
		return host.failLaunch(fmt.Errorf("start Jailer: %w", errors.Join(startErr, missingJailerProcess(process))))
	}
	if err := callWithContextFence(ctx, "bind Firecracker API socket", func(callCtx context.Context) error { return http.Bind(callCtx, stage.APISocketPath) }); err != nil {
		return host.failLaunch(err)
	}
	if err := callWithContextFence(ctx, "bind guest vsock", func(callCtx context.Context) error { return guest.Bind(callCtx, stage.VSockUDSPath) }); err != nil {
		return host.failLaunch(err)
	}
	for _, call := range []struct {
		path string
		body any
	}{
		{path: "/machine-config", body: firecrackerMachineConfig{VCPUCount: plan.Machine().VCPUCount, MemoryMiB: plan.Machine().MemoryMiB, SMT: false}},
		{path: "/boot-source", body: firecrackerBootSource{KernelImagePath: stage.KernelImagePath, BootArgs: strings.Join(request.KernelArguments, " ")}},
		{path: "/drives/rootfs", body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: stage.RootDrivePath, RootDevice: true, ReadOnly: false}},
		{path: "/vsock", body: firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: stage.VSockUDSPath}},
		{path: "/actions", body: firecrackerAction{ActionType: "InstanceStart"}},
	} {
		if err := callWithContextFence(ctx, "configure Firecracker "+call.path, func(callCtx context.Context) error { return http.Put(callCtx, call.path, call.body) }); err != nil {
			return host.failLaunch(err)
		}
	}
	host.finishLaunch(true)
	return nil
}

// AwaitSerial observes the exact immutable guest marker through the injected guest channel.
func (host *LinuxJailerHost) AwaitSerial(ctx context.Context, marker string) error {
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, cleaned, request, guest := host.launched, host.cleaning, host.cleaned, cloneLaunchRequest(host.request), host.Guest
	host.mu.Unlock()
	if !launched || cleaning || cleaned || marker != request.SerialMarker {
		return fmt.Errorf("%w: launched immutable serial marker is required", ErrSmokeUnavailable)
	}
	if err := callWithContextFence(ctx, "await guest serial marker", func(callCtx context.Context) error { return guest.AwaitSerial(callCtx, marker) }); err != nil {
		return host.abortAfterStart(err)
	}
	return nil
}

// Control sends the guest protocol's bounded PING through the injected private vsock channel.
func (host *LinuxJailerHost) Control(ctx context.Context) error {
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	launched, cleaning, cleaned, request, guest := host.launched, host.cleaning, host.cleaned, cloneLaunchRequest(host.request), host.Guest
	host.mu.Unlock()
	if !launched || cleaning || cleaned {
		return fmt.Errorf("%w: launched guest channel is required", ErrSmokeUnavailable)
	}
	if err := callWithContextFence(ctx, "control guest vsock", func(callCtx context.Context) error { return guest.Ping(callCtx, request.Boot.VMID) }); err != nil {
		return host.abortAfterStart(err)
	}
	return nil
}

// Cleanup closes guest control and delegates Jailer termination, wait, and exact resource proof to the process port.
func (host *LinuxJailerHost) Cleanup(ctx context.Context) (CleanupProof, error) {
	if host == nil {
		return CleanupProof{Reason: "Linux Jailer host is absent"}, fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	if err := contextError(ctx); err != nil {
		return CleanupProof{Reason: "cleanup context is cancelled"}, err
	}
	for {
		host.mu.Lock()
		if host.cleaned {
			proof, err := host.cleanupProof, host.cleanupErr
			host.mu.Unlock()
			return proof, err
		}
		if host.cleaning {
			done := host.cleanupDone
			host.mu.Unlock()
			select {
			case <-ctx.Done():
				return CleanupProof{Reason: "cleanup waited for concurrent cleanup"}, ctx.Err()
			case <-done:
				continue
			}
		}
		if host.launching {
			done := host.launchDone
			host.mu.Unlock()
			select {
			case <-ctx.Done():
				return CleanupProof{Reason: "cleanup waited for launch cancellation"}, ctx.Err()
			case <-done:
				continue
			}
		}
		process, guest := host.process, host.Guest
		host.process = nil
		host.cleaning = true
		host.cleanupDone = make(chan struct{})
		host.mu.Unlock()
		if process == nil {
			proof := CleanupProof{Proved: true}
			host.storeCleanup(proof, nil)
			return proof, nil
		}
		var cleanupErr error
		if err := callWithContextFence(ctx, "close guest channel", guest.Close); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		if err := callWithContextFence(ctx, "terminate Jailer", process.Terminate); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		if err := callWithContextFence(ctx, "wait for Jailer", process.Wait); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		proof := CleanupProof{}
		if err := contextError(ctx); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clean Jailer resources before I/O: %w", err))
		} else {
			var processErr error
			proof, processErr = process.Cleanup(ctx)
			cleanupErr = errors.Join(cleanupErr, processErr)
			if err := contextError(ctx); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clean Jailer resources after I/O: %w", err))
			}
		}
		if cleanupErr != nil {
			proof.Proved = false
			if proof.Reason == "" {
				proof.Reason = "Jailer cleanup did not complete"
			}
		}
		host.storeCleanup(proof, cleanupErr)
		return proof, cleanupErr
	}
}

func (host *LinuxJailerHost) failLaunch(err error) error {
	host.finishLaunch(false)
	return host.abortAfterStart(err)
}

func (host *LinuxJailerHost) abortAfterStart(err error) error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), maximumCleanupTimeout)
	defer cancel()
	_, cleanupErr := host.Cleanup(cleanupContext)
	return errors.Join(err, cleanupErr)
}

func (host *LinuxJailerHost) finishLaunch(launched bool) {
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.launching {
		return
	}
	host.launching = false
	host.launched = launched
	close(host.launchDone)
}

func (host *LinuxJailerHost) storeCleanup(proof CleanupProof, err error) {
	host.mu.Lock()
	host.cleanupProof = proof
	host.cleanupErr = err
	host.cleaning = false
	host.cleaned = true
	close(host.cleanupDone)
	host.mu.Unlock()
}

func validJailedResourceStage(stage JailedResourceStage, plan Plan) bool {
	return safeAbsolutePath(stage.KernelImagePath) && safeAbsolutePath(stage.RootDrivePath) && safeAbsolutePath(stage.APISocketPath) && safeAbsolutePath(stage.VSockUDSPath) && stage.KernelImagePath != stage.RootDrivePath && stage.APISocketPath == jailedAPISocketPath(plan.JailerArguments()) && stage.VSockUDSPath != stage.APISocketPath
}

func jailedAPISocketPath(arguments []string) string {
	for index := range arguments {
		if arguments[index] == "--api-sock" && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func validLinuxLaunchRequest(request LaunchRequest) bool {
	return safeAbsolutePath(request.JailerPath) && len(request.JailerArguments) > 0 && safeAbsolutePath(request.RootFSCopyPath) && request.CgroupVersion == 2 && request.NetworkInterfaces == 0 && validBootInput(request.Boot) && request.SerialMarker == request.Boot.serialMarker() && sameStrings(request.KernelArguments, request.Boot.KernelArguments())
}

func sameLaunchRequest(left, right LaunchRequest) bool {
	return left.JailerPath == right.JailerPath && sameStrings(left.JailerArguments, right.JailerArguments) && left.RootFSCopyPath == right.RootFSCopyPath && left.CgroupVersion == right.CgroupVersion && left.NetworkInterfaces == right.NetworkInterfaces && left.SerialMarker == right.SerialMarker && left.Boot == right.Boot && sameStrings(left.KernelArguments, right.KernelArguments)
}

func cloneLaunchRequest(request LaunchRequest) LaunchRequest {
	request.JailerArguments = append([]string(nil), request.JailerArguments...)
	request.KernelArguments = append([]string(nil), request.KernelArguments...)
	return request
}

func callWithContextFence(ctx context.Context, action string, call func(context.Context) error) error {
	if err := contextError(ctx); err != nil {
		return fmt.Errorf("%s before I/O: %w", action, err)
	}
	if err := call(ctx); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if err := contextError(ctx); err != nil {
		return fmt.Errorf("%s after I/O: %w", action, err)
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrSmokeUnavailable)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func missingJailerProcess(process JailerProcess) error {
	if process == nil {
		return errors.New("Jailer process is absent")
	}
	return nil
}
