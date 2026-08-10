package firecracker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	defaultGuestCID     = 3
	defaultVSockUDSPath = "/run/firecracker.vsock"
)

// JailerStarter starts the Jailer only after the host has validated every launch prerequisite.
type JailerStarter interface {
	Start(context.Context, string, []string) (JailerProcess, error)
}

// JailerProcess owns the running Jailer and its exact per-VM cleanup.
type JailerProcess interface {
	Terminate(context.Context) error
	Wait(context.Context) error
	Cleanup(context.Context) (CleanupProof, error)
}

// FirecrackerHTTPPort sends one bounded JSON request over the private Firecracker API socket.
type FirecrackerHTTPPort interface {
	Put(context.Context, string, any) error
}

// GuestChannel carries the private guest serial observation and vsock control protocol.
type GuestChannel interface {
	AwaitSerial(context.Context, string) error
	Ping(context.Context, string) error
	Close(context.Context) error
}

// LinuxJailerHost is the Linux/KVM-only SmokeHost adapter composed from real host ports.
type LinuxJailerHost struct {
	PreflightState KVMPreflight
	RootFSCopyPath string
	Jailer         JailerStarter
	HTTP           FirecrackerHTTPPort
	Guest          GuestChannel

	mu        sync.Mutex
	preflight bool
	prepared  bool
	launched  bool
	process   JailerProcess
	plan      Plan
	request   LaunchRequest
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

// Preflight rejects all missing Linux/KVM, fixture, plan, and port prerequisites before launch.
func (host *LinuxJailerHost) Preflight(_ context.Context, plan Plan, fixtures FixtureSet) error {
	if host == nil || host.Jailer == nil || host.HTTP == nil || host.Guest == nil || !safeAbsolutePath(host.RootFSCopyPath) || !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) {
		return fmt.Errorf("%w: Linux Jailer ports, private rootfs copy, compiled plan, and verified fixtures are required", ErrSmokeUnavailable)
	}
	if err := host.PreflightState.Validate(); err != nil {
		return err
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.preflight || host.prepared || host.launched || host.process != nil {
		return fmt.Errorf("%w: Linux Jailer host is single-use", ErrSmokeUnavailable)
	}
	host.preflight = true
	return nil
}

// Prepare binds the verified fixture version and plan VM ID into the rootfs init arguments.
func (host *LinuxJailerHost) Prepare(_ context.Context, plan Plan, fixtures FixtureSet) (LaunchRequest, error) {
	if host == nil || !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) {
		return LaunchRequest{}, fmt.Errorf("%w: compiled plan and verified fixtures are required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.preflight || host.prepared || host.launched || host.process != nil {
		return LaunchRequest{}, fmt.Errorf("%w: successful single-use preflight is required", ErrSmokeUnavailable)
	}
	request, err := NewLaunchRequest(plan, host.RootFSCopyPath, BootInput{VMID: plan.VMID(), FixtureVersion: fixtures.FixtureVersion()})
	if err != nil {
		return LaunchRequest{}, err
	}
	host.request = request
	host.plan = plan
	host.prepared = true
	return request, nil
}

// Launch starts the Jailer and configures only the no-NIC Firecracker REST sequence.
func (host *LinuxJailerHost) Launch(ctx context.Context, request LaunchRequest) error {
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.preflight || !host.prepared || host.launched || host.process != nil || !sameLaunchRequest(request, host.request) || !validLinuxLaunchRequest(request) {
		return fmt.Errorf("%w: preflight-bound immutable launch request is required", ErrSmokeUnavailable)
	}
	process, err := host.Jailer.Start(ctx, request.JailerPath, append([]string(nil), request.JailerArguments...))
	if process != nil {
		host.process = process
	}
	if err != nil || process == nil {
		return fmt.Errorf("start Jailer: %w", errors.Join(err, missingJailerProcess(process)))
	}
	for _, call := range []struct {
		path string
		body any
	}{
		{path: "/machine-config", body: firecrackerMachineConfig{VCPUCount: host.plan.Machine().VCPUCount, MemoryMiB: host.plan.Machine().MemoryMiB, SMT: false}},
		{path: "/boot-source", body: firecrackerBootSource{KernelImagePath: host.plan.Kernel().Path, BootArgs: strings.Join(request.KernelArguments, " ")}},
		{path: "/drives/rootfs", body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: request.RootFSCopyPath, RootDevice: true, ReadOnly: false}},
		{path: "/vsock", body: firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: defaultVSockUDSPath}},
		{path: "/actions", body: firecrackerAction{ActionType: "InstanceStart"}},
	} {
		if err := host.HTTP.Put(ctx, call.path, call.body); err != nil {
			return fmt.Errorf("configure Firecracker %s: %w", call.path, err)
		}
	}
	host.launched = true
	return nil
}

// AwaitSerial observes the exact immutable guest marker through the injected guest channel.
func (host *LinuxJailerHost) AwaitSerial(ctx context.Context, marker string) error {
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.launched || marker != host.request.SerialMarker {
		return fmt.Errorf("%w: launched immutable serial marker is required", ErrSmokeUnavailable)
	}
	if err := host.Guest.AwaitSerial(ctx, marker); err != nil {
		return fmt.Errorf("await guest serial marker: %w", err)
	}
	return nil
}

// Control sends the guest protocol's bounded PING through the injected private vsock channel.
func (host *LinuxJailerHost) Control(ctx context.Context) error {
	if host == nil {
		return fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.launched {
		return fmt.Errorf("%w: launched guest channel is required", ErrSmokeUnavailable)
	}
	if err := host.Guest.Ping(ctx, host.request.Boot.VMID); err != nil {
		return fmt.Errorf("control guest vsock: %w", err)
	}
	return nil
}

// Cleanup closes guest control and delegates Jailer termination, wait, and exact resource proof to the process port.
func (host *LinuxJailerHost) Cleanup(ctx context.Context) (CleanupProof, error) {
	if host == nil {
		return CleanupProof{Reason: "Linux Jailer host is absent"}, fmt.Errorf("%w: Linux Jailer host is required", ErrSmokeUnavailable)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.process == nil {
		return CleanupProof{Proved: true}, nil
	}
	var cleanupErr error
	if err := host.Guest.Close(ctx); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close guest channel: %w", err))
	}
	if err := host.process.Terminate(ctx); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("terminate Jailer: %w", err))
	}
	if err := host.process.Wait(ctx); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("wait for Jailer: %w", err))
	}
	proof, processErr := host.process.Cleanup(ctx)
	cleanupErr = errors.Join(cleanupErr, processErr)
	if cleanupErr != nil {
		proof.Proved = false
		if proof.Reason == "" {
			proof.Reason = "Jailer cleanup did not complete"
		}
	}
	return proof, cleanupErr
}

func validLinuxLaunchRequest(request LaunchRequest) bool {
	return safeAbsolutePath(request.JailerPath) && len(request.JailerArguments) > 0 && safeAbsolutePath(request.RootFSCopyPath) && request.CgroupVersion == 2 && request.NetworkInterfaces == 0 && validBootInput(request.Boot) && request.SerialMarker == request.Boot.serialMarker() && sameStrings(request.KernelArguments, request.Boot.KernelArguments())
}

func sameLaunchRequest(left, right LaunchRequest) bool {
	return left.JailerPath == right.JailerPath && sameStrings(left.JailerArguments, right.JailerArguments) && left.RootFSCopyPath == right.RootFSCopyPath && left.CgroupVersion == right.CgroupVersion && left.NetworkInterfaces == right.NetworkInterfaces && left.SerialMarker == right.SerialMarker && left.Boot == right.Boot && sameStrings(left.KernelArguments, right.KernelArguments)
}

func missingJailerProcess(process JailerProcess) error {
	if process == nil {
		return errors.New("Jailer process is absent")
	}
	return nil
}
