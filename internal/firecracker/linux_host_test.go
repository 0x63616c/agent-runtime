package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestExpectedJailRootIncludesTheJailerExecutableBaseName(t *testing.T) {
	plan := mustCompile(t, validProfile())

	if got, want := expectedJailRoot(plan), filepath.Join("/srv/agent-runtime/jailer", "firecracker", "sandbox-001", "root"); got != want {
		t.Fatalf("expectedJailRoot() = %q, want Jailer chroot layout %q", got, want)
	}
}

func TestLinuxJailerHostOrdersTheNoNICRESTLaunchAndGuestControlPorts(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{}
	guest := &recordingGuestChannel{}
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: stage},
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		Jailer:         processes,
		HTTP:           http,
		Guest:          guest,
	}

	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	processes.process.serial = newBoundedJailerOutput(1024)
	if _, err := processes.process.serial.Write([]byte(request.SerialMarker + "\n")); err != nil {
		t.Fatalf("write serial marker: %v", err)
	}
	if err := host.AwaitSerial(context.Background(), request.SerialMarker); err != nil {
		t.Fatalf("AwaitSerial() error = %v", err)
	}
	if err := host.Control(context.Background()); err != nil {
		t.Fatalf("Control() error = %v", err)
	}
	cleanup, err := host.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if !cleanup.Proved {
		t.Fatalf("Cleanup() = %#v, want proof", cleanup)
	}
	if got, want := processes.starts, []processStart{{Request: JailerStartRequest{Authority: mustCompileJailerExecutionAuthority(t, plan), Stage: stage}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Jailer starts = %#v, want %#v", got, want)
	}
	if got, want := http.calls, []firecrackerRESTCall{
		{Path: "/machine-config", Body: firecrackerMachineConfig{VCPUCount: 1, MemoryMiB: 256}},
		{Path: "/boot-source", Body: firecrackerBootSource{KernelImagePath: stage.Kernel.JailedPath, BootArgs: "console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1"}},
		{Path: "/drives/rootfs", Body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: stage.RootFS.JailedPath, RootDevice: true, ReadOnly: false}},
		{Path: "/vsock", Body: firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: stage.VSockUDSPath}},
		{Path: "/actions", Body: firecrackerAction{ActionType: "InstanceStart"}},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("REST calls = %#v, want %#v", got, want)
	}
	if got, want := http.binds, []string{hostJailedPath(stage.JailRoot, stage.APISocketPath)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("HTTP binds = %v, want %v", got, want)
	}
	if got, want := guest.steps, []string{"bind:" + hostJailedPath(stage.JailRoot, stage.VSockUDSPath), "ping:" + request.Boot.VMID, "close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("guest steps = %v, want %v", got, want)
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want %v", got, want)
	}
}

func TestLinuxJailerHostRefusesAuthenticatedDispatchUntilACertifiedProfileExists(t *testing.T) {
	plan := mustCompile(t, validProfile())
	host := newLinuxJailerHost(plan, verifiedPlanFixtures(plan), &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})
	envelope := sandboxhostprotocol.Envelope{HostID: "host_01", AssignmentID: "assignment_01", FencingToken: 1, CapabilityDigest: string(plan.Capabilities().Digest)}
	if err := host.ExecuteDispatch(context.Background(), envelope); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ExecuteDispatch() = %v, want unavailable before any guest authority profile", err)
	}
}

func TestLinuxJailerHostCarriesItsPreflightBoundAuthorityIntoTheConcreteStarter(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)
	command := &recordingOSJailerCommand{closeOnTerminate: true}
	starter := LinuxJailerStarter{
		goos:               "linux",
		kernelCapabilities: func() error { return nil },
		cgroupPrerequisite: func(got JailerExecutionAuthority) error {
			if !reflect.DeepEqual(got, authority) {
				t.Errorf("cgroup authority = %#v, want preflight authority", got)
			}
			return nil
		},
		trustArtifact:   func(PinnedArtifact) error { return nil },
		verifyArtifact:  func(context.Context, PinnedArtifact) error { return nil },
		trustStageRoot:  func(string) error { return nil },
		command:         func(string, []string, string) jailerCommand { return command },
		removeNamespace: func(string) error { return nil },
		removeCgroup:    func(string) error { return nil },
	}
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: stage},
		Authority:      authority,
		Jailer:         starter,
		HTTP:           &recordingFirecrackerHTTP{},
		Guest:          &recordingGuestChannel{},
	}

	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	if _, err := host.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if got, want := command.signals, []os.Signal{syscall.SIGTERM}; !reflect.DeepEqual(got, want) {
		t.Fatalf("signals = %#v, want %#v", got, want)
	}
}

func TestLinuxJailerHostObservesStarterSerialWhileGuestControlRemainsDeferred(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	processes := &recordingJailerStarter{}
	processes.process.serial = newBoundedJailerOutput(1024)
	host := newLinuxJailerHost(plan, fixtures, processes, &recordingFirecrackerHTTP{}, nil)
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	if _, err := processes.process.serial.Write([]byte(request.SerialMarker + "\n")); err != nil {
		t.Fatalf("write serial marker: %v", err)
	}
	if err := host.AwaitSerial(context.Background(), request.SerialMarker); err != nil {
		t.Fatalf("AwaitSerial() error = %v", err)
	}
	if err := host.Control(context.Background()); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Control() error = %v, want deferred guest-control refusal", err)
	}
	if _, err := host.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
}

func TestLinuxJailerHostCleansAfterSerialObservationCancellation(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	processes := &recordingJailerStarter{}
	processes.process.serial = newBoundedJailerOutput(1024)
	host := newLinuxJailerHost(plan, fixtures, processes, &recordingFirecrackerHTTP{}, nil)
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := host.AwaitSerial(ctx, request.SerialMarker); !errors.Is(err, context.Canceled) {
		t.Fatalf("AwaitSerial() error = %v, want preserved cancellation", err)
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process cleanup steps = %v, want %v", got, want)
	}
}

func TestLinuxJailerHostRefusesBeforeAnyPortWhenPreflightOrFixturesAreIncomplete(t *testing.T) {
	plan := mustCompile(t, validProfile())
	for _, test := range []struct {
		name      string
		preflight KVMPreflight
		fixtures  FixtureSet
	}{
		{name: "KVM", preflight: KVMPreflight{GOOS: "darwin"}, fixtures: verifiedPlanFixtures(plan)},
		{name: "fixtures", preflight: validKVMPreflight(), fixtures: FixtureSet{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			processes := &recordingJailerStarter{}
			http := &recordingFirecrackerHTTP{}
			guest := &recordingGuestChannel{}
			host := LinuxJailerHost{PreflightState: test.preflight, RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4", Resources: &recordingResourceStager{}, Authority: mustCompileJailerExecutionAuthority(t, plan), Jailer: processes, HTTP: http, Guest: guest}

			if err := host.Preflight(context.Background(), plan, test.fixtures); !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("Preflight() error = %v, want fail-closed refusal", err)
			}
			if len(processes.starts) != 0 || len(http.calls) != 0 || len(guest.steps) != 0 {
				t.Fatalf("ports were used before prerequisite validation: starts=%v calls=%v guest=%v", processes.starts, http.calls, guest.steps)
			}
		})
	}
}

func TestLinuxJailerHostStopsRESTConfigurationBeforeInstanceStartOnFailure(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{failPath: "/boot-source"}
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")},
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		Jailer:         processes,
		HTTP:           http,
		Guest:          &recordingGuestChannel{},
	}
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if err := host.Launch(context.Background(), request); err == nil {
		t.Fatal("Launch() error = nil, want REST configuration failure")
	}
	if got, want := http.paths(), []string{"/machine-config", "/boot-source"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("REST paths = %v, want %v", got, want)
	}
	if _, err := host.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want %v after failed configuration", got, want)
	}
}

func TestLinuxJailerHostWaitsForThePrivateAPISocketBeforeRESTConfiguration(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{readyErr: errors.New("socket not ready")}
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")},
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		Jailer:         processes,
		HTTP:           http,
		Guest:          &recordingGuestChannel{},
	}
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err == nil {
		t.Fatal("Launch() error = nil, want API readiness failure")
	}
	if http.ready != 1 || len(http.calls) != 0 {
		t.Fatalf("readiness/calls = %d/%d, want one readiness probe and no REST requests", http.ready, len(http.calls))
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want %v after readiness failure", got, want)
	}
}

func TestLinuxJailerHostRetainsAProcessForCleanupWhenStartReturnsBothProcessAndError(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	processes := &recordingJailerStarter{startErr: errors.New("Jailer reported startup failure")}
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")},
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		Jailer:         processes,
		HTTP:           &recordingFirecrackerHTTP{},
		Guest:          &recordingGuestChannel{},
	}
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err == nil {
		t.Fatal("Launch() error = nil, want Jailer startup failure")
	}
	if _, err := host.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want %v after partial Jailer start", got, want)
	}
}

func TestLinuxJailerHostRefusesAMutatedPreparedRequestBeforeStartingJailer(t *testing.T) {
	plan := mustCompile(t, validProfile())
	processes := &recordingJailerStarter{}
	fixtures := verifiedPlanFixtures(plan)
	host := newLinuxJailerHost(plan, fixtures, processes, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	request.JailerArguments[0] = "--exec-file"

	if err := host.Launch(context.Background(), request); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Launch() error = %v, want mutated-request refusal", err)
	}
	if len(processes.starts) != 0 {
		t.Fatalf("Jailer starts = %#v, want none after caller mutation", processes.starts)
	}
}

func TestLinuxJailerHostCancelsAfterStartAndCleansBeforeReturning(t *testing.T) {
	plan := mustCompile(t, validProfile())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processes := &recordingJailerStarter{onStart: cancel}
	http := &recordingFirecrackerHTTP{}
	fixtures := verifiedPlanFixtures(plan)
	host := newLinuxJailerHost(plan, fixtures, processes, http, &recordingGuestChannel{})
	if err := host.Preflight(ctx, plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(ctx, plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if err := host.Launch(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Launch() error = %v, want context cancellation", err)
	}
	if len(http.calls) != 0 {
		t.Fatalf("REST calls = %#v, want none after post-start cancellation", http.calls)
	}
	if host.launched {
		t.Fatal("host reported launched after cancellation")
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want %v after cancellation", got, want)
	}
}

func TestLinuxJailerHostFencesCancellationAfterEachRESTCallAndCleans(t *testing.T) {
	plan := mustCompile(t, validProfile())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{onPut: func(path string) {
		if path == "/machine-config" {
			cancel()
		}
	}}
	fixtures := verifiedPlanFixtures(plan)
	host := newLinuxJailerHost(plan, fixtures, processes, http, &recordingGuestChannel{})
	if err := host.Preflight(ctx, plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(ctx, plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if err := host.Launch(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Launch() error = %v, want REST-boundary cancellation", err)
	}
	if got, want := http.paths(), []string{"/machine-config"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("REST paths = %v, want %v", got, want)
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want %v after REST cancellation", got, want)
	}
}

func TestLinuxJailerHostCleanupIsIdempotentAfterItClearsTheProcess(t *testing.T) {
	plan := mustCompile(t, validProfile())
	processes := &recordingJailerStarter{}
	fixtures := verifiedPlanFixtures(plan)
	host := newLinuxJailerHost(plan, fixtures, processes, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	first, firstErr := host.Cleanup(context.Background())
	second, secondErr := host.Cleanup(context.Background())
	if firstErr != nil || secondErr != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("Cleanup() results = (%#v, %v), (%#v, %v), want one stable cleanup proof", first, firstErr, second, secondErr)
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want one cleanup sequence", got)
	}
}

func TestLinuxJailerHostBindsPlanResourcesAndJailedPathsToEveryPort(t *testing.T) {
	plan := mustCompile(t, validProfile())
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{}
	guest := &recordingGuestChannel{}
	fixtures := verifiedPlanFixtures(plan)
	bound := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	bound.VSockUDSPath = "/run/guest-control.vsock"
	bound.BindingDigest = bound.bindingDigest()
	stage := &recordingResourceStager{stage: bound}
	host := newLinuxJailerHost(plan, fixtures, processes, http, guest)
	host.Resources = stage
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	request, err := host.Prepare(context.Background(), plan, fixtures)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := host.Launch(context.Background(), request); err != nil {
		t.Fatalf("Launch() error = %v", err)
	}
	wantStart := JailerStartRequest{Authority: mustCompileJailerExecutionAuthority(t, plan), Stage: stage.stage}
	if got := processes.starts[0].Request; !reflect.DeepEqual(got, wantStart) {
		t.Fatalf("Jailer start request = %#v, want %#v", got, wantStart)
	}
	wantBoot := firecrackerBootSource{KernelImagePath: stage.stage.Kernel.JailedPath, BootArgs: "console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1"}
	if got := http.calls[1].Body; !reflect.DeepEqual(got, wantBoot) {
		t.Fatalf("boot source = %#v, want %#v", got, wantBoot)
	}
	wantDrive := firecrackerRootDrive{DriveID: "rootfs", PathOnHost: stage.stage.RootFS.JailedPath, RootDevice: true, ReadOnly: false}
	if got := http.calls[2].Body; !reflect.DeepEqual(got, wantDrive) {
		t.Fatalf("root drive = %#v, want %#v", got, wantDrive)
	}
	wantVSock := firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: stage.stage.VSockUDSPath}
	if got := http.calls[3].Body; !reflect.DeepEqual(got, wantVSock) {
		t.Fatalf("vsock = %#v, want %#v", got, wantVSock)
	}
	if got, want := guest.steps[0], "bind:"+hostJailedPath(stage.stage.JailRoot, stage.stage.VSockUDSPath); got != want {
		t.Fatalf("guest bind = %q, want %q", got, want)
	}
}

func TestLinuxJailerHostRefusesAnUnboundJailedResourceStageBeforeStartingPorts(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	for name, mutate := range map[string]func(*JailedResourceStage){
		"altered binding digest": func(stage *JailedResourceStage) {
			stage.BindingDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"substituted kernel": func(stage *JailedResourceStage) {
			stage.Kernel.Source = plan.Firecracker()
			stage.BindingDigest = stage.bindingDigest()
		},
		"duplicate destination": func(stage *JailedResourceStage) {
			stage.RootFS.JailedPath = stage.Kernel.JailedPath
			stage.BindingDigest = stage.bindingDigest()
		},
	} {
		t.Run(name, func(t *testing.T) {
			processes := &recordingJailerStarter{}
			http := &recordingFirecrackerHTTP{}
			guest := &recordingGuestChannel{}
			host := newLinuxJailerHost(plan, fixtures, processes, http, guest)
			stage := validBoundJailedResourceStage(plan, fixtures, host.RootFSCopyPath)
			mutate(&stage)
			stager := &recordingResourceStager{stage: stage}
			host.Resources = stager

			if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
				t.Fatalf("Preflight() error = %v", err)
			}
			if _, err := host.Prepare(context.Background(), plan, fixtures); !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("Prepare() error = %v, want bound-stage refusal", err)
			}
			if len(processes.starts) != 0 || len(http.calls) != 0 || len(guest.steps) != 0 {
				t.Fatalf("ports were used after an unbound resource stage: starts=%v calls=%v guest=%v", processes.starts, http.calls, guest.steps)
			}
			if got := stager.discarded; !reflect.DeepEqual(got, []JailedResourceStage{stage}) {
				t.Fatalf("discarded stages = %#v, want exact invalid stage %#v", got, stage)
			}
			proof, err := host.Cleanup(context.Background())
			if err != nil || !proof.Proved || !sameStrings(proof.Removed, []string{filepath.Dir(stage.JailRoot)}) {
				t.Fatalf("Cleanup() = (%#v, %v), want exact staged namespace cleanup proof", proof, err)
			}
		})
	}
}

func TestLinuxJailerHostDoesNotProveCleanupWhenInvalidStagedNamespaceDiscardFailsOrIsAmbiguous(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	for name, mutate := range map[string]func(*recordingResourceStager){
		"discard fails": func(stager *recordingResourceStager) {
			stager.discardErr = errors.New("remove jailed namespace")
		},
		"discard proof is ambiguous": func(stager *recordingResourceStager) {
			stager.discardProof = CleanupProof{Proved: true, Removed: []string{"/other/vm"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			processes := &recordingJailerStarter{}
			http := &recordingFirecrackerHTTP{}
			guest := &recordingGuestChannel{}
			host := newLinuxJailerHost(plan, fixtures, processes, http, guest)
			stage := validBoundJailedResourceStage(plan, fixtures, host.RootFSCopyPath)
			stage.BindingDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			stager := &recordingResourceStager{stage: stage}
			mutate(stager)
			host.Resources = stager

			if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
				t.Fatalf("Preflight() error = %v", err)
			}
			if _, err := host.Prepare(context.Background(), plan, fixtures); !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("Prepare() error = %v, want invalid-stage refusal with failed cleanup", err)
			}
			if got := stager.discarded; !reflect.DeepEqual(got, []JailedResourceStage{stage}) {
				t.Fatalf("discarded stages = %#v, want exact invalid stage %#v", got, stage)
			}
			proof, err := host.Cleanup(context.Background())
			if err == nil || proof.Proved {
				t.Fatalf("Cleanup() = (%#v, %v), want unproved failed staged cleanup", proof, err)
			}
			if len(processes.starts) != 0 || len(http.calls) != 0 || len(guest.steps) != 0 {
				t.Fatalf("ports were used after an invalid staged cleanup: starts=%v calls=%v guest=%v", processes.starts, http.calls, guest.steps)
			}
		})
	}
}

func TestLinuxJailerHostDoesNotAcceptAnInvalidStageDiscardProofForAnotherVM(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{}
	guest := &recordingGuestChannel{}
	host := newLinuxJailerHost(plan, fixtures, processes, http, guest)
	stage := validBoundJailedResourceStage(plan, fixtures, host.RootFSCopyPath)
	stage.JailRoot = "/srv/agent-runtime/jailer/other-vm/root"
	stage.BindingDigest = stage.bindingDigest()
	stager := &recordingResourceStager{stage: stage}
	host.Resources = stager

	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	if _, err := host.Prepare(context.Background(), plan, fixtures); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Prepare() error = %v, want other-VM stage refusal", err)
	}
	if got := stager.discarded; !reflect.DeepEqual(got, []JailedResourceStage{stage}) {
		t.Fatalf("discarded stages = %#v, want exact invalid stage %#v", got, stage)
	}
	proof, err := host.Cleanup(context.Background())
	if err == nil || proof.Proved {
		t.Fatalf("Cleanup() = (%#v, %v), want unproved other-VM discard", proof, err)
	}
}

func validBoundJailedResourceStage(plan Plan, fixtures FixtureSet, rootFSCopyPath string) JailedResourceStage {
	stage := JailedResourceStage{
		FixtureVersion: fixtures.FixtureVersion(),
		JailRoot:       expectedJailRoot(plan),
		OwnerUID:       plan.UID(),
		OwnerGID:       plan.GID(),
		Jailer:         plan.Jailer(),
		Firecracker:    JailedFixtureBinding{Source: plan.Firecracker(), JailedPath: "/firecracker"},
		Kernel:         JailedFixtureBinding{Source: plan.Kernel(), JailedPath: "/kernel/vmlinux"},
		RootFS:         JailedFixtureBinding{Source: PinnedArtifact{Path: rootFSCopyPath, Digest: plan.RootFS().Digest}, JailedPath: "/drives/rootfs.ext4"},
		GuestAgent:     plan.GuestAgent(),
		GuestInitPath:  "/sbin/init",
		APISocketPath:  "/run/firecracker.socket",
		VSockUDSPath:   "/run/firecracker.vsock",
	}
	stage.BindingDigest = stage.bindingDigest()
	return stage
}

type processStart struct {
	Request JailerStartRequest
}

type recordingJailerStarter struct {
	starts   []processStart
	process  recordingJailerProcess
	startErr error
	onStart  func()
}

func (starter *recordingJailerStarter) Start(_ context.Context, request JailerStartRequest) (JailerProcess, error) {
	request.Authority = cloneJailerExecutionAuthority(request.Authority)
	starter.starts = append(starter.starts, processStart{Request: request})
	if starter.onStart != nil {
		starter.onStart()
	}
	return &starter.process, starter.startErr
}

type recordingJailerProcess struct {
	steps  []string
	serial *boundedJailerOutput
}

func (process *recordingJailerProcess) Terminate(context.Context) error {
	process.steps = append(process.steps, "terminate")
	return nil
}
func (process *recordingJailerProcess) Wait(context.Context) error {
	process.steps = append(process.steps, "wait")
	return nil
}
func (process *recordingJailerProcess) Cleanup(context.Context) (CleanupProof, error) {
	process.steps = append(process.steps, "cleanup")
	return CleanupProof{Proved: true, Removed: []string{"jailer-cgroup", "jailer-chroot"}}, nil
}
func (process *recordingJailerProcess) AwaitSerial(ctx context.Context, marker string) error {
	if process.serial == nil {
		return ErrSmokeUnavailable
	}
	return process.serial.AwaitSerial(ctx, marker)
}

type firecrackerRESTCall struct {
	Path string
	Body any
}

type recordingFirecrackerHTTP struct {
	calls    []firecrackerRESTCall
	binds    []string
	ready    int
	readyErr error
	failPath string
	onPut    func(string)
}

func (port *recordingFirecrackerHTTP) Bind(_ context.Context, path string) error {
	port.binds = append(port.binds, path)
	return nil
}

func (port *recordingFirecrackerHTTP) WaitReady(context.Context) error {
	port.ready++
	return port.readyErr
}

func (port *recordingFirecrackerHTTP) Put(_ context.Context, path string, body any) error {
	port.calls = append(port.calls, firecrackerRESTCall{Path: path, Body: body})
	if port.onPut != nil {
		port.onPut(path)
	}
	if path == port.failPath {
		return errors.New("injected REST failure")
	}
	return nil
}

func (port *recordingFirecrackerHTTP) paths() []string {
	paths := make([]string, 0, len(port.calls))
	for _, call := range port.calls {
		paths = append(paths, call.Path)
	}
	return paths
}

type recordingGuestChannel struct{ steps []string }

func (channel *recordingGuestChannel) Bind(_ context.Context, path string) error {
	channel.steps = append(channel.steps, "bind:"+path)
	return nil
}
func (channel *recordingGuestChannel) AwaitSerial(_ context.Context, marker string) error {
	channel.steps = append(channel.steps, "marker:"+marker)
	return nil
}

type recordingResourceStager struct {
	stage        JailedResourceStage
	discarded    []JailedResourceStage
	discardProof CleanupProof
	discardErr   error
}

func (stager *recordingResourceStager) Stage(context.Context, Plan, FixtureSet, string) (JailedResourceStage, error) {
	return stager.stage, nil
}

func (stager *recordingResourceStager) Discard(_ context.Context, _ Plan, stage JailedResourceStage) (CleanupProof, error) {
	stager.discarded = append(stager.discarded, stage)
	if stager.discardErr != nil {
		return CleanupProof{Reason: "discard failed"}, stager.discardErr
	}
	if stager.discardProof.Proved || stager.discardProof.Reason != "" || len(stager.discardProof.Removed) != 0 {
		return stager.discardProof, nil
	}
	return CleanupProof{Proved: true, Removed: []string{filepath.Dir(stage.JailRoot)}}, nil
}

func newLinuxJailerHost(plan Plan, fixtures FixtureSet, processes JailerStarter, http FirecrackerHTTPPort, guest GuestControlChannel) *LinuxJailerHost {
	return &LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Authority:      testJailerExecutionAuthority(plan),
		Jailer:         processes,
		HTTP:           http,
		Guest:          guest,
		Resources:      &recordingResourceStager{stage: validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")},
	}
}

func testJailerExecutionAuthority(plan Plan) JailerExecutionAuthority {
	authority, err := CompileJailerExecutionAuthority(plan, validJailerCgroupAssignment(), completeExternalJailerLimitOwners())
	if err != nil {
		panic(err)
	}
	return authority
}

func (channel *recordingGuestChannel) Ping(_ context.Context, vmID string) error {
	channel.steps = append(channel.steps, "ping:"+vmID)
	return nil
}
func (channel *recordingGuestChannel) Close(context.Context) error {
	channel.steps = append(channel.steps, "close")
	return nil
}

func validKVMPreflight() KVMPreflight {
	return KVMPreflight{GOOS: "linux", GOARCH: "amd64", KVMCharacterDevice: true, KVMReadWrite: true, CgroupV2: true}
}
