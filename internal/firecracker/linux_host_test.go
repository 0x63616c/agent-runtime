package firecracker

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestLinuxJailerHostOrdersTheNoNICRESTLaunchAndGuestControlPorts(t *testing.T) {
	plan := mustCompile(t, validProfile())
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{}
	guest := &recordingGuestChannel{}
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: defaultJailedResourceStage},
		Jailer:         processes,
		HTTP:           http,
		Guest:          guest,
	}
	fixtures := verifiedPlanFixtures(plan)

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
	if got, want := processes.starts, []processStart{{Request: JailerStartRequest{Path: plan.Jailer().Path, Arguments: plan.JailerArguments(), Resources: plan.Resources(), Stage: defaultJailedResourceStage}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Jailer starts = %#v, want %#v", got, want)
	}
	if got, want := http.calls, []firecrackerRESTCall{
		{Path: "/machine-config", Body: firecrackerMachineConfig{VCPUCount: 1, MemoryMiB: 256}},
		{Path: "/boot-source", Body: firecrackerBootSource{KernelImagePath: defaultJailedResourceStage.KernelImagePath, BootArgs: "console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1"}},
		{Path: "/drives/rootfs", Body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: defaultJailedResourceStage.RootDrivePath, RootDevice: true, ReadOnly: false}},
		{Path: "/vsock", Body: firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: defaultJailedResourceStage.VSockUDSPath}},
		{Path: "/actions", Body: firecrackerAction{ActionType: "InstanceStart"}},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("REST calls = %#v, want %#v", got, want)
	}
	if got, want := http.binds, []string{defaultJailedResourceStage.APISocketPath}; !reflect.DeepEqual(got, want) {
		t.Fatalf("HTTP binds = %v, want %v", got, want)
	}
	if got, want := guest.steps, []string{"bind:" + defaultJailedResourceStage.VSockUDSPath, "marker:" + request.SerialMarker, "ping:" + request.Boot.VMID, "close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("guest steps = %v, want %v", got, want)
	}
	if got, want := processes.process.steps, []string{"terminate", "wait", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process steps = %v, want %v", got, want)
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
			host := LinuxJailerHost{PreflightState: test.preflight, RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4", Resources: &recordingResourceStager{stage: defaultJailedResourceStage}, Jailer: processes, HTTP: http, Guest: guest}

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
	processes := &recordingJailerStarter{}
	http := &recordingFirecrackerHTTP{failPath: "/boot-source"}
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: defaultJailedResourceStage},
		Jailer:         processes,
		HTTP:           http,
		Guest:          &recordingGuestChannel{},
	}
	fixtures := verifiedPlanFixtures(plan)
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

func TestLinuxJailerHostRetainsAProcessForCleanupWhenStartReturnsBothProcessAndError(t *testing.T) {
	plan := mustCompile(t, validProfile())
	processes := &recordingJailerStarter{startErr: errors.New("Jailer reported startup failure")}
	host := LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Resources:      &recordingResourceStager{stage: defaultJailedResourceStage},
		Jailer:         processes,
		HTTP:           &recordingFirecrackerHTTP{},
		Guest:          &recordingGuestChannel{},
	}
	fixtures := verifiedPlanFixtures(plan)
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
	host := newLinuxJailerHost(processes, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})
	fixtures := verifiedPlanFixtures(plan)
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
	host := newLinuxJailerHost(processes, http, &recordingGuestChannel{})
	fixtures := verifiedPlanFixtures(plan)
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
	host := newLinuxJailerHost(processes, http, &recordingGuestChannel{})
	fixtures := verifiedPlanFixtures(plan)
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
	host := newLinuxJailerHost(processes, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})
	fixtures := verifiedPlanFixtures(plan)
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
	stage := &recordingResourceStager{stage: JailedResourceStage{
		KernelImagePath: "/kernel/vmlinux",
		RootDrivePath:   "/drives/rootfs.ext4",
		APISocketPath:   "/run/firecracker.socket",
		VSockUDSPath:    "/run/guest-control.vsock",
	}}
	host := newLinuxJailerHost(processes, http, guest)
	host.Resources = stage
	fixtures := verifiedPlanFixtures(plan)
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
	wantStart := JailerStartRequest{Path: plan.Jailer().Path, Arguments: plan.JailerArguments(), Resources: plan.Resources(), Stage: stage.stage}
	if got := processes.starts[0].Request; !reflect.DeepEqual(got, wantStart) {
		t.Fatalf("Jailer start request = %#v, want %#v", got, wantStart)
	}
	wantBoot := firecrackerBootSource{KernelImagePath: stage.stage.KernelImagePath, BootArgs: "console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1"}
	if got := http.calls[1].Body; !reflect.DeepEqual(got, wantBoot) {
		t.Fatalf("boot source = %#v, want %#v", got, wantBoot)
	}
	wantDrive := firecrackerRootDrive{DriveID: "rootfs", PathOnHost: stage.stage.RootDrivePath, RootDevice: true, ReadOnly: false}
	if got := http.calls[2].Body; !reflect.DeepEqual(got, wantDrive) {
		t.Fatalf("root drive = %#v, want %#v", got, wantDrive)
	}
	wantVSock := firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: stage.stage.VSockUDSPath}
	if got := http.calls[3].Body; !reflect.DeepEqual(got, wantVSock) {
		t.Fatalf("vsock = %#v, want %#v", got, wantVSock)
	}
	if got, want := guest.steps[0], "bind:"+stage.stage.VSockUDSPath; got != want {
		t.Fatalf("guest bind = %q, want %q", got, want)
	}
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
	request.Arguments = append([]string(nil), request.Arguments...)
	starter.starts = append(starter.starts, processStart{Request: request})
	if starter.onStart != nil {
		starter.onStart()
	}
	return &starter.process, starter.startErr
}

type recordingJailerProcess struct{ steps []string }

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

type firecrackerRESTCall struct {
	Path string
	Body any
}

type recordingFirecrackerHTTP struct {
	calls    []firecrackerRESTCall
	binds    []string
	failPath string
	onPut    func(string)
}

func (port *recordingFirecrackerHTTP) Bind(_ context.Context, path string) error {
	port.binds = append(port.binds, path)
	return nil
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
	stage JailedResourceStage
}

func (stager *recordingResourceStager) Stage(context.Context, Plan, FixtureSet, string) (JailedResourceStage, error) {
	return stager.stage, nil
}

func newLinuxJailerHost(processes JailerStarter, http FirecrackerHTTPPort, guest GuestChannel) *LinuxJailerHost {
	return &LinuxJailerHost{
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Jailer:         processes,
		HTTP:           http,
		Guest:          guest,
		Resources:      &recordingResourceStager{stage: defaultJailedResourceStage},
	}
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
