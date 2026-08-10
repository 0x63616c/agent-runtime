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
	if got, want := processes.starts, []processStart{{Path: plan.Jailer().Path, Arguments: plan.JailerArguments()}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Jailer starts = %#v, want %#v", got, want)
	}
	if got, want := http.calls, []firecrackerRESTCall{
		{Path: "/machine-config", Body: firecrackerMachineConfig{VCPUCount: 1, MemoryMiB: 256}},
		{Path: "/boot-source", Body: firecrackerBootSource{KernelImagePath: plan.Kernel().Path, BootArgs: "console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1"}},
		{Path: "/drives/rootfs", Body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: request.RootFSCopyPath, RootDevice: true, ReadOnly: false}},
		{Path: "/vsock", Body: firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: defaultVSockUDSPath}},
		{Path: "/actions", Body: firecrackerAction{ActionType: "InstanceStart"}},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("REST calls = %#v, want %#v", got, want)
	}
	if got, want := guest.steps, []string{"marker:" + request.SerialMarker, "ping:" + request.Boot.VMID, "close"}; !reflect.DeepEqual(got, want) {
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
			host := LinuxJailerHost{PreflightState: test.preflight, RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4", Jailer: processes, HTTP: http, Guest: guest}

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

type processStart struct {
	Path      string
	Arguments []string
}

type recordingJailerStarter struct {
	starts   []processStart
	process  recordingJailerProcess
	startErr error
}

func (starter *recordingJailerStarter) Start(_ context.Context, path string, arguments []string) (JailerProcess, error) {
	starter.starts = append(starter.starts, processStart{Path: path, Arguments: append([]string(nil), arguments...)})
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
	failPath string
}

func (port *recordingFirecrackerHTTP) Put(_ context.Context, path string, body any) error {
	port.calls = append(port.calls, firecrackerRESTCall{Path: path, Body: body})
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

func (channel *recordingGuestChannel) AwaitSerial(_ context.Context, marker string) error {
	channel.steps = append(channel.steps, "marker:"+marker)
	return nil
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
