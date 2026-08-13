package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestLinuxJailerStarterStartsOnlyTheAuthorityBoundJailerAndStage(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)
	command := &recordingOSJailerCommand{closeOnTerminate: true}
	var verified []PinnedArtifact
	starter := LinuxJailerStarter{
		goos:               "linux",
		kernelCapabilities: func() error { return nil },
		cgroupPrerequisite: func(JailerExecutionAuthority) error { return nil },
		trustArtifact:      func(PinnedArtifact) error { return nil },
		verifyArtifact: func(_ context.Context, artifact PinnedArtifact) error {
			verified = append(verified, artifact)
			return nil
		},
		trustStageRoot: func(string) error { return nil },
		command: func(path string, arguments []string, directory string) jailerCommand {
			if path != stage.Jailer.Path || !reflect.DeepEqual(arguments, authority.Arguments()) || directory != stage.JailRoot {
				t.Errorf("command = (%q, %#v, %q), want staged Jailer and authority argv", path, arguments, stage.JailRoot)
			}
			return command
		},
		removeNamespace: func(string) error { return nil },
		removeCgroup:    func(string) error { return nil },
	}

	process, err := starter.Start(context.Background(), JailerStartRequest{Authority: authority, Stage: stage})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !command.started {
		t.Fatal("Start() did not invoke the authority-bound command")
	}
	if got, want := verified, []PinnedArtifact{stage.Jailer, stage.Firecracker.Source}; !reflect.DeepEqual(got, want) {
		t.Fatalf("verified artifacts = %#v, want %#v", got, want)
	}
	close(command.waitDone)
	if err := process.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
}

func TestLinuxJailerStarterExposesTheBoundedNonDaemonizedSerialOutput(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	command := &serialRecordingOSJailerCommand{
		recordingOSJailerCommand: &recordingOSJailerCommand{closeOnTerminate: true},
		output:                   newBoundedJailerOutput(1024),
	}
	starter := LinuxJailerStarter{
		goos:               "linux",
		kernelCapabilities: func() error { return nil },
		cgroupPrerequisite: func(JailerExecutionAuthority) error { return nil },
		trustArtifact:      func(PinnedArtifact) error { return nil },
		verifyArtifact:     func(context.Context, PinnedArtifact) error { return nil },
		trustStageRoot:     func(string) error { return nil },
		command:            func(string, []string, string) jailerCommand { return command },
		removeNamespace:    func(string) error { return nil },
		removeCgroup:       func(string) error { return nil },
	}

	process, err := starter.Start(context.Background(), JailerStartRequest{Authority: mustCompileJailerExecutionAuthority(t, plan), Stage: stage})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	serial, ok := process.(JailerSerialObserver)
	if !ok {
		t.Fatalf("process = %T, want JailerSerialObserver sourced from Jailer stdout", process)
	}
	marker := BootInput{VMID: plan.VMID(), FixtureVersion: fixtures.FixtureVersion()}.serialMarker()
	if _, err := command.output.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write serial marker: %v", err)
	}
	if err := serial.AwaitSerial(context.Background(), marker); err != nil {
		t.Fatalf("AwaitSerial() error = %v", err)
	}
	if err := process.Terminate(context.Background()); err != nil {
		t.Fatalf("Terminate() error = %v", err)
	}
}

func TestClassifyJailerStartupDiagnosticsRetainsOnlyFixedFailureCategories(t *testing.T) {
	for _, test := range []struct {
		name   string
		output string
		want   JailerStartupDiagnostic
	}{
		{name: "permission", output: "cannot open /private/operator-secret: permission denied", want: JailerStartupDiagnosticPermissionDenied},
		{name: "kvm", output: "KVM_CREATE_VM failed for /private/operator-secret", want: JailerStartupDiagnosticKVMInitialization},
		{name: "api socket", output: "failed to create API socket /private/operator-secret", want: JailerStartupDiagnosticAPIInitialization},
		{name: "unknown", output: "arbitrary host failure /private/operator-secret", want: JailerStartupDiagnosticExited},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyJailerStartupDiagnostics([]byte(test.output)); got != test.want {
				t.Fatalf("classifyJailerStartupDiagnostics() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLinuxJailerStarterRefusesAnUnboundAuthorityOrStageBeforeHostIO(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)
	cases := map[string]func(*JailerStartRequest){
		"missing authority": func(request *JailerStartRequest) { request.Authority = JailerExecutionAuthority{} },
		"wrong jail root": func(request *JailerStartRequest) {
			request.Stage.JailRoot = "/srv/agent-runtime/jailer/firecracker/other/root"
		},
		"wrong Jailer UID": func(request *JailerStartRequest) { request.Stage.OwnerUID++ },
		"altered argv": func(request *JailerStartRequest) {
			request.Authority.arguments[0] = "--netns"
		},
		"other cgroup parent": func(request *JailerStartRequest) {
			request.Authority.arguments[13] = "other-parent"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			starts := 0
			request := JailerStartRequest{Authority: authority, Stage: stage}
			request.Authority.arguments = append([]string(nil), authority.arguments...)
			mutate(&request)
			starter := LinuxJailerStarter{
				goos:               "linux",
				kernelCapabilities: func() error { return nil },
				cgroupPrerequisite: func(JailerExecutionAuthority) error {
					t.Fatal("cgroupPrerequisite() called after invalid binding")
					return nil
				},
				trustArtifact: func(PinnedArtifact) error { t.Fatal("trustArtifact() called after invalid binding"); return nil },
				verifyArtifact: func(context.Context, PinnedArtifact) error {
					t.Fatal("verifyArtifact() called after invalid binding")
					return nil
				},
				trustStageRoot: func(string) error { t.Fatal("trustStageRoot() called after invalid binding"); return nil },
				command: func(string, []string, string) jailerCommand {
					starts++
					return &recordingOSJailerCommand{}
				},
			}
			if _, err := starter.Start(context.Background(), request); !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("Start() error = %v, want bound-authority refusal", err)
			}
			if starts != 0 {
				t.Fatalf("command starts = %d, want none", starts)
			}
		})
	}
}

func TestLinuxJailerProcessTerminatesReapsAndCleansOnlyAssignedResources(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	authority := mustCompileJailerExecutionAuthority(t, plan)
	command := &recordingOSJailerCommand{closeOnTerminate: true}
	var removed []string
	starter := LinuxJailerStarter{
		goos:               "linux",
		kernelCapabilities: func() error { return nil },
		cgroupPrerequisite: func(JailerExecutionAuthority) error { return nil },
		trustArtifact:      func(PinnedArtifact) error { return nil },
		verifyArtifact:     func(context.Context, PinnedArtifact) error { return nil },
		trustStageRoot:     func(string) error { return nil },
		command:            func(string, []string, string) jailerCommand { return command },
		removeNamespace:    func(path string) error { removed = append(removed, "namespace:"+path); return nil },
		removeCgroup:       func(path string) error { removed = append(removed, "cgroup:"+path); return nil },
	}

	process, err := starter.Start(context.Background(), JailerStartRequest{Authority: authority, Stage: stage})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	<-command.waitEntered
	if err := process.Terminate(context.Background()); err != nil {
		t.Fatalf("Terminate() error = %v", err)
	}
	if got, want := command.signals, []os.Signal{syscall.SIGTERM}; !reflect.DeepEqual(got, want) {
		t.Fatalf("signals = %#v, want %#v", got, want)
	}
	if err := process.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	proof, err := process.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if !proof.Proved {
		t.Fatalf("Cleanup() proof = %#v, want proved", proof)
	}
	if got, want := removed, []string{
		"cgroup:/sys/fs/cgroup/agent-runtime/firecracker/sandbox-001",
		"namespace:/srv/agent-runtime/jailer/firecracker/sandbox-001",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("removed = %#v, want %#v", got, want)
	}
}

func TestLinuxJailerStarterCancelsAfterStartAndReapsBeforeReturning(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	startContext, cancel := context.WithCancel(context.Background())
	command := &recordingOSJailerCommand{closeOnTerminate: true, onStart: cancel}
	var removed []string
	starter := LinuxJailerStarter{
		goos:               "linux",
		kernelCapabilities: func() error { return nil },
		cgroupPrerequisite: func(JailerExecutionAuthority) error { return nil },
		trustArtifact:      func(PinnedArtifact) error { return nil },
		verifyArtifact:     func(context.Context, PinnedArtifact) error { return nil },
		trustStageRoot:     func(string) error { return nil },
		command:            func(string, []string, string) jailerCommand { return command },
		removeNamespace:    func(path string) error { removed = append(removed, path); return nil },
		removeCgroup:       func(path string) error { removed = append(removed, path); return nil },
	}

	if process, err := starter.Start(startContext, JailerStartRequest{Authority: mustCompileJailerExecutionAuthority(t, plan), Stage: stage}); process != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() = (%#v, %v), want canceled start after bounded cleanup", process, err)
	}
	if got, want := command.signals, []os.Signal{syscall.SIGTERM}; !reflect.DeepEqual(got, want) {
		t.Fatalf("signals = %#v, want %#v", got, want)
	}
	if got, want := removed, []string{
		"/sys/fs/cgroup/agent-runtime/firecracker/sandbox-001",
		"/srv/agent-runtime/jailer/firecracker/sandbox-001",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("removed = %#v, want cgroup and namespace cleanup %#v", got, want)
	}
}

func TestLinuxJailerStarterRefusesUnavailableLinuxCapabilitiesBeforeStarting(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	starts := 0
	starter := LinuxJailerStarter{
		goos:               "darwin",
		kernelCapabilities: func() error { return errors.New("must not run") },
		command: func(string, []string, string) jailerCommand {
			starts++
			return &recordingOSJailerCommand{}
		},
	}

	if _, err := starter.Start(context.Background(), JailerStartRequest{Authority: mustCompileJailerExecutionAuthority(t, plan), Stage: stage}); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Start() error = %v, want Linux capability refusal", err)
	}
	if starts != 0 {
		t.Fatalf("command starts = %d, want none", starts)
	}
}

func TestLinuxJailerStarterRefusesAnUndelegatedCgroupBeforeArtifactOrProcessIO(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	starts := 0
	starter := LinuxJailerStarter{
		goos:               "linux",
		kernelCapabilities: func() error { return nil },
		cgroupPrerequisite: func(JailerExecutionAuthority) error { return errors.New("memory controller is not delegated") },
		trustArtifact:      func(PinnedArtifact) error { t.Fatal("trustArtifact() called after cgroup refusal"); return nil },
		verifyArtifact: func(context.Context, PinnedArtifact) error {
			t.Fatal("verifyArtifact() called after cgroup refusal")
			return nil
		},
		command: func(string, []string, string) jailerCommand {
			starts++
			return &recordingOSJailerCommand{}
		},
	}

	if _, err := starter.Start(context.Background(), JailerStartRequest{Authority: mustCompileJailerExecutionAuthority(t, plan), Stage: stage}); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Start() error = %v, want delegated-cgroup refusal", err)
	}
	if starts != 0 {
		t.Fatalf("command starts = %d, want none", starts)
	}
}

func TestTrustedJailerArtifactRefusesAnArtifactOutsideTheOperatorOwnedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jailer")
	if err := os.WriteFile(path, []byte("untrusted"), 0o755); err != nil {
		t.Fatalf("write test artifact: %v", err)
	}
	if err := trustedJailerArtifact(PinnedArtifact{Path: path, Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("trustedJailerArtifact() error = nil, want untrusted artifact refusal")
	}
}

type recordingOSJailerCommand struct {
	started          bool
	signals          []os.Signal
	startErr         error
	waitErr          error
	waitDone         chan struct{}
	waitEntered      chan struct{}
	closeOnTerminate bool
	waitClosed       bool
	onStart          func()
	output           *boundedJailerOutput
}

type serialRecordingOSJailerCommand struct {
	*recordingOSJailerCommand
	output *boundedJailerOutput
}

func (command *serialRecordingOSJailerCommand) SerialOutput() *boundedJailerOutput {
	return command.output
}

func (command *recordingOSJailerCommand) Start() error {
	command.started = true
	if command.waitDone == nil {
		command.waitDone = make(chan struct{})
	}
	if command.waitEntered == nil {
		command.waitEntered = make(chan struct{})
	}
	if command.onStart != nil {
		command.onStart()
	}
	return command.startErr
}

func (command *recordingOSJailerCommand) Wait() error {
	close(command.waitEntered)
	<-command.waitDone
	return command.waitErr
}

func (command *recordingOSJailerCommand) Signal(signal os.Signal) error {
	command.signals = append(command.signals, signal)
	if command.closeOnTerminate && signal == syscall.SIGTERM && !command.waitClosed {
		command.waitClosed = true
		close(command.waitDone)
	}
	return nil
}

func (command *recordingOSJailerCommand) SerialOutput() *boundedJailerOutput {
	if command.output == nil {
		command.output = newBoundedJailerOutput(maximumJailerOutputSize)
	}
	return command.output
}

func mustCompileJailerExecutionAuthority(t *testing.T, plan Plan) JailerExecutionAuthority {
	t.Helper()
	authority, err := CompileJailerExecutionAuthority(plan, validJailerCgroupAssignment(), completeExternalJailerLimitOwners())
	if err != nil {
		t.Fatalf("CompileJailerExecutionAuthority() error = %v", err)
	}
	return authority
}
