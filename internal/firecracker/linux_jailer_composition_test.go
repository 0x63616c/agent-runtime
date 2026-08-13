package firecracker

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFirecrackerVSockDialerSelectsOnlyTheFixedGuestControlPort(t *testing.T) {
	base := guestChannelDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "unix" || address != "/run/firecracker.vsock" {
			t.Fatalf("DialContext(%q, %q)", network, address)
		}
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			reader := bufio.NewReader(server)
			if got := guestChannelTestReadLine(t, reader); got != "CONNECT 10777" {
				t.Errorf("Firecracker CONNECT = %q", got)
				return
			}
			_, _ = server.Write([]byte("OK 1073741824\n"))
			if got := guestChannelTestReadLine(t, reader); got != "guest-frame" {
				t.Errorf("guest frame = %q", got)
			}
		}()
		return client, nil
	})
	connection, err := (firecrackerVSockDialer{dialer: base}).DialContext(context.Background(), "unix", "/run/firecracker.vsock")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := connection.Write([]byte("guest-frame\n")); err != nil {
		t.Fatalf("write guest frame: %v", err)
	}
}

func TestNewLinuxJailerHostComposesReviewedJailerAndPrivateUnixPorts(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority := mustCompileJailerExecutionAuthority(t, plan)
	dialer := &recordingUnixDialer{}
	host, err := NewLinuxJailerHost(LinuxJailerHostConfig{
		Plan:           plan,
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Authority:      authority,
		UnixDialer:     dialer,
	})
	if err != nil {
		t.Fatalf("NewLinuxJailerHost() error = %v", err)
	}
	if _, ok := host.Resources.(LinuxJailerResourceStager); !ok {
		t.Fatalf("Resources = %T, want reviewed LinuxJailerResourceStager", host.Resources)
	}
	if _, ok := host.Jailer.(LinuxJailerStarter); !ok {
		t.Fatalf("Jailer = %T, want reviewed LinuxJailerStarter", host.Jailer)
	}
	http, ok := host.HTTP.(*unixFirecrackerHTTP)
	if !ok || http.socketPath != filepath.Join(expectedJailRoot(plan), "run", "firecracker.socket") || http.dialer != dialer {
		t.Fatalf("HTTP = %#v, want fixed private Unix REST port", host.HTTP)
	}
	guest, ok := host.Guest.(*UnixGuestControlChannel)
	guestDialer, wrapped := guest.dial.(firecrackerVSockDialer)
	if !ok || !wrapped || guestDialer.dialer != dialer {
		t.Fatalf("Guest = %#v, want fixed private Unix guest-control port", host.Guest)
	}
	authority.arguments[0] = "--mutated"
	if got, want := host.Authority.Arguments()[0], "--id"; got != want {
		t.Fatalf("Authority retained caller mutation = %q, want %q", got, want)
	}
	if err := host.Preflight(context.Background(), plan, verifiedPlanFixtures(plan)); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
}

func TestNewLinuxJailerHostRefusesIncompleteOrWidenedCompositionBeforeHostIO(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority := mustCompileJailerExecutionAuthority(t, plan)
	valid := LinuxJailerHostConfig{
		Plan:           plan,
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Authority:      authority,
		UnixDialer:     &recordingUnixDialer{},
	}
	for name, mutate := range map[string]func(*LinuxJailerHostConfig){
		"missing unix dialer": func(config *LinuxJailerHostConfig) { config.UnixDialer = nil },
		"unsafe rootfs path":  func(config *LinuxJailerHostConfig) { config.RootFSCopyPath = "relative-rootfs" },
		"incomplete preflight": func(config *LinuxJailerHostConfig) {
			config.PreflightState.CgroupV2 = false
		},
		"widened authority": func(config *LinuxJailerHostConfig) {
			config.Authority.arguments = append([]string{"--netns", "/run/other"}, config.Authority.arguments...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.Authority = cloneJailerExecutionAuthority(valid.Authority)
			mutate(&config)
			if host, err := NewLinuxJailerHost(config); host != nil || !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("NewLinuxJailerHost() = (%#v, %v), want pre-I/O refusal", host, err)
			}
		})
	}
}

func TestNewLinuxJailerHostKeepsTheAuthorityBoundUnixSocketBeforeAnyDial(t *testing.T) {
	plan := mustCompile(t, validProfile())
	dialer := &recordingUnixDialer{}
	host, err := NewLinuxJailerHost(LinuxJailerHostConfig{
		Plan:           plan,
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		UnixDialer:     dialer,
	})
	if err != nil {
		t.Fatalf("NewLinuxJailerHost() error = %v", err)
	}
	if err := host.HTTP.Bind(context.Background(), "/run/other.socket"); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("HTTP.Bind() error = %v, want fixed-socket refusal", err)
	}
	if err := host.HTTP.Bind(context.Background(), hostJailedPath(expectedJailRoot(plan), fixedFirecrackerAPISocket)); err != nil {
		t.Fatalf("HTTP.Bind() error = %v, want the exact host-visible staged socket", err)
	}
	if got := dialer.CallCount(); got != 0 {
		t.Fatalf("Unix dials = %d, want none before the exact bound socket", got)
	}
	if got, want := host.Authority.ExternalLimitOwners(), completeExternalJailerLimitOwners(); !reflect.DeepEqual(got, want) {
		t.Fatalf("authority external owners = %#v, want %#v", got, want)
	}
}

func TestNewLinuxJailerHostRefusesAnArtifactOnlyPlanSubstitutionBeforeStagingOrPorts(t *testing.T) {
	plan := mustCompile(t, validProfile())
	dialer := &recordingUnixDialer{}
	host, err := NewLinuxJailerHost(LinuxJailerHostConfig{
		Plan:           plan,
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		UnixDialer:     dialer,
	})
	if err != nil {
		t.Fatalf("NewLinuxJailerHost() error = %v", err)
	}
	other := plan
	other.kernel = PinnedArtifact{Path: "/opt/firecracker/other-vmlinux", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	otherFixtures := verifiedPlanFixtures(other)

	if err := host.Preflight(context.Background(), other, otherFixtures); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Preflight() error = %v, want artifact-only plan substitution refusal", err)
	}
	if host.preflight {
		t.Fatal("Preflight marked host ready after an artifact-only plan substitution")
	}
	if got := dialer.CallCount(); got != 0 {
		t.Fatalf("Unix dials = %d, want no port activity before plan refusal", got)
	}
}

func TestNewLinuxJailerHostRefusesAnArtifactOnlyPlanSubstitutionAtPrepareBeforeStaging(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	host, err := NewLinuxJailerHost(LinuxJailerHostConfig{
		Plan:           plan,
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		UnixDialer:     &recordingUnixDialer{},
	})
	if err != nil {
		t.Fatalf("NewLinuxJailerHost() error = %v", err)
	}
	stager := &compositionRecordingStager{stage: validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")}
	host.Resources = stager
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	other := plan
	other.kernel = PinnedArtifact{Path: "/opt/firecracker/other-vmlinux", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}

	if _, err := host.Prepare(context.Background(), other, verifiedPlanFixtures(other)); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Prepare() error = %v, want artifact-only plan substitution refusal", err)
	}
	if got := stager.calls; got != 0 {
		t.Fatalf("stage calls = %d, want no staging before plan refusal", got)
	}
}

func TestNewLinuxJailerHostRefusesAChangedFixtureBindingAtPrepareBeforeStaging(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	host, err := NewLinuxJailerHost(LinuxJailerHostConfig{
		Plan:           plan,
		PreflightState: validKVMPreflight(),
		RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4",
		Authority:      mustCompileJailerExecutionAuthority(t, plan),
		UnixDialer:     &recordingUnixDialer{},
	})
	if err != nil {
		t.Fatalf("NewLinuxJailerHost() error = %v", err)
	}
	stager := &compositionRecordingStager{stage: validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")}
	host.Resources = stager
	if err := host.Preflight(context.Background(), plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	other := fixtures
	other.fixtureVersion = "fixture-v2"

	if _, err := host.Prepare(context.Background(), plan, other); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Prepare() error = %v, want fixture binding refusal", err)
	}
	if got := stager.calls; got != 0 {
		t.Fatalf("stage calls = %d, want no staging before fixture refusal", got)
	}
}

func TestCloneLinuxJailerFixtureSetKeepsTheVerifiedArtifactBindings(t *testing.T) {
	fixtures := verifiedPlanFixtures(mustCompile(t, validProfile()))
	clone := cloneLinuxJailerFixtureSet(fixtures)
	if !sameLinuxJailerFixtureSet(clone, fixtures) {
		t.Fatalf("cloneLinuxJailerFixtureSet() = %#v, want all verified fixture bindings retained", clone)
	}
}

func TestLinuxJailerHostDiscardsTheBoundStageWhenCancellationArrivesAfterStaging(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stage := validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4")
	stager := &compositionCancellationStager{stage: stage, cancel: cancel}
	host := newLinuxJailerHost(plan, fixtures, &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})
	host.Resources = stager
	if err := host.Preflight(ctx, plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}

	if _, err := host.Prepare(ctx, plan, fixtures); !errors.Is(err, context.Canceled) {
		t.Fatalf("Prepare() error = %v, want preserved cancellation", err)
	}
	if got, want := stager.discarded, []JailedResourceStage{stage}; !reflect.DeepEqual(got, want) {
		t.Fatalf("discarded stages = %#v, want %#v", got, want)
	}
	proof, err := host.Cleanup(context.Background())
	if err != nil || !proof.Proved || !reflect.DeepEqual(proof.Removed, []string{filepath.Dir(stage.JailRoot)}) {
		t.Fatalf("Cleanup() = (%#v, %v), want retained staged-namespace cleanup proof", proof, err)
	}
}

func TestLinuxJailerHostPreservesCancellationAndDiscardFailureAfterStaging(t *testing.T) {
	plan := mustCompile(t, validProfile())
	fixtures := verifiedPlanFixtures(plan)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	discardFailure := errors.New("discard failed")
	stager := &compositionCancellationStager{
		stage:      validBoundJailedResourceStage(plan, fixtures, "/run/agent-runtime/sandbox-001/rootfs.ext4"),
		cancel:     cancel,
		discardErr: discardFailure,
	}
	host := newLinuxJailerHost(plan, fixtures, &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})
	host.Resources = stager
	if err := host.Preflight(ctx, plan, fixtures); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}

	if _, err := host.Prepare(ctx, plan, fixtures); !errors.Is(err, context.Canceled) || !errors.Is(err, discardFailure) {
		t.Fatalf("Prepare() error = %v, want joined cancellation and discard failure", err)
	}
	proof, err := host.Cleanup(context.Background())
	if !errors.Is(err, discardFailure) || proof.Proved {
		t.Fatalf("Cleanup() = (%#v, %v), want retained failed staged-namespace cleanup", proof, err)
	}
}

type compositionRecordingStager struct {
	calls int
	stage JailedResourceStage
}

func (stager *compositionRecordingStager) Stage(context.Context, Plan, FixtureSet, string) (JailedResourceStage, error) {
	stager.calls++
	return stager.stage, nil
}

type compositionCancellationStager struct {
	stage      JailedResourceStage
	cancel     context.CancelFunc
	discardErr error
	discarded  []JailedResourceStage
}

func (stager *compositionCancellationStager) Stage(context.Context, Plan, FixtureSet, string) (JailedResourceStage, error) {
	stager.cancel()
	return stager.stage, nil
}

func (stager *compositionCancellationStager) Discard(_ context.Context, _ Plan, stage JailedResourceStage) (CleanupProof, error) {
	stager.discarded = append(stager.discarded, stage)
	if stager.discardErr != nil {
		return CleanupProof{Reason: "discard failed"}, stager.discardErr
	}
	return CleanupProof{Proved: true, Removed: []string{filepath.Dir(stage.JailRoot)}}, nil
}
