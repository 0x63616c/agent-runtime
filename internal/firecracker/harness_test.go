package firecracker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFixtureLockAdmitsOnlyCompleteImmutableArtifacts(t *testing.T) {
	lock := validFixtureLock()
	if err := lock.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	for _, mutate := range []func(*FixtureLock){
		func(lock *FixtureLock) { lock.Artifacts[0].Source = "" },
		func(lock *FixtureLock) { lock.Artifacts[0].SizeBytes = 0 },
		func(lock *FixtureLock) { lock.Artifacts[0].License = "" },
		func(lock *FixtureLock) { lock.Artifacts[1].Name = lock.Artifacts[0].Name },
	} {
		candidate := validFixtureLock()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrFixtureLock) {
			t.Errorf("Validate() error = %v, want fixture-lock refusal", err)
		}
	}
}

func TestFixtureProvisionerVerifiesEveryDownloadBeforeReturningExecutablePaths(t *testing.T) {
	lock := validFixtureLock()
	contents := fixtureContents(lock)
	store := fixtureStoreFunc(func(_ context.Context, source string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(contents[source])), nil
	})
	set, err := ProvisionFixtures(context.Background(), lock, store, t.TempDir())
	if err != nil {
		t.Fatalf("ProvisionFixtures() error = %v", err)
	}
	if got, want := set.Names(), []FixtureName{FixtureFirecracker, FixtureJailer, FixtureKernel, FixtureRootFS}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}
	for _, name := range set.Names() {
		artifact, ok := set.Artifact(name)
		if !ok || filepath.Dir(artifact.Path) != set.Directory() {
			t.Errorf("Artifact(%q) = %#v, %v; want staged artifact", name, artifact, ok)
		}
	}
}

func TestFixtureProvisionerLeavesNoExecutableFixtureWhenAnyDigestIsWrong(t *testing.T) {
	lock := validFixtureLock()
	contents := fixtureContents(lock)
	contents[lock.Artifacts[2].Source] = []byte("changed kernel")
	destination := t.TempDir()
	_, err := ProvisionFixtures(context.Background(), lock, fixtureStoreFunc(func(_ context.Context, source string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(contents[source])), nil
	}), destination)
	if !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("ProvisionFixtures() error = %v, want integrity refusal", err)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatalf("ReadDir() error = %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("fixture directory entries = %v, want no usable fixtures", entries)
	}
}

func TestFixtureProvisionerStopsReadingImmediatelyAfterDeclaredSize(t *testing.T) {
	lock := validFixtureLock()
	contents := fixtureContents(lock)
	first := lock.Artifacts[0]
	contents[first.Source] = append(contents[first.Source], []byte("untrusted trailing bytes")...)
	reader := &countingReader{Reader: bytes.NewReader(contents[first.Source])}

	_, err := ProvisionFixtures(context.Background(), lock, fixtureStoreFunc(func(_ context.Context, source string) (io.ReadCloser, error) {
		if source == first.Source {
			return io.NopCloser(reader), nil
		}
		return io.NopCloser(bytes.NewReader(contents[source])), nil
	}), t.TempDir())
	if !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("ProvisionFixtures() error = %v, want integrity refusal", err)
	}
	if want := int(first.SizeBytes) + 1; reader.bytesRead > want {
		t.Fatalf("fixture reader consumed %d bytes, want hard cap of %d", reader.bytesRead, want)
	}
}

func TestFixtureProvisionerRejectsOversizedDeclaredContentLengthBeforeReadingBody(t *testing.T) {
	lock := validFixtureLock()
	contents := fixtureContents(lock)
	first := lock.Artifacts[0]
	reader := &countingReader{Reader: bytes.NewReader(contents[first.Source])}

	_, err := ProvisionFixtures(context.Background(), lock, fixtureResponseFunc(func(_ context.Context, source string) (FixtureResponse, error) {
		if source == first.Source {
			return FixtureResponse{Body: io.NopCloser(reader), ContentLength: int64(first.SizeBytes) + 1}, nil
		}
		return FixtureResponse{Body: io.NopCloser(bytes.NewReader(contents[source])), ContentLength: int64(len(contents[source]))}, nil
	}), t.TempDir())
	if !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("ProvisionFixtures() error = %v, want integrity refusal", err)
	}
	if reader.bytesRead != 0 {
		t.Fatalf("fixture reader consumed %d bytes, want Content-Length refusal before body", reader.bytesRead)
	}
}

func TestSmokeHarnessBuildsJailedNoNICConfigurationAndCleansEveryResource(t *testing.T) {
	plan := mustCompile(t, validProfile())
	runner := &recordingHost{marker: "AGENT_RUNTIME_SMOKE_OK"}
	harness := SmokeHarness{Host: runner, Timeout: time.Second}
	evidence, err := harness.Run(context.Background(), plan, verifiedPlanFixtures(plan))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if evidence.ProofLevel != ProofLevelLinuxKVME2E || evidence.Result != EvidencePassed || !evidence.Cleanup.Proved {
		t.Fatalf("Run() evidence = %#v, want retained protected-run success", evidence)
	}
	if got, want := runner.steps, []string{"preflight", "prepare", "launch", "marker", "control", "cleanup"}; !reflect.DeepEqual(got, want) {
		t.Errorf("steps = %v, want %v", got, want)
	}
	if runner.request.NetworkInterfaces != 0 || runner.request.RootFSCopyPath == "" || runner.request.CgroupVersion != 2 || runner.request.SerialMarker != "AGENT_RUNTIME_SMOKE_OK" || !reflect.DeepEqual(runner.request.JailerArguments, plan.JailerArguments()) || runner.request.JailerPath != plan.Jailer().Path {
		t.Errorf("launch request = %#v, want cgroup-v2 rootfs copy and no NIC", runner.request)
	}
}

func TestSmokeHarnessNeverReportsPassedWithoutCleanupProof(t *testing.T) {
	plan := mustCompile(t, validProfile())
	runner := &recordingHost{marker: "AGENT_RUNTIME_SMOKE_OK", cleanup: CleanupProof{Reason: "jailer process still present"}}

	evidence, err := (SmokeHarness{Host: runner, Timeout: time.Second}).Run(context.Background(), plan, verifiedPlanFixtures(plan))
	if err == nil {
		t.Fatal("Run() error = nil, want cleanup-proof failure")
	}
	if evidence.Result == EvidencePassed {
		t.Fatalf("Run() evidence = %#v, must not report passed without cleanup proof", evidence)
	}
}

func TestSmokeHarnessGivesCleanupABoundedContext(t *testing.T) {
	plan := mustCompile(t, validProfile())
	runner := &recordingHost{marker: "AGENT_RUNTIME_SMOKE_OK"}

	if _, err := (SmokeHarness{Host: runner, Timeout: time.Second}).Run(context.Background(), plan, verifiedPlanFixtures(plan)); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !runner.cleanupHasDeadline {
		t.Fatal("Cleanup() context has no deadline, want explicit bounded cleanup context")
	}
}

func TestSmokeHarnessReturnsCleanupErrorsInsteadOfReportingPassed(t *testing.T) {
	plan := mustCompile(t, validProfile())
	runner := &recordingHost{marker: "AGENT_RUNTIME_SMOKE_OK", cleanupErr: errors.New("remove jailer cgroup")}

	evidence, err := (SmokeHarness{Host: runner, Timeout: time.Second}).Run(context.Background(), plan, verifiedPlanFixtures(plan))
	if err == nil || !strings.Contains(err.Error(), "remove jailer cgroup") {
		t.Fatalf("Run() error = %v, want cleanup error", err)
	}
	if evidence.Result == EvidencePassed {
		t.Fatalf("Run() evidence = %#v, must not report passed when cleanup errors", evidence)
	}
}

func TestProtectedKVMWorkflowRunsOnProtectedMainPush(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "firecracker-kvm.yml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Contains(workflow, []byte("push:\n    branches:\n      - main")) {
		t.Fatalf("workflow triggers = %q, want protected main push", workflow)
	}
}

func TestSmokeHarnessNeverLaunchesWhenFixtureVerificationOrPreflightFails(t *testing.T) {
	plan := mustCompile(t, validProfile())
	for _, test := range []struct {
		name string
		set  FixtureSet
		host *recordingHost
	}{
		{name: "fixture", set: FixtureSet{}, host: &recordingHost{}},
		{name: "preflight", set: verifiedPlanFixtures(plan), host: &recordingHost{preflightErr: errors.New("no KVM")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := (SmokeHarness{Host: test.host, Timeout: time.Second}).Run(context.Background(), plan, test.set)
			if err == nil {
				t.Fatal("Run() error = nil, want refusal")
			}
			if contains(test.host.steps, "launch") {
				t.Fatalf("steps = %v, must not launch before all verification", test.host.steps)
			}
		})
	}
}

func TestValidateKVMPreflightRequiresLinuxAMD64CharacterKVMAndCgroupV2(t *testing.T) {
	valid := KVMPreflight{GOOS: "linux", GOARCH: "amd64", KVMCharacterDevice: true, KVMReadWrite: true, CgroupV2: true}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	for _, mutate := range []func(*KVMPreflight){
		func(preflight *KVMPreflight) { preflight.GOOS = "darwin" },
		func(preflight *KVMPreflight) { preflight.GOARCH = "arm64" },
		func(preflight *KVMPreflight) { preflight.KVMCharacterDevice = false },
		func(preflight *KVMPreflight) { preflight.KVMReadWrite = false },
		func(preflight *KVMPreflight) { preflight.CgroupV2 = false },
	} {
		candidate := valid
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrSmokeUnavailable) {
			t.Errorf("Validate() error = %v, want unavailable refusal", err)
		}
	}
}

func validFixtureLock() FixtureLock {
	artifacts := []LockedArtifact{
		{Name: FixtureFirecracker, Source: "https://fixtures.invalid/firecracker", License: "Apache-2.0"},
		{Name: FixtureJailer, Source: "https://fixtures.invalid/jailer", License: "Apache-2.0"},
		{Name: FixtureKernel, Source: "https://fixtures.invalid/vmlinux", License: "GPL-2.0-only"},
		{Name: FixtureRootFS, Source: "https://fixtures.invalid/rootfs", License: "GPL-2.0-only"},
	}
	for index := range artifacts {
		content := []byte("fixture-" + string(artifacts[index].Name))
		artifacts[index].Digest = digest(content)
		artifacts[index].SizeBytes = uint64(len(content))
	}
	return FixtureLock{Version: "firecracker.fixtures/v1", Artifacts: artifacts}
}

func fixtureContents(lock FixtureLock) map[string][]byte {
	contents := make(map[string][]byte, len(lock.Artifacts))
	for _, artifact := range lock.Artifacts {
		contents[artifact.Source] = []byte("fixture-" + string(artifact.Name))
	}
	return contents
}

func verifiedPlanFixtures(plan Plan) FixtureSet {
	return FixtureSet{directory: "/fixtures", artifacts: planArtifacts(plan), verified: true}
}

type recordingHost struct {
	steps              []string
	marker             string
	preflightErr       error
	request            LaunchRequest
	cleanup            CleanupProof
	cleanupHasDeadline bool
	cleanupErr         error
}

func (host *recordingHost) Preflight(context.Context, Plan, FixtureSet) error {
	host.steps = append(host.steps, "preflight")
	return host.preflightErr
}
func (host *recordingHost) Prepare(_ context.Context, plan Plan, _ FixtureSet) (LaunchRequest, error) {
	host.steps = append(host.steps, "prepare")
	request, err := NewLaunchRequest(plan, "/run/jailer/rootfs.ext4", host.marker)
	if err != nil {
		return LaunchRequest{}, err
	}
	host.request = request
	return host.request, nil
}
func (host *recordingHost) Launch(context.Context, LaunchRequest) error {
	host.steps = append(host.steps, "launch")
	return nil
}
func (host *recordingHost) AwaitSerial(context.Context, string) error {
	host.steps = append(host.steps, "marker")
	return nil
}
func (host *recordingHost) Control(context.Context) error {
	host.steps = append(host.steps, "control")
	return nil
}
func (host *recordingHost) Cleanup(ctx context.Context) (CleanupProof, error) {
	host.steps = append(host.steps, "cleanup")
	_, host.cleanupHasDeadline = ctx.Deadline()
	if host.cleanup.Reason != "" || host.cleanup.Proved {
		return host.cleanup, host.cleanupErr
	}
	return CleanupProof{Proved: true}, host.cleanupErr
}

type countingReader struct {
	io.Reader
	bytesRead int
}

type fixtureResponseFunc func(context.Context, string) (FixtureResponse, error)

func (f fixtureResponseFunc) Open(ctx context.Context, source string) (FixtureResponse, error) {
	return f(ctx, source)
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.Reader.Read(buffer)
	reader.bytesRead += read
	return read, err
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
