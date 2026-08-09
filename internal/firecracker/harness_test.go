package firecracker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
		func(lock *FixtureLock) { lock.Sources[0].URL = "" },
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

func TestFixtureLockV2RequiresGuestAgentAlongsideEveryLaunchArtifact(t *testing.T) {
	lock := validFixtureLock()

	if err := lock.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want a complete v2 fixture identity", err)
	}
}

func TestFixtureLockV2RefusesLegacyV1WithoutImplicitMigration(t *testing.T) {
	lock := validFixtureLock()
	lock.Version = "firecracker.fixtures/v1"

	if err := lock.Validate(); !errors.Is(err, ErrFixtureLock) {
		t.Fatalf("Validate() error = %v, want explicit legacy-lock refusal", err)
	}
}

func TestFixtureLockV2RequiresFirecrackerAndJailerToShareVerifiedBundle(t *testing.T) {
	lock := validFixtureLock()
	lock.Artifacts[1].SourceID = "kernel"

	if err := lock.Validate(); !errors.Is(err, ErrFixtureLock) {
		t.Fatalf("Validate() error = %v, want source-bundle refusal", err)
	}
}

func TestFixtureLockV2BindsDirectArtifactToItsVerifiedSource(t *testing.T) {
	lock := validFixtureLock()
	lock.Artifacts[2].Digest = digest([]byte("substituted-kernel"))

	if err := lock.Validate(); !errors.Is(err, ErrFixtureLock) {
		t.Fatalf("Validate() error = %v, want direct-source identity refusal", err)
	}
}

func TestFixtureLockV2RejectsAmbiguousBundleMemberPath(t *testing.T) {
	lock := validFixtureLock()
	lock.Artifacts[0].Member = "."

	if err := lock.Validate(); !errors.Is(err, ErrFixtureLock) {
		t.Fatalf("Validate() error = %v, want bundle-member refusal", err)
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
	if got, want := set.Names(), []FixtureName{FixtureFirecracker, FixtureGuestAgent, FixtureJailer, FixtureKernel, FixtureRootFS}; !reflect.DeepEqual(got, want) {
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
	contents[fixtureSource(lock, lock.Artifacts[2].SourceID).URL] = []byte("changed kernel")
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
	first := lock.Artifacts[2]
	firstSource := fixtureSource(lock, first.SourceID)
	contents[firstSource.URL] = append(contents[firstSource.URL], []byte("untrusted trailing bytes")...)
	reader := &countingReader{Reader: bytes.NewReader(contents[firstSource.URL])}

	_, err := ProvisionFixtures(context.Background(), lock, fixtureStoreFunc(func(_ context.Context, source string) (io.ReadCloser, error) {
		if source == firstSource.URL {
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
	first := lock.Artifacts[2]
	firstSource := fixtureSource(lock, first.SourceID)
	reader := &countingReader{Reader: bytes.NewReader(contents[firstSource.URL])}

	_, err := ProvisionFixtures(context.Background(), lock, fixtureResponseFunc(func(_ context.Context, source string) (FixtureResponse, error) {
		if source == firstSource.URL {
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
	const revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	firecrackerContent := []byte("fixture-firecracker")
	jailerContent := []byte("fixture-jailer")
	kernelContent := []byte("fixture-kernel")
	rootFSContent := []byte("fixture-rootfs")
	guestAgentContent := []byte("fixture-guest-agent")
	bundleContent := fixtureBundle(map[string][]byte{
		"release/firecracker": firecrackerContent,
		"release/jailer":      jailerContent,
	})
	guestAgentDigest := digest(guestAgentContent)
	return FixtureLock{
		Version: "firecracker.fixtures/v2",
		Sources: []LockedSource{
			{ID: "firecracker-release", URL: "https://fixtures.invalid/firecracker-release", Reference: "v1.16.1", Format: FixtureSourceTarGzip, Digest: digest(bundleContent), SizeBytes: uint64(len(bundleContent)), License: "Apache-2.0"},
			{ID: "kernel", URL: "https://fixtures.invalid/vmlinux", Reference: "version-id-kernel", Format: FixtureSourceFile, Digest: digest(kernelContent), SizeBytes: uint64(len(kernelContent)), License: "GPL-2.0-only"},
			{ID: "rootfs", URL: "https://fixtures.invalid/rootfs", Reference: "project-release-rootfs", Format: FixtureSourceFile, Digest: digest(rootFSContent), SizeBytes: uint64(len(rootFSContent)), License: "LicenseRef-agent-runtime-rootfs-sbom"},
			{ID: "guest-agent", URL: "https://fixtures.invalid/guest-agent", Reference: "project-release-guest-agent", Format: FixtureSourceFile, Digest: guestAgentDigest, SizeBytes: uint64(len(guestAgentContent)), License: "MIT"},
		},
		Artifacts: []LockedArtifact{
			{Name: FixtureFirecracker, SourceID: "firecracker-release", Member: "release/firecracker", Digest: digest(firecrackerContent), SizeBytes: uint64(len(firecrackerContent)), License: "Apache-2.0"},
			{Name: FixtureJailer, SourceID: "firecracker-release", Member: "release/jailer", Digest: digest(jailerContent), SizeBytes: uint64(len(jailerContent)), License: "Apache-2.0"},
			{Name: FixtureKernel, SourceID: "kernel", Digest: digest(kernelContent), SizeBytes: uint64(len(kernelContent)), License: "GPL-2.0-only"},
			{Name: FixtureRootFS, SourceID: "rootfs", Digest: digest(rootFSContent), SizeBytes: uint64(len(rootFSContent)), License: "LicenseRef-agent-runtime-rootfs-sbom", Build: &BuildProvenance{RecipePath: "tools/firecracker/build-rootfs.sh", SourceRevision: revision, Toolchain: "go1.26.0+e2fsprogs", InputsDigest: digest([]byte("rootfs-inputs")), SBOMDigest: digest([]byte("rootfs-sbom")), GuestAgentDigest: guestAgentDigest}},
			{Name: FixtureGuestAgent, SourceID: "guest-agent", Digest: guestAgentDigest, SizeBytes: uint64(len(guestAgentContent)), License: "MIT", Build: &BuildProvenance{RecipePath: "tools/firecracker/build-guest-agent.sh", SourceRevision: revision, Toolchain: "go1.26.0", InputsDigest: digest([]byte("guest-agent-inputs")), SBOMDigest: digest([]byte("guest-agent-sbom")), Static: true}},
		},
	}
}

func fixtureContents(lock FixtureLock) map[string][]byte {
	return map[string][]byte{
		fixtureSource(lock, "firecracker-release").URL: fixtureBundle(map[string][]byte{"release/firecracker": []byte("fixture-firecracker"), "release/jailer": []byte("fixture-jailer")}),
		fixtureSource(lock, "kernel").URL:              []byte("fixture-kernel"),
		fixtureSource(lock, "rootfs").URL:              []byte("fixture-rootfs"),
		fixtureSource(lock, "guest-agent").URL:         []byte("fixture-guest-agent"),
	}
}

func fixtureSource(lock FixtureLock, id string) LockedSource {
	for _, source := range lock.Sources {
		if source.ID == id {
			return source
		}
	}
	panic("fixture source is absent: " + id)
}

func fixtureBundle(members map[string][]byte) []byte {
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range []string{"release/firecracker", "release/jailer"} {
		content := members[name]
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			panic(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			panic(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		panic(err)
	}
	if err := gzipWriter.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
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
