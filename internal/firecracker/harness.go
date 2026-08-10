package firecracker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

var (
	// ErrFixtureLock means a fixture lock is incomplete or permits mutable provenance.
	ErrFixtureLock = errors.New("invalid Firecracker fixture lock")
	// ErrSmokeUnavailable means a protected-run host cannot prove a smoke prerequisite.
	ErrSmokeUnavailable = errors.New("Firecracker smoke harness unavailable")
)

const maximumFixtureLockBytes = 256 << 10

// FixtureName identifies one non-interchangeable Firecracker fixture.
type FixtureName string

const (
	// FixtureFirecracker identifies the Firecracker VMM executable.
	FixtureFirecracker FixtureName = "firecracker"
	// FixtureJailer identifies the Firecracker Jailer executable.
	FixtureJailer FixtureName = "jailer"
	// FixtureKernel identifies the admitted guest kernel.
	FixtureKernel FixtureName = "kernel"
	// FixtureRootFS identifies the admitted guest root filesystem.
	FixtureRootFS FixtureName = "rootfs"
	// FixtureGuestAgent identifies the project-owned static guest control program.
	FixtureGuestAgent FixtureName = "guest-agent"
)

// FixtureSourceFormat describes how artifacts are derived from a verified source.
type FixtureSourceFormat string

const (
	// FixtureSourceFile identifies a source containing exactly one artifact.
	FixtureSourceFile FixtureSourceFormat = "file"
	// FixtureSourceTarGzip identifies a gzip-compressed tar source bundle.
	FixtureSourceTarGzip FixtureSourceFormat = "tar.gz"
)

// FixtureSourceKind identifies the immutable identity scheme used by one source.
type FixtureSourceKind string

const (
	// FixtureSourceReleaseArchive identifies a versioned upstream release archive.
	FixtureSourceReleaseArchive FixtureSourceKind = "release-archive"
	// FixtureSourceVersionedObject identifies an immutable object-store object version.
	FixtureSourceVersionedObject FixtureSourceKind = "versioned-object"
	// FixtureSourceProjectBuild identifies an output rebuilt from one project commit.
	FixtureSourceProjectBuild FixtureSourceKind = "project-build"
)

// FixturePlatform records the operating-system and processor identity of a bootable fixture.
type FixturePlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// LockedSource records a single immutable non-executable fixture source.
type LockedSource struct {
	ID        string              `json:"id"`
	Kind      FixtureSourceKind   `json:"kind"`
	URL       string              `json:"url"`
	Reference string              `json:"immutable_reference"`
	Format    FixtureSourceFormat `json:"format"`
	Digest    sandbox.Digest      `json:"sha256"`
	SizeBytes uint64              `json:"size_bytes"`
	License   string              `json:"license"`
}

// BuildProvenance records the checked-in, reproducible inputs of a project-owned fixture output.
type BuildProvenance struct {
	RecipePath        string         `json:"recipe_path"`
	SourceRevision    string         `json:"source_revision"`
	Toolchain         string         `json:"toolchain"`
	InputsDigest      sandbox.Digest `json:"inputs_sha256"`
	SBOMDigest        sandbox.Digest `json:"sbom_sha256"`
	Static            bool           `json:"static"`
	GuestAgentDigest  sandbox.Digest `json:"guest_agent_sha256,omitempty"`
	AttestationMember string         `json:"attestation_member,omitempty"`
}

// LockedArtifact records immutable provenance required before an artifact may be used.
type LockedArtifact struct {
	Name      FixtureName      `json:"name"`
	SourceID  string           `json:"source_id"`
	Member    string           `json:"member,omitempty"`
	Digest    sandbox.Digest   `json:"sha256"`
	SizeBytes uint64           `json:"size_bytes"`
	License   string           `json:"license"`
	Platform  FixturePlatform  `json:"platform"`
	Build     *BuildProvenance `json:"build,omitempty"`
}

// RootFSAttestation is the rootfs-build sidecar that binds the installed init to the guest-agent artifact.
type RootFSAttestation struct {
	SchemaVersion string          `json:"schema_version"`
	RootFSDigest  sandbox.Digest  `json:"rootfs_sha256"`
	RootFSSize    uint64          `json:"rootfs_size_bytes"`
	InitPath      string          `json:"init_path"`
	InitDigest    sandbox.Digest  `json:"init_sha256"`
	InitSize      uint64          `json:"init_size_bytes"`
	Platform      FixturePlatform `json:"platform"`
	Static        bool            `json:"static"`
}

// FixtureLock is a reviewed, complete fixture identity lock.
type FixtureLock struct {
	Version        string           `json:"version"`
	FixtureVersion string           `json:"fixture_version"`
	Sources        []LockedSource   `json:"sources"`
	Artifacts      []LockedArtifact `json:"artifacts"`
}

// ParseFixtureLock reads one bounded, strict, complete fixture-lock document.
func ParseFixtureLock(reader io.Reader) (FixtureLock, error) {
	if reader == nil {
		return FixtureLock{}, fmt.Errorf("%w: lock reader is required", ErrFixtureLock)
	}
	contents, err := io.ReadAll(io.LimitReader(reader, maximumFixtureLockBytes+1))
	if err != nil {
		return FixtureLock{}, fmt.Errorf("%w: read lock: %v", ErrFixtureLock, err)
	}
	if len(contents) > maximumFixtureLockBytes {
		return FixtureLock{}, fmt.Errorf("%w: lock exceeds %d bytes", ErrFixtureLock, maximumFixtureLockBytes)
	}
	if err := validateFixtureLockJSON(contents); err != nil {
		return FixtureLock{}, fmt.Errorf("%w: strict lock shape: %v", ErrFixtureLock, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var lock FixtureLock
	if err := decoder.Decode(&lock); err != nil {
		return FixtureLock{}, fmt.Errorf("%w: decode lock: %v", ErrFixtureLock, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return FixtureLock{}, fmt.Errorf("%w: lock contains trailing data", ErrFixtureLock)
	}
	if err := lock.Validate(); err != nil {
		return FixtureLock{}, err
	}
	return lock, nil
}

type fixtureLockJSONShape struct {
	fields  map[string]fixtureLockJSONShape
	element *fixtureLockJSONShape
}

var fixtureLockJSONDocument = fixtureLockJSONShape{fields: map[string]fixtureLockJSONShape{
	"version":         fixtureLockJSONScalar,
	"fixture_version": fixtureLockJSONScalar,
	"sources":         {element: &fixtureLockJSONSource},
	"artifacts":       {element: &fixtureLockJSONArtifact},
}}

var fixtureLockJSONSource = fixtureLockJSONShape{fields: map[string]fixtureLockJSONShape{
	"id":                  fixtureLockJSONScalar,
	"kind":                fixtureLockJSONScalar,
	"url":                 fixtureLockJSONScalar,
	"immutable_reference": fixtureLockJSONScalar,
	"format":              fixtureLockJSONScalar,
	"sha256":              fixtureLockJSONScalar,
	"size_bytes":          fixtureLockJSONScalar,
	"license":             fixtureLockJSONScalar,
}}

var fixtureLockJSONArtifact = fixtureLockJSONShape{fields: map[string]fixtureLockJSONShape{
	"name":       fixtureLockJSONScalar,
	"source_id":  fixtureLockJSONScalar,
	"member":     fixtureLockJSONScalar,
	"sha256":     fixtureLockJSONScalar,
	"size_bytes": fixtureLockJSONScalar,
	"license":    fixtureLockJSONScalar,
	"platform": {fields: map[string]fixtureLockJSONShape{
		"os":           fixtureLockJSONScalar,
		"architecture": fixtureLockJSONScalar,
	}},
	"build": {fields: map[string]fixtureLockJSONShape{
		"recipe_path":        fixtureLockJSONScalar,
		"source_revision":    fixtureLockJSONScalar,
		"toolchain":          fixtureLockJSONScalar,
		"inputs_sha256":      fixtureLockJSONScalar,
		"sbom_sha256":        fixtureLockJSONScalar,
		"static":             fixtureLockJSONScalar,
		"guest_agent_sha256": fixtureLockJSONScalar,
		"attestation_member": fixtureLockJSONScalar,
	}},
}}

var fixtureLockJSONScalar fixtureLockJSONShape

func validateFixtureLockJSON(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := validateFixtureLockJSONValue(decoder, fixtureLockJSONDocument); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func validateFixtureLockJSONValue(decoder *json.Decoder, shape fixtureLockJSONShape) error {
	if shape.element != nil {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
			return errors.New("array is required")
		}
		for decoder.More() {
			if err := validateFixtureLockJSONValue(decoder, *shape.element); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if shape.fields == nil {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if _, isContainer := token.(json.Delim); isContainer {
			return errors.New("scalar value is required")
		}
		return nil
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("object is required")
	}
	seen := make(map[string]struct{}, len(shape.fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("object key is required")
		}
		field, known := shape.fields[key]
		if !known {
			return fmt.Errorf("unknown or non-canonical key %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = struct{}{}
		if err := validateFixtureLockJSONValue(decoder, field); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

// Validate rejects partial, mutable, duplicate, or unlicensed fixture locks.
func (lock FixtureLock) Validate() error {
	if lock.Version != "firecracker.fixtures/v2" || !validFixtureVersion(lock.FixtureVersion) || len(lock.Artifacts) != 5 {
		return fmt.Errorf("%w: schema version, immutable fixture version, and exactly five artifacts are required", ErrFixtureLock)
	}
	sources := make(map[string]LockedSource, len(lock.Sources))
	for _, source := range lock.Sources {
		if !validFixtureSource(source) || sources[source.ID].ID != "" {
			return fmt.Errorf("%w: every source needs one safe ID, immutable HTTPS reference, SHA-256, non-zero size, format, and license", ErrFixtureLock)
		}
		sources[source.ID] = source
	}
	want := map[FixtureName]bool{FixtureFirecracker: false, FixtureJailer: false, FixtureKernel: false, FixtureRootFS: false, FixtureGuestAgent: false}
	var firecrackerSourceID, jailerSourceID string
	var guestAgentDigest sandbox.Digest
	var rootFS *LockedArtifact
	for _, artifact := range lock.Artifacts {
		seen, known := want[artifact.Name]
		source, found := sources[artifact.SourceID]
		if !known || seen || !found || !validArtifactIdentity(artifact) || !validArtifactDerivation(artifact, source) {
			return fmt.Errorf("%w: every named artifact needs one source, valid derivation, SHA-256, non-zero size, and license", ErrFixtureLock)
		}
		if artifact.Name == FixtureFirecracker {
			firecrackerSourceID = artifact.SourceID
		}
		if artifact.Name == FixtureJailer {
			jailerSourceID = artifact.SourceID
		}
		if artifact.Name == FixtureGuestAgent {
			guestAgentDigest = artifact.Digest
		}
		if artifact.Name == FixtureRootFS {
			copy := artifact
			rootFS = &copy
		}
		want[artifact.Name] = true
	}
	for name, seen := range want {
		if !seen {
			return fmt.Errorf("%w: missing %s", ErrFixtureLock, name)
		}
	}
	if firecrackerSourceID == "" || firecrackerSourceID != jailerSourceID || rootFS == nil || rootFS.Build == nil || rootFS.Build.GuestAgentDigest != guestAgentDigest {
		return fmt.Errorf("%w: Firecracker and Jailer must share one verified bundle and rootfs must bind the guest agent digest", ErrFixtureLock)
	}
	return nil
}

func validFixtureSource(source LockedSource) bool {
	parsed, err := url.Parse(source.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if !validFixtureID(source.ID) || source.Format == "" || !validSHA256(source.Digest) || source.SizeBytes == 0 || source.SizeBytes >= math.MaxInt64 || strings.TrimSpace(source.License) == "" {
		return false
	}
	switch source.Kind {
	case FixtureSourceReleaseArchive:
		version, ok := strings.CutPrefix(source.Reference, "release:")
		return ok && validReleaseVersion(version) && source.Format == FixtureSourceTarGzip && len(parsed.Query()) == 0 && parsed.Host == "github.com" && strings.HasPrefix(parsed.Path, "/firecracker-microvm/firecracker/releases/download/"+version+"/")
	case FixtureSourceVersionedObject:
		versionID, ok := strings.CutPrefix(source.Reference, "version-id:")
		return ok && validObjectVersionID(versionID) && source.Format == FixtureSourceFile && len(parsed.Query()) == 1 && len(parsed.Query()["versionId"]) == 1 && parsed.Query().Get("versionId") == versionID
	case FixtureSourceProjectBuild:
		revision, ok := strings.CutPrefix(source.Reference, "commit:")
		return ok && validRevision(revision) && len(parsed.Query()) == 0 && (source.Format == FixtureSourceFile || source.Format == FixtureSourceTarGzip)
	default:
		return false
	}
}

func validArtifactIdentity(artifact LockedArtifact) bool {
	return validSHA256(artifact.Digest) && artifact.SizeBytes > 0 && artifact.SizeBytes < math.MaxInt64 && strings.TrimSpace(artifact.License) != "" && validFixturePlatform(artifact.Platform)
}

func validArtifactDerivation(artifact LockedArtifact, source LockedSource) bool {
	switch source.Format {
	case FixtureSourceFile:
		if artifact.Member != "" || artifact.Digest != source.Digest || artifact.SizeBytes != source.SizeBytes {
			return false
		}
	case FixtureSourceTarGzip:
		if !validBundleMember(artifact.Member) {
			return false
		}
	default:
		return false
	}
	switch artifact.Name {
	case FixtureFirecracker, FixtureJailer:
		return source.Kind == FixtureSourceReleaseArchive && source.Format == FixtureSourceTarGzip && artifact.Build == nil
	case FixtureKernel:
		return source.Kind == FixtureSourceVersionedObject && source.Format == FixtureSourceFile && artifact.Build == nil
	case FixtureRootFS:
		return source.Kind == FixtureSourceProjectBuild && source.Format == FixtureSourceTarGzip && validBuildProvenance(artifact.Build, false) && provenanceMatchesSource(artifact.Build, source) && validBundleMember(artifact.Build.AttestationMember)
	case FixtureGuestAgent:
		return source.Kind == FixtureSourceProjectBuild && source.Format == FixtureSourceFile && validBuildProvenance(artifact.Build, true) && provenanceMatchesSource(artifact.Build, source) && artifact.Build.AttestationMember == ""
	default:
		return false
	}
}

func validFixturePlatform(platform FixturePlatform) bool {
	return platform.OS == "linux" && platform.Architecture == "amd64"
}

func validReleaseVersion(value string) bool {
	if len(value) < 6 || value[0] != 'v' {
		return false
	}
	components := strings.Split(value[1:], ".")
	if len(components) != 3 {
		return false
	}
	for _, component := range components {
		if component == "" {
			return false
		}
		for _, character := range component {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validObjectVersionID(value string) bool {
	if value == "" || value == "latest" || value == "main" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._~-", character)) {
			return false
		}
	}
	return true
}

func validFixtureID(value string) bool {
	return validVMID(value)
}

func validFixtureVersion(value string) bool {
	return validFixtureID(value) && value != "latest" && value != "main"
}

func validBundleMember(value string) bool {
	return value != "" && value != "." && !strings.HasPrefix(value, "/") && path.Clean(value) == value && !strings.HasPrefix(value, "../") && !strings.Contains(value, "\\")
}

func validBuildProvenance(provenance *BuildProvenance, requireStatic bool) bool {
	if provenance == nil || provenance.Static != requireStatic || !strings.HasPrefix(provenance.RecipePath, "tools/firecracker/") || path.Clean(provenance.RecipePath) != provenance.RecipePath || strings.Contains(provenance.RecipePath, "\\") || !validRevision(provenance.SourceRevision) || strings.TrimSpace(provenance.Toolchain) == "" || !validSHA256(provenance.InputsDigest) || !validSHA256(provenance.SBOMDigest) {
		return false
	}
	return !requireStatic || provenance.GuestAgentDigest == ""
}

func provenanceMatchesSource(provenance *BuildProvenance, source LockedSource) bool {
	revision, ok := strings.CutPrefix(source.Reference, "commit:")
	return ok && provenance != nil && provenance.SourceRevision == revision
}

func validRevision(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// FixtureResponse is a non-executable immutable fixture response. ContentLength
// is -1 when the source did not declare one.
type FixtureResponse struct {
	Body          io.ReadCloser
	ContentLength int64
}

// FixtureFetcher retrieves an immutable source without executing it.
type FixtureFetcher interface {
	Open(context.Context, string) (FixtureResponse, error)
}

type fixtureStoreFunc func(context.Context, string) (io.ReadCloser, error)

func (f fixtureStoreFunc) Open(ctx context.Context, source string) (FixtureResponse, error) {
	body, err := f(ctx, source)
	return FixtureResponse{Body: body, ContentLength: -1}, err
}

// FixtureSet contains fixtures that have been downloaded and completely verified.
type FixtureSet struct {
	directory      string
	fixtureVersion string
	artifacts      map[FixtureName]PinnedArtifact
	verified       bool
}

// Directory returns the private staging directory containing verified fixtures.
func (set FixtureSet) Directory() string { return set.directory }

// FixtureVersion returns the immutable fixture identity that the guest must report at boot.
func (set FixtureSet) FixtureVersion() string { return set.fixtureVersion }

// Names returns the complete fixture set in deterministic order.
func (set FixtureSet) Names() []FixtureName {
	names := make([]FixtureName, 0, len(set.artifacts))
	for name := range set.artifacts {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool { return names[left] < names[right] })
	return names
}

// Artifact returns one verified fixture identity.
func (set FixtureSet) Artifact(name FixtureName) (PinnedArtifact, bool) {
	artifact, ok := set.artifacts[name]
	return artifact, ok
}

// ProvisionFixtures downloads every locked fixture to private staging and only returns after all size and digest checks pass.
func ProvisionFixtures(ctx context.Context, lock FixtureLock, fetcher FixtureFetcher, destination string) (FixtureSet, error) {
	if err := lock.Validate(); err != nil {
		return FixtureSet{}, err
	}
	if fetcher == nil || !safeAbsolutePath(destination) {
		return FixtureSet{}, fmt.Errorf("%w: fetcher and private destination are required", ErrFixtureLock)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return FixtureSet{}, fmt.Errorf("create fixture staging: %w", err)
	}
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		entries, readErr := os.ReadDir(destination)
		if readErr != nil {
			return
		}
		for _, entry := range entries {
			_ = os.RemoveAll(filepath.Join(destination, entry.Name()))
		}
	}()
	stagedSources, err := stageFixtureSources(ctx, lock.Sources, fetcher, destination)
	if err != nil {
		return FixtureSet{}, err
	}
	if err := verifyRootFSAgentBinding(lock, stagedSources); err != nil {
		return FixtureSet{}, err
	}
	set := FixtureSet{directory: destination, fixtureVersion: lock.FixtureVersion, artifacts: make(map[FixtureName]PinnedArtifact, len(lock.Artifacts))}
	for _, artifact := range lock.Artifacts {
		source, found := findFixtureSource(lock.Sources, artifact.SourceID)
		if !found {
			return FixtureSet{}, fmt.Errorf("%w: source %s disappeared after validation", ErrFixtureLock, artifact.SourceID)
		}
		path, found := stagedSources[artifact.SourceID]
		if !found {
			return FixtureSet{}, fmt.Errorf("%w: staged source %s is absent", ErrArtifactIntegrity, artifact.SourceID)
		}
		artifactPath := filepath.Join(destination, string(artifact.Name))
		if err := stageFixtureArtifact(artifactPath, source, artifact, path); err != nil {
			return FixtureSet{}, err
		}
		set.artifacts[artifact.Name] = PinnedArtifact{Path: artifactPath, Digest: artifact.Digest}
	}
	set.verified = true
	cleanup = false
	return set, nil
}

func verifyRootFSAgentBinding(lock FixtureLock, stagedSources map[string]string) error {
	var rootFS, guestAgent *LockedArtifact
	for index := range lock.Artifacts {
		artifact := &lock.Artifacts[index]
		switch artifact.Name {
		case FixtureRootFS:
			rootFS = artifact
		case FixtureGuestAgent:
			guestAgent = artifact
		}
	}
	if rootFS == nil || guestAgent == nil || rootFS.Build == nil {
		return fmt.Errorf("%w: rootfs and guest-agent identities are required", ErrArtifactIntegrity)
	}
	source, found := findFixtureSource(lock.Sources, rootFS.SourceID)
	if !found {
		return fmt.Errorf("%w: rootfs source is absent", ErrArtifactIntegrity)
	}
	sourcePath, found := stagedSources[source.ID]
	if !found {
		return fmt.Errorf("%w: staged rootfs source is absent", ErrArtifactIntegrity)
	}
	contents, err := readVerifiedBundleMember(sourcePath, source.ID, rootFS.Build.AttestationMember, 64<<10)
	if err != nil {
		return fmt.Errorf("%w: read rootfs attestation: %v", ErrArtifactIntegrity, err)
	}
	var attestation RootFSAttestation
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attestation); err != nil || !validRootFSAttestation(attestation, *rootFS, *guestAgent) {
		return fmt.Errorf("%w: rootfs attestation does not bind /sbin/init to the verified guest agent", ErrArtifactIntegrity)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: rootfs attestation contains trailing data", ErrArtifactIntegrity)
	}
	return nil
}

func validRootFSAttestation(attestation RootFSAttestation, rootFS, guestAgent LockedArtifact) bool {
	return attestation.SchemaVersion == "agent-runtime.firecracker.rootfs-attestation/v1" && attestation.RootFSDigest == rootFS.Digest && attestation.RootFSSize == rootFS.SizeBytes && attestation.InitPath == "/sbin/init" && attestation.InitDigest == guestAgent.Digest && attestation.InitSize == guestAgent.SizeBytes && attestation.Platform == guestAgent.Platform && validFixturePlatform(attestation.Platform) && attestation.Static
}

func readVerifiedBundleMember(sourcePath, sourceID, member string, maximumSize uint64) ([]byte, error) {
	file, err := os.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("open staged bundle %s: %w", sourceID, err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("open gzip bundle %s: %w", sourceID, err)
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)
	var contents []byte
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("read bundle %s: %w", sourceID, nextErr)
		}
		if header.Name != member {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || uint64(header.Size) > maximumSize || contents != nil {
			return nil, fmt.Errorf("invalid bundle member %s", member)
		}
		contents, err = io.ReadAll(io.LimitReader(tarReader, int64(maximumSize)+1))
		if err != nil || uint64(len(contents)) > maximumSize {
			return nil, fmt.Errorf("read bounded bundle member %s", member)
		}
	}
	if contents == nil {
		return nil, fmt.Errorf("bundle member %s is absent", member)
	}
	return contents, nil
}

func stageFixtureSources(ctx context.Context, sources []LockedSource, fetcher FixtureFetcher, destination string) (map[string]string, error) {
	sourceDirectory := filepath.Join(destination, ".sources")
	if err := os.Mkdir(sourceDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("stage fixture sources: %w", err)
	}
	staged := make(map[string]string, len(sources))
	for _, source := range sources {
		response, err := fetcher.Open(ctx, source.URL)
		if err != nil {
			return nil, fmt.Errorf("%w: download source %s: %v", ErrArtifactIntegrity, source.ID, err)
		}
		if response.Body == nil {
			return nil, fmt.Errorf("%w: download source %s: empty response body", ErrArtifactIntegrity, source.ID)
		}
		if response.ContentLength >= 0 && uint64(response.ContentLength) > source.SizeBytes {
			_ = response.Body.Close()
			return nil, fmt.Errorf("%w: download source %s: declared content length exceeds fixture limit", ErrArtifactIntegrity, source.ID)
		}
		stagedPath := filepath.Join(sourceDirectory, source.ID)
		if err := writeVerifiedFixture(stagedPath, response.Body, source.Digest, source.SizeBytes); err != nil {
			return nil, fmt.Errorf("%w: verify source %s", ErrArtifactIntegrity, source.ID)
		}
		staged[source.ID] = stagedPath
	}
	return staged, nil
}

func stageFixtureArtifact(destination string, source LockedSource, artifact LockedArtifact, sourcePath string) error {
	if source.Format == FixtureSourceFile {
		file, err := os.Open(sourcePath)
		if err != nil {
			return fmt.Errorf("%w: open staged source %s: %v", ErrArtifactIntegrity, source.ID, err)
		}
		if err := writeVerifiedFixture(destination, file, artifact.Digest, artifact.SizeBytes); err != nil {
			return fmt.Errorf("%w: verify %s", ErrArtifactIntegrity, artifact.Name)
		}
		return nil
	}
	file, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("%w: open staged bundle %s: %v", ErrArtifactIntegrity, source.ID, err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("%w: open gzip bundle %s: %v", ErrArtifactIntegrity, source.ID, err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	found := false
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("%w: read bundle %s: %v", ErrArtifactIntegrity, source.ID, nextErr)
		}
		if header.Name != artifact.Member {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size != int64(artifact.SizeBytes) {
			return fmt.Errorf("%w: invalid bundle member %s", ErrArtifactIntegrity, artifact.Name)
		}
		if err := writeVerifiedFixture(destination, tarReader, artifact.Digest, artifact.SizeBytes); err != nil {
			return fmt.Errorf("%w: verify bundle member %s", ErrArtifactIntegrity, artifact.Name)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("%w: bundle member %s is absent", ErrArtifactIntegrity, artifact.Name)
	}
	return nil
}

func writeVerifiedFixture(destination string, reader io.Reader, digest sandbox.Digest, sizeBytes uint64) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, int64(sizeBytes)+1))
	closeErr := errors.Join(file.Close(), closerError(reader))
	if copyErr != nil || closeErr != nil || uint64(written) != sizeBytes || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != string(digest) {
		return errors.New("digest or size mismatch")
	}
	return nil
}

func closerError(reader io.Reader) error {
	closer, ok := reader.(io.Closer)
	if !ok {
		return nil
	}
	return closer.Close()
}

func findFixtureSource(sources []LockedSource, id string) (LockedSource, bool) {
	for _, source := range sources {
		if source.ID == id {
			return source, true
		}
	}
	return LockedSource{}, false
}

// BootInput is the validated immutable argument pair passed to rootfs /sbin/init.
type BootInput struct {
	VMID           string
	FixtureVersion string
}

// KernelArguments returns the closed kernel command-line argument sequence for this boot input.
func (input BootInput) KernelArguments() []string {
	return []string{"console=ttyS0", "reboot=k", "panic=1", "init=/sbin/init", "--", input.VMID, input.FixtureVersion}
}

func validBootInput(input BootInput) bool {
	return validVMID(input.VMID) && validFixtureVersion(input.FixtureVersion)
}

func (input BootInput) serialMarker() string {
	return "AGENT_RUNTIME_FC_SMOKE " + input.VMID + " " + input.FixtureVersion + " agent-runtime-firecracker-guest/v1"
}

// LaunchRequest is the complete no-NIC Jailer request passed to a protected host implementation.
type LaunchRequest struct {
	JailerPath        string
	JailerArguments   []string
	RootFSCopyPath    string
	CgroupVersion     uint8
	NetworkInterfaces uint8
	SerialMarker      string
	Boot              BootInput
	KernelArguments   []string
}

// NewLaunchRequest freezes the exact Jailer argv and deny-all launch configuration for one verified rootfs copy.
func NewLaunchRequest(plan Plan, rootFSCopyPath string, boot BootInput) (LaunchRequest, error) {
	if !validCompiledPlan(plan) || !safeAbsolutePath(rootFSCopyPath) || !validBootInput(boot) || boot.VMID != plan.VMID() {
		return LaunchRequest{}, fmt.Errorf("%w: compiled plan, private rootfs copy, and plan-bound boot input are required", ErrSmokeUnavailable)
	}
	return LaunchRequest{
		JailerPath:        plan.Jailer().Path,
		JailerArguments:   plan.JailerArguments(),
		RootFSCopyPath:    rootFSCopyPath,
		CgroupVersion:     2,
		NetworkInterfaces: 0,
		SerialMarker:      boot.serialMarker(),
		Boot:              boot,
		KernelArguments:   boot.KernelArguments(),
	}, nil
}

// CleanupProof records only non-sensitive cleanup observations.
type CleanupProof struct {
	Proved  bool     `json:"proved"`
	Removed []string `json:"removed,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// SmokeHost is the protected-runner boundary; implementations must perform actual host operations.
type SmokeHost interface {
	Preflight(context.Context, Plan, FixtureSet) error
	Prepare(context.Context, Plan, FixtureSet) (LaunchRequest, error)
	Launch(context.Context, LaunchRequest) error
	AwaitSerial(context.Context, string) error
	Control(context.Context) error
	Cleanup(context.Context) (CleanupProof, error)
}

// EvidenceResult classifies an observed protected-run outcome.
type EvidenceResult string

const (
	// EvidencePassed means the exact Linux/KVM smoke protocol completed.
	EvidencePassed EvidenceResult = "passed"
	// EvidenceBlocked means an unavailable prerequisite prevented a run.
	EvidenceBlocked EvidenceResult = "blocked"
	// ProofLevelLinuxKVME2E identifies only a real protected KVM run.
	ProofLevelLinuxKVME2E = "linux_kvm_e2e"
)

// SmokeEvidence is a bounded, redacted record suitable for workflow retention.
type SmokeEvidence struct {
	SchemaVersion string         `json:"schema_version"`
	ProofLevel    string         `json:"proof_level"`
	Result        EvidenceResult `json:"result"`
	SerialMarker  string         `json:"serial_marker"`
	Cleanup       CleanupProof   `json:"cleanup"`
}

// SmokeHarness orders verification, launch, guest observation, control, and cleanup under one bounded timeout.
type SmokeHarness struct {
	Host    SmokeHost
	Timeout time.Duration
}

const maximumCleanupTimeout = 30 * time.Second

// KVMPreflight captures the non-secret, necessary host observations before a protected run.
type KVMPreflight struct {
	GOOS               string `json:"goos"`
	GOARCH             string `json:"goarch"`
	KVMCharacterDevice bool   `json:"kvm_character_device"`
	KVMReadWrite       bool   `json:"kvm_read_write"`
	CgroupV2           bool   `json:"cgroup_v2"`
}

// Validate rejects every environment other than an actual Linux x86_64 KVM and cgroups-v2 host.
func (preflight KVMPreflight) Validate() error {
	if preflight.GOOS != "linux" || preflight.GOARCH != "amd64" || !preflight.KVMCharacterDevice || !preflight.KVMReadWrite || !preflight.CgroupV2 {
		return fmt.Errorf("%w: require linux/amd64, read-write character /dev/kvm, and cgroups v2", ErrSmokeUnavailable)
	}
	return nil
}

// InspectLocalKVMPreflight performs only environment inspection; it does not launch a VMM.
func InspectLocalKVMPreflight() KVMPreflight {
	preflight := KVMPreflight{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	info, err := os.Stat("/dev/kvm")
	preflight.KVMCharacterDevice = err == nil && info.Mode()&os.ModeCharDevice != 0
	if preflight.KVMCharacterDevice {
		file, openErr := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		preflight.KVMReadWrite = openErr == nil
		if file != nil {
			_ = file.Close()
		}
	}
	_, err = os.Stat("/sys/fs/cgroup/cgroup.controllers")
	preflight.CgroupV2 = err == nil
	return preflight
}

// Run executes a protected smoke run. It never invokes Launch until the compiled plan and fixture set are complete.
func (harness SmokeHarness) Run(ctx context.Context, plan Plan, fixtures FixtureSet) (evidence SmokeEvidence, err error) {
	if harness.Host == nil || harness.Timeout <= 0 || !validCompiledPlan(plan) || !fixturesMatchPlan(fixtures, plan) {
		return SmokeEvidence{}, fmt.Errorf("%w: complete host, timeout, plan, and verified fixtures are required", ErrSmokeUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, harness.Timeout)
	defer cancel()
	cleanupTimeout := harness.Timeout
	if cleanupTimeout > maximumCleanupTimeout {
		cleanupTimeout = maximumCleanupTimeout
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cleanupCancel()
		proof, cleanupErr := harness.Host.Cleanup(cleanupCtx)
		evidence.Cleanup = proof
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("cleanup protected Firecracker resources: %w", cleanupErr))
		}
		if !proof.Proved {
			if proof.Reason == "" {
				proof.Reason = "cleanup proof is absent"
				evidence.Cleanup = proof
			}
			err = errors.Join(err, fmt.Errorf("cleanup protected Firecracker resources: cleanup proof is absent"))
		}
		if err != nil {
			evidence.Result = EvidenceBlocked
		}
	}()
	if err := harness.Host.Preflight(ctx, plan, fixtures); err != nil {
		return SmokeEvidence{}, fmt.Errorf("%w: preflight: %v", ErrSmokeUnavailable, err)
	}
	request, err := harness.Host.Prepare(ctx, plan, fixtures)
	if err != nil {
		return SmokeEvidence{}, fmt.Errorf("prepare jailed rootfs: %w", err)
	}
	if !safeAbsolutePath(request.JailerPath) || len(request.JailerArguments) == 0 || request.CgroupVersion != 2 || request.NetworkInterfaces != 0 || request.RootFSCopyPath == "" || !validBootInput(request.Boot) || request.Boot.VMID != plan.VMID() || request.Boot.FixtureVersion != fixtures.FixtureVersion() || request.SerialMarker != request.Boot.serialMarker() || !sameStrings(request.KernelArguments, request.Boot.KernelArguments()) {
		return SmokeEvidence{}, fmt.Errorf("%w: incomplete no-NIC jailed request", ErrSmokeUnavailable)
	}
	if err := harness.Host.Launch(ctx, request); err != nil {
		return SmokeEvidence{}, fmt.Errorf("launch jailer: %w", err)
	}
	if err := harness.Host.AwaitSerial(ctx, request.SerialMarker); err != nil {
		return SmokeEvidence{}, fmt.Errorf("await guest serial marker: %w", err)
	}
	if err := harness.Host.Control(ctx); err != nil {
		return SmokeEvidence{}, fmt.Errorf("guest control channel: %w", err)
	}
	return SmokeEvidence{SchemaVersion: "firecracker.smoke-evidence/v1", ProofLevel: ProofLevelLinuxKVME2E, Result: EvidencePassed, SerialMarker: request.SerialMarker}, nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func fixturesMatchPlan(set FixtureSet, plan Plan) bool {
	for name, want := range planArtifacts(plan) {
		got, ok := set.artifacts[name]
		if !ok || !validArtifact(got) || got != want {
			return false
		}
	}
	return set.verified && validFixtureVersion(set.fixtureVersion) && len(set.artifacts) == 5 && safeAbsolutePath(set.directory)
}

func planArtifacts(plan Plan) map[FixtureName]PinnedArtifact {
	return map[FixtureName]PinnedArtifact{FixtureFirecracker: plan.Firecracker(), FixtureJailer: plan.Jailer(), FixtureKernel: plan.Kernel(), FixtureRootFS: plan.RootFS(), FixtureGuestAgent: plan.GuestAgent()}
}

func digest(content []byte) sandbox.Digest {
	return sandbox.Digest(fmt.Sprintf("sha256:%x", sha256.Sum256(content)))
}
