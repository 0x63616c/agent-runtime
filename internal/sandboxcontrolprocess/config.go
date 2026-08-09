// Package sandboxcontrolprocess composes the separately runnable sandbox
// control role from one strict operator document and explicit secret sources.
package sandboxcontrolprocess

import (
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolapi"
	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
)

var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Config is a validated immutable sandbox-control process declaration.
type Config struct {
	listenAddress          string
	tlsCertificateFile     string
	tlsPrivateKeyFile      string
	databaseDSNEnvironment string
	authorizationEnv       string
	assertionKeyEnv        string
	identity               sandboxcontrolapi.Identity
	bindingLifetime        time.Duration
	retention              time.Duration
	waitInterval           time.Duration
	admission              sandbox.OperationAdmissionPolicy
	hostControl            *hostControlConfig
}

type document struct {
	Version                int                  `json:"version"`
	ListenAddress          string               `json:"listen_address"`
	TLSCertificateFile     string               `json:"tls_certificate_file"`
	TLSPrivateKeyFile      string               `json:"tls_private_key_file"`
	DatabaseDSNEnvironment string               `json:"database_dsn_environment"`
	AuthorizationEnv       string               `json:"authorization_environment"`
	AssertionKeyEnv        string               `json:"assertion_key_environment"`
	Identity               identityDocument     `json:"identity"`
	BindingLifetimeSeconds uint32               `json:"binding_lifetime_seconds"`
	RetentionSeconds       uint32               `json:"retention_seconds"`
	WaitIntervalMillis     uint32               `json:"wait_interval_millis"`
	Admission              admissionDocument    `json:"admission"`
	HostControl            *hostControlDocument `json:"host_control"`
}

type hostControlDocument struct {
	ListenAddress                string    `json:"listen_address"`
	TLSCertificateFile           string    `json:"tls_certificate_file"`
	TLSPrivateKeyFile            string    `json:"tls_private_key_file"`
	ClientCAFile                 string    `json:"client_ca_file"`
	ControlTrustVersion          uint64    `json:"control_trust_version"`
	ControlRevocationEpoch       uint64    `json:"control_revocation_epoch"`
	ControlKeyID                 string    `json:"control_key_id"`
	ControlKeyVersion            uint64    `json:"control_key_version"`
	ControlKeyNotBefore          time.Time `json:"control_key_not_before"`
	ControlKeyNotAfter           time.Time `json:"control_key_not_after"`
	ControlSigningKeyEnvironment string    `json:"control_signing_key_environment"`
	LeaseSeconds                 uint32    `json:"lease_seconds"`
}

type hostControlConfig struct {
	listenAddress                string
	tlsCertificateFile           string
	tlsPrivateKeyFile            string
	clientCAFile                 string
	trustVersion                 uint64
	revocationEpoch              uint64
	controlKeyID                 string
	keyVersion                   uint64
	keyNotBefore                 time.Time
	keyNotAfter                  time.Time
	controlSigningKeyEnvironment string
	lease                        time.Duration
}

type identityDocument struct {
	Authority string `json:"authority"`
	Tenant    string `json:"tenant"`
	Subject   string `json:"subject"`
	Principal string `json:"principal"`
}

func (identity identityDocument) apiIdentity() sandboxcontrolapi.Identity {
	return sandboxcontrolapi.Identity{
		Authority: identity.Authority, Tenant: identity.Tenant,
		Subject: identity.Subject, Principal: identity.Principal,
	}
}

type admissionDocument struct {
	Version               string                               `json:"version"`
	CanonicalizerVersion  string                               `json:"canonicalizer_version"`
	CapabilityVersion     string                               `json:"capability_version"`
	ImageAdmissionVersion string                               `json:"image_admission_version"`
	Defaults              resourceLimitsDocument               `json:"defaults"`
	Maximum               resourceLimitsDocument               `json:"maximum"`
	Capabilities          sandbox.CapabilitySnapshot           `json:"capabilities"`
	AdmittedImages        map[sandbox.Digest]sandbox.ImageInfo `json:"admitted_images"`
}

type resourceLimitsDocument struct {
	MilliCPU            uint32 `json:"milli_cpu"`
	MemoryBytes         uint64 `json:"memory_bytes"`
	RootDiskBytes       uint64 `json:"root_disk_bytes"`
	TmpfsBytes          uint64 `json:"tmpfs_bytes"`
	PIDs                uint32 `json:"pids"`
	ProcessCount        uint32 `json:"process_count"`
	OpenFiles           uint32 `json:"open_files"`
	Inodes              uint64 `json:"inodes"`
	Files               uint64 `json:"files"`
	LifetimeSeconds     uint32 `json:"lifetime_seconds"`
	ProducedOutputBytes uint64 `json:"produced_output_bytes"`
	RetainedOutputBytes uint64 `json:"retained_output_bytes"`
	TransferBytes       uint64 `json:"transfer_bytes"`
	NetworkConnections  uint32 `json:"network_connections"`
	VolumeBytes         uint64 `json:"volume_bytes"`
	SnapshotBytes       uint64 `json:"snapshot_bytes"`
}

func (limits resourceLimitsDocument) resourceLimits() sandbox.ResourceLimits {
	return sandbox.ResourceLimits{
		MilliCPU: limits.MilliCPU, MemoryBytes: limits.MemoryBytes, RootDiskBytes: limits.RootDiskBytes,
		TmpfsBytes: limits.TmpfsBytes, PIDs: limits.PIDs, ProcessCount: limits.ProcessCount,
		OpenFiles: limits.OpenFiles, Inodes: limits.Inodes, Files: limits.Files,
		Lifetime:            time.Duration(limits.LifetimeSeconds) * time.Second,
		ProducedOutputBytes: limits.ProducedOutputBytes, RetainedOutputBytes: limits.RetainedOutputBytes,
		TransferBytes: limits.TransferBytes, NetworkConnections: limits.NetworkConnections,
		VolumeBytes: limits.VolumeBytes, SnapshotBytes: limits.SnapshotBytes,
	}
}

// Parse decodes exactly one strict versioned process declaration.
func Parse(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse sandbox-control configuration: input is required")
	}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse sandbox-control configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("parse sandbox-control configuration: exactly one document is required")
	}
	if decoded.Version != 1 && decoded.Version != 2 {
		return Config{}, errors.New("validate sandbox-control configuration: version must be 1 or 2")
	}
	if decoded.Version == 1 && decoded.HostControl != nil {
		return Config{}, errors.New("validate sandbox-control configuration: version 1 host_control cannot bind versioned envelope trust; migrate to version 2")
	}
	host, port, err := net.SplitHostPort(decoded.ListenAddress)
	if err != nil || (host != "127.0.0.1" && host != "0.0.0.0" && host != "::1" && host != "::") || port == "" {
		return Config{}, errors.New("validate sandbox-control configuration: listen_address must be an explicit local bind address")
	}
	if !filepath.IsAbs(decoded.TLSCertificateFile) || !filepath.IsAbs(decoded.TLSPrivateKeyFile) || decoded.TLSCertificateFile == decoded.TLSPrivateKeyFile {
		return Config{}, errors.New("validate sandbox-control configuration: distinct absolute TLS mount paths are required")
	}
	for _, name := range []string{decoded.DatabaseDSNEnvironment, decoded.AuthorizationEnv, decoded.AssertionKeyEnv} {
		if !environmentName.MatchString(name) {
			return Config{}, errors.New("validate sandbox-control configuration: secret environment references are invalid")
		}
	}
	bindingLifetime := time.Duration(decoded.BindingLifetimeSeconds) * time.Second
	retention := time.Duration(decoded.RetentionSeconds) * time.Second
	waitInterval := time.Duration(decoded.WaitIntervalMillis) * time.Millisecond
	if bindingLifetime <= 0 || bindingLifetime > time.Hour || retention <= 0 || retention > 365*24*time.Hour || waitInterval <= 0 || waitInterval > time.Second {
		return Config{}, errors.New("validate sandbox-control configuration: lifetimes and wait interval must be finite")
	}
	hostControl, err := parseHostControl(decoded.HostControl, decoded.ListenAddress, decoded.TLSCertificateFile, decoded.TLSPrivateKeyFile)
	if err != nil {
		return Config{}, err
	}
	return Config{
		listenAddress: decoded.ListenAddress, tlsCertificateFile: decoded.TLSCertificateFile,
		tlsPrivateKeyFile: decoded.TLSPrivateKeyFile, databaseDSNEnvironment: decoded.DatabaseDSNEnvironment,
		authorizationEnv: decoded.AuthorizationEnv, assertionKeyEnv: decoded.AssertionKeyEnv,
		identity: decoded.Identity.apiIdentity(), bindingLifetime: bindingLifetime, retention: retention, waitInterval: waitInterval,
		admission:   sandbox.OperationAdmissionPolicy{Version: decoded.Admission.Version, CanonicalizerVersion: decoded.Admission.CanonicalizerVersion, CapabilityVersion: decoded.Admission.CapabilityVersion, ImageAdmissionVersion: decoded.Admission.ImageAdmissionVersion, Defaults: decoded.Admission.Defaults.resourceLimits(), Maximum: decoded.Admission.Maximum.resourceLimits(), Capabilities: decoded.Admission.Capabilities, AdmittedImages: decoded.Admission.AdmittedImages},
		hostControl: hostControl,
	}, nil
}

func parseHostControl(decoded *hostControlDocument, publicAddress, publicCertificate, publicKey string) (*hostControlConfig, error) {
	if decoded == nil {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(decoded.ListenAddress)
	if err != nil || (host != "127.0.0.1" && host != "0.0.0.0" && host != "::1" && host != "::") || port == "" || decoded.ListenAddress == publicAddress {
		return nil, errors.New("validate sandbox-control configuration: host_control requires a distinct explicit bind address")
	}
	for _, path := range []string{decoded.TLSCertificateFile, decoded.TLSPrivateKeyFile, decoded.ClientCAFile} {
		if !filepath.IsAbs(path) {
			return nil, errors.New("validate sandbox-control configuration: host_control requires absolute TLS paths")
		}
	}
	if decoded.TLSCertificateFile == decoded.TLSPrivateKeyFile || decoded.TLSCertificateFile == publicCertificate || decoded.TLSPrivateKeyFile == publicKey || !environmentName.MatchString(decoded.ControlSigningKeyEnvironment) || decoded.ControlKeyID == "" || len(decoded.ControlKeyID) > 128 || decoded.ControlTrustVersion == 0 || decoded.ControlRevocationEpoch == 0 || decoded.ControlKeyVersion == 0 || decoded.ControlKeyNotBefore.Location() != time.UTC || decoded.ControlKeyNotAfter.Location() != time.UTC || !decoded.ControlKeyNotAfter.After(decoded.ControlKeyNotBefore) {
		return nil, errors.New("validate sandbox-control configuration: host_control identity and signing authority are invalid")
	}
	lease := time.Duration(decoded.LeaseSeconds) * time.Second
	if lease <= 0 || lease > time.Hour {
		return nil, errors.New("validate sandbox-control configuration: host_control lease must be finite")
	}
	return &hostControlConfig{listenAddress: decoded.ListenAddress, tlsCertificateFile: decoded.TLSCertificateFile, tlsPrivateKeyFile: decoded.TLSPrivateKeyFile, clientCAFile: decoded.ClientCAFile, trustVersion: decoded.ControlTrustVersion, revocationEpoch: decoded.ControlRevocationEpoch, controlKeyID: decoded.ControlKeyID, keyVersion: decoded.ControlKeyVersion, keyNotBefore: decoded.ControlKeyNotBefore, keyNotAfter: decoded.ControlKeyNotAfter, controlSigningKeyEnvironment: decoded.ControlSigningKeyEnvironment, lease: lease}, nil
}
