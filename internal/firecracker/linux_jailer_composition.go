package firecracker

import (
	"fmt"
	"path/filepath"
	"strings"
)

const fixedFirecrackerAPISocket = "/run/firecracker.socket"

// LinuxJailerHostConfig is the complete reviewed composition input for one Linux Jailer host.
// Constructing it neither starts a Jailer nor verifies Linux/KVM execution.
type LinuxJailerHostConfig struct {
	Plan              Plan
	PreflightState    KVMPreflight
	RootFSCopyPath    string
	Authority         JailerExecutionAuthority
	SecretContainment *SecretContainmentManifest
	UnixDialer        unixSocketDialer
}

// NewLinuxJailerHost composes the reviewed resource stager, Jailer starter,
// fixed private Unix REST port, and fixed private guest-vsock transport. The
// resulting host stays unavailable until profile-specific Linux/KVM evidence.
// It validates immutable authority before construction but leaves all host I/O to the explicit SmokeHost lifecycle.
func NewLinuxJailerHost(config LinuxJailerHostConfig) (*LinuxJailerHost, error) {
	if !validCompiledPlan(config.Plan) || !validJailerExecutionAuthority(config.Authority, config.Plan) || !safeAbsolutePath(config.RootFSCopyPath) {
		return nil, fmt.Errorf("%w: compiled plan, exact Jailer authority, and private rootfs copy are required", ErrSmokeUnavailable)
	}
	if config.SecretContainment != nil && !validSecretContainmentManifest(*config.SecretContainment, config.Plan, config.Authority) {
		return nil, fmt.Errorf("%w: exact unavailable secret-containment launch profile is required", ErrSmokeUnavailable)
	}
	if err := config.PreflightState.Validate(); err != nil {
		return nil, err
	}
	http, err := newUnixFirecrackerHTTP(hostJailedPath(expectedJailRoot(config.Plan), fixedFirecrackerAPISocket), config.UnixDialer)
	if err != nil {
		return nil, err
	}
	guest, err := NewUnixGuestControlChannel(config.UnixDialer)
	if err != nil {
		return nil, err
	}
	host := &LinuxJailerHost{
		PreflightState: config.PreflightState,
		RootFSCopyPath: config.RootFSCopyPath,
		Resources:      LinuxJailerResourceStager{},
		Authority:      cloneJailerExecutionAuthority(config.Authority),
		Jailer:         LinuxJailerStarter{},
		HTTP:           http,
		Guest:          guest,
		configured:     true,
		configuredPlan: cloneLinuxJailerPlan(config.Plan),
	}
	if config.SecretContainment != nil {
		host.secretContainment = cloneSecretContainmentManifest(*config.SecretContainment)
		host.hasSecretContainment = true
	}
	return host, nil
}

// hostJailedPath maps one exact chroot-visible absolute path to its host-visible path.
// The caller must already have bound the jail root and jailed path to the same verified stage.
func hostJailedPath(jailRoot, jailedPath string) string {
	if !jailDestinationContained(jailRoot, jailedPath) {
		return ""
	}
	return filepath.Join(jailRoot, strings.TrimPrefix(jailedPath, "/"))
}
