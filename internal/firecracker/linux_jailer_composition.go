package firecracker

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

const fixedFirecrackerAPISocket = "/run/firecracker.socket"

const guestControlVSockPort = 10777

// LinuxJailerHostConfig is the complete reviewed composition input for one Linux Jailer host.
// Constructing it neither starts a Jailer nor verifies Linux/KVM execution.
type LinuxJailerHostConfig struct {
	Plan              Plan
	PreflightState    KVMPreflight
	RootFSCopyPath    string
	Authority         JailerExecutionAuthority
	SecretContainment *SecretContainmentManifest
	NoRouteProxy      *NoRouteProxyTopologyManifest
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
	if config.NoRouteProxy != nil && !validNoRouteProxyTopologyManifest(*config.NoRouteProxy, config.Plan, config.Authority) {
		return nil, fmt.Errorf("%w: exact unavailable no-route proxy launch profile is required", ErrSmokeUnavailable)
	}
	if err := config.PreflightState.Validate(); err != nil {
		return nil, err
	}
	http, err := newUnixFirecrackerHTTP(hostJailedPath(expectedJailRoot(config.Plan), fixedFirecrackerAPISocket), config.UnixDialer)
	if err != nil {
		return nil, err
	}
	guest, err := NewUnixGuestControlChannel(firecrackerVSockDialer{dialer: config.UnixDialer})
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
	if config.NoRouteProxy != nil {
		host.noRouteProxy = *config.NoRouteProxy
		host.hasNoRouteProxy = true
	}
	return host, nil
}

// firecrackerVSockDialer performs Firecracker's mandatory host-to-guest vsock
// bridge handshake before handing the resulting stream to our guest protocol.
// The guest protocol itself starts only after this fixed port is selected.
type firecrackerVSockDialer struct{ dialer unixSocketDialer }

func (dialer firecrackerVSockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dialer.dialer == nil || network != "unix" {
		return nil, fmt.Errorf("Firecracker vsock dialer requires an exact Unix socket")
	}
	connection, err := dialer.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			return nil, err
		}
	}
	if _, err := fmt.Fprintf(connection, "CONNECT %d\n", guestControlVSockPort); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("request Firecracker guest vsock port: %w", err)
	}
	line, err := bufio.NewReaderSize(connection, 64).ReadString('\n')
	if err != nil || !validFirecrackerVSockAcknowledgement(line) {
		_ = connection.Close()
		return nil, fmt.Errorf("confirm Firecracker guest vsock port")
	}
	return connection, nil
}

func validFirecrackerVSockAcknowledgement(line string) bool {
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "OK" {
		return false
	}
	port, err := strconv.ParseUint(fields[1], 10, 32)
	return err == nil && port != 0
}

// hostJailedPath maps one exact chroot-visible absolute path to its host-visible path.
// The caller must already have bound the jail root and jailed path to the same verified stage.
func hostJailedPath(jailRoot, jailedPath string) string {
	if !jailDestinationContained(jailRoot, jailedPath) {
		return ""
	}
	return filepath.Join(jailRoot, strings.TrimPrefix(jailedPath, "/"))
}
