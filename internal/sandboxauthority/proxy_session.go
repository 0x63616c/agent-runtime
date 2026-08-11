package sandboxauthority

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ProxySessionRequest is the only guest-to-host proxy request shape. It binds
// one lease-fenced process to one admitted DNS destination; it has no address,
// URL, resolver, listener, or arbitrary-tunnel field.
type ProxySessionRequest struct {
	SandboxID    string
	ProcessID    string
	OperationID  string
	VMID         string
	FencingToken uint64
	Destination  EgressDestination
}

// ProxySession is one host-owned, single-connection proxy authorization. An
// AF_VSOCK transport may compose it only after its control envelope and guest
// identity have been verified; it never becomes a generic host tunnel.
type ProxySession struct {
	mu          sync.Mutex
	lease       EgressLease
	vmID        string
	fence       uint64
	used        bool
	closed      bool
	connections map[net.Conn]struct{}
}

// NewProxySession freezes one admitted finite lease to one exact guest VM and
// one current host-assignment fencing token.
func NewProxySession(lease EgressLease, vmID string, fencingToken uint64, now time.Time) (*ProxySession, error) {
	frozen, err := NewEgressLease(lease, now)
	if err != nil || vmID == "" || fencingToken == 0 {
		return nil, fmt.Errorf("open guest proxy session: %w", ErrDenied)
	}
	return &ProxySession{
		lease:       frozen,
		vmID:        vmID,
		fence:       fencingToken,
		connections: make(map[net.Conn]struct{}),
	}, nil
}

// Connect rechecks every immutable lease, VM, and fence field, resolves only
// at the host proxy boundary, and retains exactly one connection for reaping.
func (session *ProxySession) Connect(ctx context.Context, request ProxySessionRequest, now time.Time, resolver Resolver, dialer Dialer) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("connect guest proxy session: %w", ErrDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("connect guest proxy session: %w", ErrDenied)
	}

	session.mu.Lock()
	closed, used := session.closed, session.used
	lease, vmID, fence := session.lease, session.vmID, session.fence
	session.mu.Unlock()
	if closed || used || request.SandboxID != lease.SandboxID || request.ProcessID != lease.ProcessID || request.OperationID != lease.OperationID || request.VMID != vmID || request.FencingToken != fence {
		return nil, fmt.Errorf("connect guest proxy session: %w", ErrDenied)
	}

	connection, err := lease.Connect(ctx, request.Destination, now, resolver, dialer)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return nil, err
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		_ = connection.Close()
		return nil, fmt.Errorf("connect guest proxy session: %w", ErrExpired)
	}
	if session.used {
		_ = connection.Close()
		return nil, fmt.Errorf("connect guest proxy session: %w", ErrDenied)
	}
	session.used = true
	session.connections[connection] = struct{}{}
	return connection, nil
}

// Close revokes a session and closes its in-flight proxied connection before
// its guest or Jailer reaper runs. Closing an already closed session is safe.
func (session *ProxySession) Close(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("close guest proxy session: %w", ErrDenied)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if session == nil {
		return nil
	}

	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return nil
	}
	session.closed = true
	connections := make([]net.Conn, 0, len(session.connections))
	for connection := range session.connections {
		connections = append(connections, connection)
	}
	session.mu.Unlock()

	var result error
	for _, connection := range connections {
		if err := connection.Close(); err != nil && result == nil {
			result = err
		}
	}
	return result
}
