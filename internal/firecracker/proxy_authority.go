package firecracker

import (
	"fmt"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

// ProxyExecutionAuthority binds one already-admitted egress lease to the
// authenticated host command that may consume it. It owns neither a listener
// nor a guest-selected resolver, address, or general tunnel.
type ProxyExecutionAuthority struct {
	lease    sandboxauthority.EgressLease
	clock    clock.Clock
	resolver sandboxauthority.Resolver
	dialer   sandboxauthority.Dialer
}

// NewProxyExecutionAuthority freezes one finite lease with the host-owned
// resolver and dialer used only after exact envelope and guest-frame checks.
func NewProxyExecutionAuthority(lease sandboxauthority.EgressLease, source clock.Clock, resolver sandboxauthority.Resolver, dialer sandboxauthority.Dialer) (*ProxyExecutionAuthority, error) {
	if source == nil || resolver == nil || dialer == nil {
		return nil, fmt.Errorf("create guest proxy authority: clock, resolver, and dialer are required")
	}
	frozen, err := sandboxauthority.NewEgressLease(lease, source.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("create guest proxy authority: %w", err)
	}
	return &ProxyExecutionAuthority{lease: frozen, clock: source, resolver: resolver, dialer: dialer}, nil
}

// Begin opens one lease-fenced proxy session only when the signed host envelope
// and its bounded proxy body name exactly the authority's command context.
func (authority *ProxyExecutionAuthority) Begin(envelope sandboxhostprotocol.Envelope) (*sandboxauthority.ProxySession, error) {
	if authority == nil {
		return nil, fmt.Errorf("begin guest proxy authority: %w", ErrCapabilityUnavailable)
	}
	payload, err := DecodeGuestProxyPayload(envelope.Payload)
	if err != nil || envelope.OperationKind != GuestProxyOperationKind || envelope.Principal != authority.lease.Principal || envelope.SandboxID != authority.lease.SandboxID || envelope.ProcessID != authority.lease.ProcessID || envelope.OperationID != authority.lease.OperationID || !envelope.ExpiresAt.Equal(authority.lease.ExpiresAt) || payload.Request.SandboxID != envelope.SandboxID || payload.Request.ProcessID != envelope.ProcessID || payload.Request.OperationID != envelope.OperationID || payload.Request.VMID != envelope.SandboxID || payload.Request.FencingToken != envelope.FencingToken {
		return nil, fmt.Errorf("begin guest proxy authority: %w", ErrCapabilityUnavailable)
	}
	session, err := sandboxauthority.NewProxySession(authority.lease, envelope.SandboxID, envelope.FencingToken, authority.clock.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("begin guest proxy authority: %w", err)
	}
	return session, nil
}

func (authority *ProxyExecutionAuthority) resolve() sandboxauthority.Resolver {
	if authority == nil {
		return nil
	}
	return authority.resolver
}

func (authority *ProxyExecutionAuthority) dial() sandboxauthority.Dialer {
	if authority == nil {
		return nil
	}
	return authority.dialer
}

func (authority *ProxyExecutionAuthority) now() time.Time {
	if authority == nil || authority.clock == nil {
		return time.Time{}
	}
	return authority.clock.Now().UTC()
}
