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

// ProxyAuthorityIssuer is the private host-control boundary for one
// per-command proxy lease. It owns a fixed no-route topology, Jailer authority,
// resolver, and dialer; it accepts no listener, host address, guest resolver,
// or arbitrary tunnel input.
type ProxyAuthorityIssuer struct {
	plan     Plan
	jailer   JailerExecutionAuthority
	topology NoRouteProxyTopologyManifest
	lease    sandboxauthority.EgressLease
	clock    clock.Clock
	resolver sandboxauthority.Resolver
	dialer   sandboxauthority.Dialer
}

// NewProxyAuthorityIssuer creates the exact host-control issuer for a finite
// lease only when it is bound to the compiled no-NIC/no-route Jailer topology.
// Construction does not apply topology or enable the egress capability.
func NewProxyAuthorityIssuer(plan Plan, jailer JailerExecutionAuthority, topology NoRouteProxyTopologyManifest, lease sandboxauthority.EgressLease, source clock.Clock, resolver sandboxauthority.Resolver, dialer sandboxauthority.Dialer) (*ProxyAuthorityIssuer, error) {
	if source == nil || resolver == nil || dialer == nil || !validNoRouteProxyTopologyManifest(topology, plan, jailer) {
		return nil, fmt.Errorf("create guest proxy issuer: %w", ErrCapabilityUnavailable)
	}
	frozen, err := sandboxauthority.NewEgressLease(lease, source.Now().UTC())
	if err != nil || frozen.SandboxID != topology.VMID {
		return nil, fmt.Errorf("create guest proxy issuer: %w", ErrCapabilityUnavailable)
	}
	return &ProxyAuthorityIssuer{plan: cloneLinuxJailerPlan(plan), jailer: cloneJailerExecutionAuthority(jailer), topology: topology, lease: frozen, clock: source, resolver: resolver, dialer: dialer}, nil
}

// BoundTo reports whether an issuer is still exactly bound to the host's
// compiled plan, Jailer authority, and unavailable no-route topology.
func (issuer *ProxyAuthorityIssuer) BoundTo(plan Plan, jailer JailerExecutionAuthority, topology NoRouteProxyTopologyManifest) bool {
	if issuer == nil || issuer.clock == nil || issuer.resolver == nil || issuer.dialer == nil || !validNoRouteProxyTopologyManifest(topology, plan, jailer) || !sameConfiguredLinuxJailerPlan(issuer.plan, plan) || !sameProxyIssuerJailerAuthority(issuer.jailer, jailer) || issuer.topology != topology {
		return false
	}
	_, err := sandboxauthority.NewEgressLease(issuer.lease, issuer.clock.Now().UTC())
	return err == nil && issuer.lease.SandboxID == topology.VMID
}

func sameProxyIssuerJailerAuthority(left, right JailerExecutionAuthority) bool {
	return left.version == right.version && left.stackResource == right.stackResource && left.cgroupParent == right.cgroupParent && left.cgroupPath == right.cgroupPath && sameStrings(left.arguments, right.arguments) && sameExternalJailerLimitOwners(left.external, right.external)
}

// Issue accepts only the canonical control-authenticated envelope already
// verified by host-process. It returns a per-command authority after exact
// plan/VM/fence/lease/DNS request binding; it does not open any proxy route.
func (issuer *ProxyAuthorityIssuer) Issue(envelope sandboxhostprotocol.Envelope, authenticatedEnvelope []byte) (*ProxyExecutionAuthority, error) {
	if issuer == nil || !issuer.BoundTo(issuer.plan, issuer.jailer, issuer.topology) || sandboxhostprotocol.ValidateAuthenticatedEnvelopeWire(authenticatedEnvelope, envelope) != nil || envelope.SandboxID != issuer.topology.VMID {
		return nil, fmt.Errorf("issue guest proxy authority: %w", ErrCapabilityUnavailable)
	}
	authority, err := NewProxyExecutionAuthority(issuer.lease, issuer.clock, issuer.resolver, issuer.dialer)
	if err != nil || !authority.accepts(envelope) {
		return nil, fmt.Errorf("issue guest proxy authority: %w", ErrCapabilityUnavailable)
	}
	return authority, nil
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
	if authority == nil || !authority.accepts(envelope) {
		return nil, fmt.Errorf("begin guest proxy authority: %w", ErrCapabilityUnavailable)
	}
	session, err := sandboxauthority.NewProxySession(authority.lease, envelope.SandboxID, envelope.FencingToken, authority.clock.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("begin guest proxy authority: %w", err)
	}
	return session, nil
}

func (authority *ProxyExecutionAuthority) accepts(envelope sandboxhostprotocol.Envelope) bool {
	if authority == nil {
		return false
	}
	payload, err := DecodeGuestProxyPayload(envelope.Payload)
	return err == nil && envelope.OperationKind == GuestProxyOperationKind && envelope.FencingToken != 0 && envelope.Principal == authority.lease.Principal && envelope.SandboxID == authority.lease.SandboxID && envelope.ProcessID == authority.lease.ProcessID && envelope.OperationID == authority.lease.OperationID && !envelope.ExpiresAt.IsZero() && envelope.ExpiresAt.Equal(authority.lease.ExpiresAt) && payload.Request.SandboxID == envelope.SandboxID && payload.Request.ProcessID == envelope.ProcessID && payload.Request.OperationID == envelope.OperationID && payload.Request.VMID == envelope.SandboxID && payload.Request.FencingToken == envelope.FencingToken && authority.lease.Authorize(payload.Request.Destination, authority.now()) == nil
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
