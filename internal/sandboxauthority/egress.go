package sandboxauthority

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/egressproxy"
)

// EgressRule is one frozen, normalized destination restriction for a command.
type EgressRule struct {
	Domain, Protocol string
	Ports            []PortRange
}

// PortRange is an inclusive, finite transport-port range.
type PortRange struct{ First, Last uint16 }

// EgressLease binds a command's frozen destination authority to a finite lifetime.
type EgressLease struct {
	Principal, SandboxID, ProcessID, OperationID string
	Rules                                        []EgressRule
	ExpiresAt                                    time.Time
}

// EgressDestination is the one checked connection destination selected from a frozen lease.
type EgressDestination struct {
	Domain, Protocol string
	Port             uint16
}

// Resolver is the proxy-owned resolver used immediately before a connection.
type Resolver interface {
	Resolve(context.Context, string) ([]net.IPAddr, error)
}

// Dialer opens a connection only after EgressLease has chosen a public resolved address.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// NewEgressLease freezes validated command egress authority. It does not create a guest route.
func NewEgressLease(lease EgressLease, now time.Time) (EgressLease, error) {
	if lease.Principal == "" || lease.SandboxID == "" || lease.ProcessID == "" || lease.OperationID == "" || !lease.ExpiresAt.After(now) || lease.ExpiresAt.Sub(now) > time.Hour || len(lease.Rules) == 0 || len(lease.Rules) > 64 {
		return EgressLease{}, fmt.Errorf("freeze command egress lease: %w", ErrDenied)
	}
	seen := map[string]struct{}{}
	for index := range lease.Rules {
		rule := &lease.Rules[index]
		rule.Domain = strings.ToLower(rule.Domain)
		rule.Protocol = strings.ToLower(rule.Protocol)
		if !validEgressRule(*rule) {
			return EgressLease{}, fmt.Errorf("freeze command egress lease: %w", ErrDenied)
		}
		key := rule.Protocol + "\x00" + rule.Domain + "\x00" + fmt.Sprint(rule.Ports)
		if _, found := seen[key]; found {
			return EgressLease{}, fmt.Errorf("freeze command egress lease: %w", ErrDenied)
		}
		seen[key] = struct{}{}
		rule.Ports = append([]PortRange(nil), rule.Ports...)
	}
	lease.ExpiresAt = lease.ExpiresAt.UTC()
	return lease, nil
}

// Authorize fails closed unless an exact or one-label wildcard rule permits the destination.
func (lease EgressLease) Authorize(destination EgressDestination, now time.Time) error {
	if !lease.ExpiresAt.After(now) {
		return ErrExpired
	}
	destination.Domain, destination.Protocol = strings.ToLower(destination.Domain), strings.ToLower(destination.Protocol)
	if !validEgressDomain(destination.Domain) || (destination.Protocol != "tcp" && destination.Protocol != "udp") || destination.Port == 0 {
		return ErrDenied
	}
	for _, rule := range lease.Rules {
		if rule.Protocol == destination.Protocol && matchesDomain(rule.Domain, destination.Domain) && containsPort(rule.Ports, destination.Port) {
			return nil
		}
	}
	return ErrDenied
}

// Connect resolves and dials one authorized destination. This is the mandatory
// proxy-side boundary; it never accepts a literal IP or a guest-provided address.
func (lease EgressLease) Connect(ctx context.Context, destination EgressDestination, now time.Time, resolver Resolver, dialer Dialer) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if resolver == nil || dialer == nil {
		return nil, fmt.Errorf("connect sandbox egress: %w", ErrDenied)
	}
	if err := lease.Authorize(destination, now); err != nil {
		return nil, err
	}
	addresses, err := resolver.Resolve(ctx, destination.Domain)
	if err != nil {
		return nil, fmt.Errorf("connect sandbox egress: resolver unavailable")
	}
	for _, address := range addresses {
		if !egressproxy.IsPublicAddress(address.IP) {
			continue
		}
		connection, dialErr := dialer.DialContext(ctx, destination.Protocol, net.JoinHostPort(address.IP.String(), fmt.Sprint(destination.Port)))
		if dialErr == nil {
			return connection, nil
		}
	}
	return nil, fmt.Errorf("connect sandbox egress: no reachable public destination")
}

func validEgressRule(rule EgressRule) bool {
	if !validEgressDomain(rule.Domain) || (rule.Protocol != "tcp" && rule.Protocol != "udp") || len(rule.Ports) == 0 || len(rule.Ports) > 16 {
		return false
	}
	var last uint16
	for _, ports := range rule.Ports {
		if ports.First == 0 || ports.Last < ports.First || (last != 0 && ports.First <= last+1) {
			return false
		}
		last = ports.Last
	}
	return true
}
func validEgressDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.HasSuffix(domain, ".") || strings.ContainsAny(domain, "/:@[]") || net.ParseIP(strings.TrimPrefix(domain, "*.")) != nil {
		return false
	}
	candidate := strings.TrimPrefix(domain, "*.")
	if candidate == domain && strings.Contains(candidate, "*") {
		return false
	}
	if !strings.Contains(candidate, ".") {
		return false
	}
	numeric := true
	for _, label := range strings.Split(candidate, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
			if c < '0' || c > '9' {
				numeric = false
			}
		}
	}
	return !numeric
}
func matchesDomain(rule, domain string) bool {
	if rule == domain {
		return true
	}
	if !strings.HasPrefix(rule, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(rule, "*.")
	return strings.HasSuffix(domain, "."+suffix) && strings.Count(strings.TrimSuffix(domain, "."+suffix), ".") == 0
}
func containsPort(ports []PortRange, value uint16) bool {
	for _, item := range ports {
		if item.First <= value && value <= item.Last {
			return true
		}
	}
	return false
}
