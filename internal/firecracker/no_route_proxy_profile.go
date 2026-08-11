package firecracker

import "fmt"

const linuxJailerNoRouteProxyVersion = "firecracker.jailer-no-route-proxy/v1"

// NoRouteProxyTopologyManifest is the fixed desired topology a future
// Firecracker egress profile must apply before it may consume a proxy lease.
// It is deliberately a configuration and refusal input, not evidence that a
// guest has no NIC, route, resolver, DoH path, or metadata path.
type NoRouteProxyTopologyManifest struct {
	Version                   string
	VMID                      string
	HostCgroupPath            string
	GuestCgroupPath           string
	GuestControlTransport     string
	GuestNICCount             uint8
	GuestRoutePolicy          string
	GuestResolverPolicy       string
	HostResolverRequired      bool
	DirectDNSDeniedRequired   bool
	DirectIPDeniedRequired    bool
	CgroupV2LifecycleRequired bool
}

// CompileNoRouteProxyTopologyManifest derives the one no-NIC/no-route desired
// topology from the exact compiled plan and Jailer authority. Callers cannot
// select a guest route, resolver, proxy listener, address, or tunnel. The
// result remains an unavailable-profile prerequisite until protected Linux/KVM
// evidence proves an initializer applied and enforced every field.
func CompileNoRouteProxyTopologyManifest(plan Plan, authority JailerExecutionAuthority) (NoRouteProxyTopologyManifest, error) {
	if !validCompiledPlan(plan) || !validJailerExecutionAuthority(authority, plan) || plan.Network().Mode != NetworkDenyAll || len(plan.Network().Allowlist) != 0 {
		return NoRouteProxyTopologyManifest{}, fmt.Errorf("compile Jailer no-route proxy manifest: %w", ErrCapabilityUnavailable)
	}
	manifest := NoRouteProxyTopologyManifest{
		Version:                   linuxJailerNoRouteProxyVersion,
		VMID:                      plan.VMID(),
		HostCgroupPath:            authority.CgroupPath(),
		GuestCgroupPath:           "/agent-runtime/proxy/" + plan.VMID(),
		GuestControlTransport:     "af-vsock",
		GuestNICCount:             0,
		GuestRoutePolicy:          "none",
		GuestResolverPolicy:       "disabled",
		HostResolverRequired:      true,
		DirectDNSDeniedRequired:   true,
		DirectIPDeniedRequired:    true,
		CgroupV2LifecycleRequired: true,
	}
	if !validNoRouteProxyTopologyManifest(manifest, plan, authority) {
		return NoRouteProxyTopologyManifest{}, fmt.Errorf("compile Jailer no-route proxy manifest: %w", ErrCapabilityUnavailable)
	}
	return manifest, nil
}

// NoRouteProxyConfigured reports whether the manifest is still exactly bound
// to the compiled plan and Jailer authority. It does not prove topology
// application, guest peer authentication, route denial, or egress capability.
func (manifest NoRouteProxyTopologyManifest) NoRouteProxyConfigured(plan Plan, authority JailerExecutionAuthority) bool {
	return validNoRouteProxyTopologyManifest(manifest, plan, authority)
}

func validNoRouteProxyTopologyManifest(manifest NoRouteProxyTopologyManifest, plan Plan, authority JailerExecutionAuthority) bool {
	network := plan.Network()
	return manifest.Version == linuxJailerNoRouteProxyVersion && validCompiledPlan(plan) && validJailerExecutionAuthority(authority, plan) && network.Mode == NetworkDenyAll && len(network.Allowlist) == 0 && manifest.VMID == plan.VMID() && manifest.HostCgroupPath == authority.CgroupPath() && manifest.GuestCgroupPath == "/agent-runtime/proxy/"+plan.VMID() && manifest.GuestControlTransport == "af-vsock" && manifest.GuestNICCount == 0 && manifest.GuestRoutePolicy == "none" && manifest.GuestResolverPolicy == "disabled" && manifest.HostResolverRequired && manifest.DirectDNSDeniedRequired && manifest.DirectIPDeniedRequired && manifest.CgroupV2LifecycleRequired
}
