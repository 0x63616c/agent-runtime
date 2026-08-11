package firecracker

import (
	"errors"
	"reflect"
	"testing"
)

func TestCompileNoRouteProxyTopologyManifestBindsTheExactNoNICJailerBoundary(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority := mustCompileJailerExecutionAuthority(t, plan)
	manifest, err := CompileNoRouteProxyTopologyManifest(plan, authority)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.NoRouteProxyConfigured(plan, authority) || manifest.HostCgroupPath != authority.CgroupPath() || manifest.GuestCgroupPath != "/agent-runtime/proxy/"+plan.VMID() || manifest.GuestControlTransport != "af-vsock" || manifest.GuestNICCount != 0 || manifest.GuestRoutePolicy != "none" || manifest.GuestResolverPolicy != "disabled" || !manifest.HostResolverRequired || !manifest.DirectDNSDeniedRequired || !manifest.DirectIPDeniedRequired || !manifest.CgroupV2LifecycleRequired {
		t.Fatalf("manifest = %#v, want exact unavailable no-route proxy boundary", manifest)
	}
}

func TestNoRouteProxyTopologyManifestAndHostCompositionRefuseSubstitution(t *testing.T) {
	plan := mustCompile(t, validProfile())
	authority := mustCompileJailerExecutionAuthority(t, plan)
	manifest, err := CompileNoRouteProxyTopologyManifest(plan, authority)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*NoRouteProxyTopologyManifest){
		"guest NIC":        func(manifest *NoRouteProxyTopologyManifest) { manifest.GuestNICCount = 1 },
		"guest route":      func(manifest *NoRouteProxyTopologyManifest) { manifest.GuestRoutePolicy = "default" },
		"guest resolver":   func(manifest *NoRouteProxyTopologyManifest) { manifest.GuestResolverPolicy = "guest" },
		"direct DNS guard": func(manifest *NoRouteProxyTopologyManifest) { manifest.DirectDNSDeniedRequired = false },
		"host cgroup":      func(manifest *NoRouteProxyTopologyManifest) { manifest.HostCgroupPath = "other/sandbox-001" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := manifest
			mutate(&candidate)
			if candidate.NoRouteProxyConfigured(plan, authority) {
				t.Fatal("NoRouteProxyConfigured() accepted a substituted manifest")
			}
			if host, err := NewLinuxJailerHost(LinuxJailerHostConfig{Plan: plan, PreflightState: validKVMPreflight(), RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4", Authority: authority, NoRouteProxy: &candidate, UnixDialer: &recordingUnixDialer{}}); host != nil || !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("NewLinuxJailerHost() = (%#v, %v), want pre-I/O refusal", host, err)
			}
		})
	}

	host, err := NewLinuxJailerHost(LinuxJailerHostConfig{Plan: plan, PreflightState: validKVMPreflight(), RootFSCopyPath: "/run/agent-runtime/sandbox-001/rootfs.ext4", Authority: authority, NoRouteProxy: &manifest, UnixDialer: &recordingUnixDialer{}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := host.NoRouteProxyTopologyManifest()
	if !ok || !reflect.DeepEqual(got, manifest) {
		t.Fatalf("NoRouteProxyTopologyManifest() = (%#v, %t), want retained manifest", got, ok)
	}
	got.GuestRoutePolicy = "mutated"
	again, ok := host.NoRouteProxyTopologyManifest()
	if !ok || again.GuestRoutePolicy != "none" {
		t.Fatalf("host retained caller mutation = %#v", again)
	}
}
