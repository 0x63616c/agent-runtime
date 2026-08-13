package tooldispatch_test

import (
	"context"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/tooldispatch"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestNewProcessFailsClosedBeforeOpeningPrivateAuthorities(t *testing.T) {
	process, err := tooldispatch.NewProcess(context.Background(), "trigger-secret", tooldispatch.ProcessConfig{})
	if process != nil || err == nil || strings.Contains(err.Error(), "trigger-secret") {
		t.Fatalf("NewProcess incomplete = %#v, %v", process, err)
	}
}

func TestMountedTrustSourceNeverFallsBackOrLeaksPath(t *testing.T) {
	trust := tooldispatch.MountedTrustSource{Path: t.TempDir() + "/missing.pem", Reference: "trust/dispatch"}
	_, err := trust.ResolveTrustBundle(context.Background(), sandbox.TrustBundleRef("trust/other"))
	if err == nil || strings.Contains(err.Error(), trust.Path) {
		t.Fatalf("mismatched trust resolution = %v", err)
	}
}

func TestControlClientRequiresHTTPSAndFixedTLSIdentity(t *testing.T) {
	client, err := tooldispatch.NewControlClient(context.Background(), "http://control.invalid", "control.invalid", tooldispatch.MountedTrustSource{Path: "/unused", Reference: "trust/dispatch"}, "control-secret")
	if client != nil || err == nil || strings.Contains(err.Error(), "control-secret") {
		t.Fatalf("NewControlClient non-HTTPS = %#v, %v", client, err)
	}
}
