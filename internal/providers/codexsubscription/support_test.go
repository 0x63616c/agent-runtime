package codexsubscription_test

import (
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/providers/codexsubscription"
)

func TestEvaluateFailsClosedForCurrentOfficialAppServerMaturity(t *testing.T) {
	disposition, err := codexsubscription.Evaluate(codexsubscription.Assessment{
		Surface:                    codexsubscription.SurfaceAppServer,
		CodexVersion:               "codex-cli 0.146.1",
		ProductionSupported:        false,
		ModelOnlyToolBoundary:      true,
		IsolatedCredentialIdentity: true,
		ProtectedCanaryAuthorized:  true,
	})
	if err != nil {
		t.Fatalf("evaluate current official review: %v", err)
	}
	if disposition.Eligible || !strings.Contains(disposition.Reason, "not approved for production") {
		t.Fatalf("disposition = %#v, want visible unsupported production block", disposition)
	}
}

func TestEvaluateRequiresEveryProductionBoundaryInOrder(t *testing.T) {
	base := codexsubscription.Assessment{Surface: codexsubscription.SurfaceAppServer, CodexVersion: "codex-cli 0.146.1", ProductionSupported: true}
	for _, test := range []struct {
		name   string
		input  codexsubscription.Assessment
		reason string
	}{
		{name: "tool boundary", input: base, reason: "tool boundary"},
		{name: "identity", input: func() codexsubscription.Assessment { value := base; value.ModelOnlyToolBoundary = true; return value }(), reason: "identity isolation"},
		{name: "canary", input: func() codexsubscription.Assessment {
			value := base
			value.ModelOnlyToolBoundary = true
			value.IsolatedCredentialIdentity = true
			return value
		}(), reason: "canary authority"},
	} {
		t.Run(test.name, func(t *testing.T) {
			disposition, err := codexsubscription.Evaluate(test.input)
			if err != nil || disposition.Eligible || !strings.Contains(disposition.Reason, test.reason) {
				t.Fatalf("evaluate = %#v, %v; want %q block", disposition, err, test.reason)
			}
		})
	}
}

func TestRequireProductionSupportDoesNotDiscloseUnrelatedCredentialLikeInput(t *testing.T) {
	err := codexsubscription.RequireProductionSupport(codexsubscription.Assessment{Surface: codexsubscription.SurfaceAppServer, CodexVersion: "token-looking-but-only-version", ProductionSupported: false})
	if err == nil || strings.Contains(err.Error(), "token-looking") || !strings.Contains(err.Error(), "compose Codex subscription model adapter") {
		t.Fatalf("composition error = %v", err)
	}
}

func TestEvaluateRejectsUnknownOrUnpinnedSurfaces(t *testing.T) {
	for _, assessment := range []codexsubscription.Assessment{
		{CodexVersion: "codex-cli 0.146.1"},
		{Surface: codexsubscription.SurfaceAppServer},
	} {
		if _, err := codexsubscription.Evaluate(assessment); err == nil {
			t.Fatalf("assessment %#v was accepted", assessment)
		}
	}
}
