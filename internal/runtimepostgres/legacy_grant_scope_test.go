package runtimepostgres

import (
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

func TestUpgradeLegacyGrantScopesRejectsAmbiguousToolCallCorrelation(t *testing.T) {
	tenant, _ := runtimecontent.ParseTenantID("legacy-scope-tenant")
	principal, _ := runtimecontent.ParsePrincipalID("legacy-scope-owner")
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	state := runtimestate.RuntimeState{
		ToolIntents: []runtimestate.ToolIntentRecord{
			{Tenant: tenant, Principal: principal, SessionID: "sess_0000000000000001", TurnID: "turn_0000000000000001", ToolCallID: "tcall_1234567890ABCDEF"},
			{Tenant: tenant, Principal: principal, SessionID: "sess_0000000000000002", TurnID: "turn_0000000000000002", ToolCallID: "tcall_1234567890ABCDEF"},
		},
		Grants: []runtimestate.CapabilityGrantRecord{{Tenant: tenant, Principal: principal, GrantID: "grant_1234567890ABCDE", ToolCallID: "tcall_1234567890ABCDEF", MaximumUses: 1, ExpiresAt: now.Add(time.Hour)}},
	}
	if _, err := upgradeLegacyGrantScopes(state); err == nil {
		t.Fatal("ambiguous legacy grant correlation upgraded")
	}
}
