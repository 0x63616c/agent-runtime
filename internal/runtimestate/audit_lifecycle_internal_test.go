package runtimestate

import "testing"

func TestEveryClosedMutationVocabularyHasDurableAuditLifecyclePhases(t *testing.T) {
	commands := []CommandKind{
		CommandRegisterAgentRevision, CommandRegisterPolicyRevision, CommandCreateSession,
		CommandAdmitInput, CommandRegisterArtifact, CommandAppendConversation,
		CommandRecordToolIntent, CommandRequestApproval, CommandDecideApproval, CommandRevokeCapabilityGrant,
		CommandConsumeCapabilityGrant, CommandBeginToolExecution, CommandRecordToolOutcome,
		CommandBeginInvocation, CommandRecordOutcome, CommandSettleTurn, CommandCancelTurn,
		CommandCloseSession, CommandCancelSession, CommandFailSession, CommandClaimOutbox, CommandAcknowledgeOutbox,
	}
	for _, command := range commands {
		phases := auditLifecycleKinds(command)
		for _, required := range []string{".attempted", ".authorized", ".committed"} {
			found := false
			for _, phase := range phases {
				if phase == string(command)+required {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s phases = %q, missing %s", command, phases, required)
			}
		}
	}
	for _, command := range []CommandKind{CommandRecordToolOutcome, CommandRecordOutcome, CommandSettleTurn, CommandCancelTurn, CommandCloseSession, CommandCancelSession, CommandFailSession, CommandRevokeCapabilityGrant} {
		if !containsAuditLifecycleKind(auditLifecycleKinds(command), string(command)+".terminal") {
			t.Errorf("%s has no terminal phase", command)
		}
	}
	for _, command := range []CommandKind{CommandClaimOutbox, CommandAcknowledgeOutbox} {
		if !containsAuditLifecycleKind(auditLifecycleKinds(command), string(command)+".reconciled") {
			t.Errorf("%s has no reconciled phase", command)
		}
	}
}

func containsAuditLifecycleKind(kinds []string, expected string) bool {
	for _, kind := range kinds {
		if kind == expected {
			return true
		}
	}
	return false
}
