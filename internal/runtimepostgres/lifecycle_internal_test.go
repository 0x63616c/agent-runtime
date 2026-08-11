package runtimepostgres

import (
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

func TestStateReferencesDeduplicatesExactOpaqueMetadata(t *testing.T) {
	reference := runtimecontent.Reference{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MediaType: runtimecontent.ConversationEntryMediaTypeV1, SizeBytes: 1}
	references := stateReferences(runtimestate.RuntimeState{Conversations: []runtimestate.ConversationRecord{{Reference: reference}}, Artifacts: []runtimestate.ArtifactRecord{{Reference: reference}}})
	if len(references) != 1 || references[0] != reference {
		t.Fatalf("references = %#v", references)
	}
}
