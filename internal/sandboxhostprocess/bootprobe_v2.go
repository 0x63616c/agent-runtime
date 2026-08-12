package sandboxhostprocess

import (
	"context"
	"net/http"

	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/internal/sandboxbootprobehostprocess"
)

// RunBootProbeV2Once is the private M3 preparation flow. It never invokes the
// v1 pull/receipt protocol and deliberately stops at a durable prepared
// session. M4 owns the later compiled stage-ready, sealed command and journal
// handoff; this reference process must not synthesize a launch transition.
func RunBootProbeV2Once(ctx context.Context, client *http.Client, origin, principal, operationID, instanceID, journalPath string) (firecrackerbootprobev2.Snapshot, error) {
	_ = journalPath // Reserved for M4's later host-instance command journal.
	return sandboxbootprobehostprocess.Prepare(ctx, client, origin, principal, operationID, instanceID)
}
