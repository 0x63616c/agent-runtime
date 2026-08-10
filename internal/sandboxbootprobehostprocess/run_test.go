package sandboxbootprobehostprocess

import (
	"context"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobejournal"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/sandbox"
	"path/filepath"
	"testing"
	"time"
)

type controlFunc func(context.Context, firecrackerbootprobev2.Snapshot) (firecrackerbootprobev2.Snapshot, error)

func (f controlFunc) LaunchStarted(c context.Context, s firecrackerbootprobev2.Snapshot) (firecrackerbootprobev2.Snapshot, error) {
	return f(c, s)
}
func TestStageAndRecoverUsesOneJournaledIntent(t *testing.T) {
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	b := firecrackerbootprobev2.Binding{HostID: "host", HostGeneration: 1, AssignmentID: "assignment", Tenant: "tenant", Principal: "tenant:p", SandboxID: "sandbox", OperationID: "operation", OperationKind: "firecracker-boot-probe", EffectiveSpecDigest: d('a'), CapabilityDigest: d('b'), CanonicalRequestDigest: d('c')}
	state, _ := firecrackerbootprobev2.NewState(b, "instance", firecrackerbootprobev2.Delivery{EnvelopeID: "envelope", DeliveryID: "delivery", Nonce: "MDEyMzQ1Njc4OWFiY2RlZg", IssuedAt: now, ExpiresAt: now.Add(time.Minute), LeaseEpoch: 1, FencingToken: 1}, now)
	session, _ := firecrackerbootprobev2.NewSession(state)
	session, _ = session.AuthorizeLaunch(now)
	wire, _ := firecrackerbootprobev2.EncodeSession(session)
	snap := firecrackerbootprobev2.Snapshot{Version: 2, Session: session, Wire: wire}
	journal, _ := firecrackerbootprobejournal.Open(filepath.Join(t.TempDir(), "journal"))
	defer journal.Close()
	calls := 0
	control := controlFunc(func(_ context.Context, s firecrackerbootprobev2.Snapshot) (firecrackerbootprobev2.Snapshot, error) {
		calls++
		return s, nil
	})
	if _, err := StageAndRecordLaunchStarted(context.Background(), journal, control, snap); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverLaunchStarted(context.Background(), journal, control, snap); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}
func d(n rune) sandbox.Digest {
	r := make([]rune, 64)
	for i := range r {
		r[i] = n
	}
	return sandbox.Digest("sha256:" + string(r))
}
