package firecracker

import (
	"context"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestHostProcessExecutorCanOnlyReachTheFencedGuestDispatchGate(t *testing.T) {
	plan := mustCompile(t, validProfile())
	executor := HostProcessExecutor{Host: newLinuxJailerHost(plan, verifiedPlanFixtures(plan), &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})}
	err := executor.Execute(context.Background(), sandboxhostprotocol.Envelope{HostID: "host_01", AssignmentID: "assignment_01", FencingToken: 1, CapabilityDigest: string(plan.Capabilities().Digest)})
	if !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Execute() = %v, want certified profile refusal", err)
	}
}
