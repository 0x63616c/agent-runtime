package firecrackerbootprobejournal

import (
	"errors"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/sandbox"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalRecoversIntentAndRefusesConcurrentHost(t *testing.T) {
	if os.Getenv("BOOT_PROBE_JOURNAL_CHILD") == "1" {
		_, err := Open(os.Getenv("BOOT_PROBE_JOURNAL_PATH"))
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("child Open() = %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "instance.json")
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := Open(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("Open(second)=%v", err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestJournalRecoversIntentAndRefusesConcurrentHost$")
	child.Env = append(os.Environ(), "BOOT_PROBE_JOURNAL_CHILD=1", "BOOT_PROBE_JOURNAL_PATH="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("second host process = %v: %s", err, output)
	}
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	b := firecrackerbootprobev2.Binding{HostID: "host", HostGeneration: 1, AssignmentID: "assignment", Tenant: "tenant", Principal: "tenant:principal", SandboxID: "sandbox", OperationID: "operation", OperationKind: "firecracker-boot-probe", EffectiveSpecDigest: digest('a'), CapabilityDigest: digest('b'), CanonicalRequestDigest: digest('c')}
	d := firecrackerbootprobev2.Delivery{EnvelopeID: "envelope", DeliveryID: "delivery", Nonce: "MDEyMzQ1Njc4OWFiY2RlZg", IssuedAt: now, ExpiresAt: now.Add(time.Minute), LeaseEpoch: 1, FencingToken: 1}
	s, _ := firecrackerbootprobev2.NewState(b, "instance", d, now)
	session, _ := firecrackerbootprobev2.NewSession(s)
	session, _ = session.AuthorizeLaunch(now)
	if err := j.StageLaunchIntent(session); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	got, ok := recovered.LaunchIntent()
	wantWire, wantErr := firecrackerbootprobev2.EncodeSession(session)
	gotWire, gotErr := firecrackerbootprobev2.EncodeSession(got)
	if !ok || wantErr != nil || gotErr != nil || string(gotWire) != string(wantWire) {
		t.Fatal("journal did not recover exact intent")
	}
}
func digest(n rune) sandbox.Digest {
	b := make([]rune, 64)
	for i := range b {
		b[i] = n
	}
	return sandbox.Digest("sha256:" + string(b))
}
