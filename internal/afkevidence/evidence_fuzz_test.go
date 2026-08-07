package afkevidence_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/afkevidence"
	"github.com/onsi/gomega"
)

func FuzzAFKEvidenceCanonicalBoundary(f *testing.F) {
	f.Add([]byte(`{"version":1,"records":[{"event":"local_check","requirement_ids":["MON-004"],"seams":["S12"],"documentation":["AGENTS.md"],"revision":"working-tree","source_ref":"local","utc_time":"2026-08-07T03:30:00Z","proof_level":"unit","command_id":"just-check","artifact_ref":"m0-local-check","result":"passed","limitations":["immutable-main-ci-pending"]}]}`))
	f.Add([]byte(`{"version":1,"records":[]}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		g := gomega.NewWithT(t)
		log, err := afkevidence.Parse(bytes.NewReader(input))
		if err != nil {
			return
		}
		encoded, marshalErr := json.Marshal(log)
		g.Expect(marshalErr).NotTo(gomega.HaveOccurred())
		_, parseErr := afkevidence.Parse(bytes.NewReader(encoded))
		g.Expect(parseErr).NotTo(gomega.HaveOccurred())
	})
}
