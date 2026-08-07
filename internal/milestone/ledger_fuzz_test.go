package milestone_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/milestone"
	"github.com/onsi/gomega"
)

func FuzzEvidenceLedgerCanonicalBoundary(f *testing.F) {
	f.Add([]byte(`{"version":1,"requirements":[{"id":"ENG-001","status":"not_started"}]}`))
	f.Add([]byte(`{"version":1,"requirements":[{"id":"ENG-001","status":"completed"}]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) {
		g := gomega.NewWithT(t)
		ledger, err := milestone.ParseLedger(bytes.NewReader(input))
		if err != nil {
			return
		}
		encoded, marshalErr := json.Marshal(ledger)
		g.Expect(marshalErr).NotTo(gomega.HaveOccurred())
		reparsed, parseErr := milestone.ParseLedger(bytes.NewReader(encoded))
		g.Expect(parseErr).NotTo(gomega.HaveOccurred())
		g.Expect(reparsed).To(gomega.Equal(ledger))
	})
}

func FuzzRequirementCatalogCanonicalBoundary(f *testing.F) {
	valid, err := json.Marshal(catalog())
	if err != nil {
		f.Fatalf("encode catalog seed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte(`{"version":1,"requirements":[]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) {
		g := gomega.NewWithT(t)
		parsed, parseErr := milestone.ParseCatalog(bytes.NewReader(input))
		if parseErr != nil {
			return
		}
		encoded, marshalErr := json.Marshal(parsed)
		g.Expect(marshalErr).NotTo(gomega.HaveOccurred())
		reparsed, reparseErr := milestone.ParseCatalog(bytes.NewReader(encoded))
		g.Expect(reparseErr).NotTo(gomega.HaveOccurred())
		g.Expect(reparsed).To(gomega.Equal(parsed))
	})
}
