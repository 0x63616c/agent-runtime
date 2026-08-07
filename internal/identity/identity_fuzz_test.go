package identity_test

import (
	"encoding/json"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/identity"
	"github.com/onsi/gomega"
)

func FuzzSessionIDCanonicalBoundary(f *testing.F) {
	for _, seed := range []string{"sess_a1b2c3d4e5f6g7h8", "", "sess_abcdefghijklmnop", "sess_abcdefghijklmnoé", "session_a1b2c3d4e5f6g7h8"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		g := gomega.NewWithT(t)
		id, err := identity.ParseSessionID(input)
		if err != nil {
			g.Expect(err.Error()).To(gomega.Equal("parse session ID: invalid value"))
			return
		}
		g.Expect(id.String()).To(gomega.Equal(input))
		g.Expect(input).To(gomega.HaveLen(21))
		encoded, marshalErr := json.Marshal(id)
		g.Expect(marshalErr).NotTo(gomega.HaveOccurred())
		var decoded identity.SessionID
		g.Expect(json.Unmarshal(encoded, &decoded)).To(gomega.Succeed())
		g.Expect(decoded).To(gomega.Equal(id))
		g.Expect(id.Redacted()).NotTo(gomega.Equal(id.String()))
	})
}
