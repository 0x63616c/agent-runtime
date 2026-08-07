package identity_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/identity"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestIdentity(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Identity Suite")
}

type sequenceSource struct {
	values []string
	err    error
}

func (s *sequenceSource) Next() (string, error) {
	if s.err != nil {
		return "", s.err
	}
	value := s.values[0]
	s.values = s.values[1:]
	return value, nil
}

var _ = Describe("Session IDs", func() {
	It("creates, parses, serializes, and redacts an opaque typed ID", func() {
		generator, err := identity.NewGenerator(&sequenceSource{values: []string{"a1b2c3d4e5f6g7h8"}})
		Expect(err).NotTo(HaveOccurred())

		id, err := generator.NewSessionID()
		Expect(err).NotTo(HaveOccurred())
		Expect(id.String()).To(Equal("sess_a1b2c3d4e5f6g7h8"))
		Expect(id.Redacted()).To(Equal("sess_...g7h8"))

		parsed, err := identity.ParseSessionID(id.String())
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed).To(Equal(id))

		encoded, err := json.Marshal(id)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(Equal(`"sess_a1b2c3d4e5f6g7h8"`))

		var decoded identity.SessionID
		Expect(json.Unmarshal(encoded, &decoded)).To(Succeed())
		Expect(decoded).To(Equal(id))
	})

	It("refuses malformed IDs and wraps source failures without losing identity", func() {
		_, err := identity.ParseSessionID("session_a1b2c3d4e5f6g7h8")
		Expect(err).To(MatchError(ContainSubstring("parse session ID: invalid value")))
		_, err = identity.ParseSessionID("sess_a1b2c3d4e5f6g7é8")
		Expect(err).To(MatchError(ContainSubstring("parse session ID: invalid value")))
		sensitive := "sess_" + strings.Repeat("credential", 100)
		_, err = identity.ParseSessionID(sensitive)
		Expect(err).To(MatchError("parse session ID: invalid value"))
		Expect(err.Error()).NotTo(ContainSubstring("credential"))

		var zero identity.SessionID
		_, err = json.Marshal(zero)
		Expect(err).To(MatchError(ContainSubstring("parse session ID: invalid value")))
		Expect(json.Unmarshal([]byte(`123`), &zero)).To(MatchError(ContainSubstring("decode session ID")))

		sentinel := errors.New("entropy unavailable")
		generator, err := identity.NewGenerator(&sequenceSource{err: sentinel})
		Expect(err).NotTo(HaveOccurred())
		_, err = generator.NewSessionID()
		Expect(err).To(MatchError(ContainSubstring("generate session ID")))
		Expect(errors.Is(err, sentinel)).To(BeTrue())
	})
})
