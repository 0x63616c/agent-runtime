package researchdossier

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// RandomKeys creates opaque idempotency keys without deriving them from a
// research brief, source, citation, or Artifact body.
type RandomKeys struct{}

// Next returns one bounded opaque idempotency key for a dossier user action.
func (RandomKeys) Next(action string) (string, error) {
	if action == "" || len(action) > 32 {
		return "", errors.New("create Research Dossier idempotency key: action is invalid")
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errors.New("create Research Dossier idempotency key: entropy is unavailable")
	}
	return "research-dossier-" + action + "-" + hex.EncodeToString(bytes[:]), nil
}
