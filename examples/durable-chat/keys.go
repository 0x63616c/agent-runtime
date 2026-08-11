package durablechat

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// RandomKeys creates opaque idempotency keys without deriving them from chat content.
type RandomKeys struct{}

// Next returns one bounded opaque idempotency key.
func (RandomKeys) Next(action string) (string, error) {
	if action == "" || len(action) > 32 {
		return "", errors.New("create Durable Chat idempotency key: action is invalid")
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errors.New("create Durable Chat idempotency key: entropy is unavailable")
	}
	return "durable-chat-" + action + "-" + hex.EncodeToString(bytes[:]), nil
}
