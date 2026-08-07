// Package identity defines runtime-owned opaque identifiers.
package identity

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cockroachdb/errors"
)

const sessionPrefix = "sess_"

// Source supplies opaque identifier payloads at the composition root.
type Source interface {
	// Next returns one canonical ASCII payload without a type prefix.
	Next() (string, error)
}

// Generator creates typed runtime IDs from an injected source.
type Generator struct {
	source Source
}

// NewGenerator creates a Generator that uses source for opaque ID payloads.
func NewGenerator(source Source) (Generator, error) {
	if source == nil {
		return Generator{}, errors.New("identity source is required")
	}
	return Generator{source: source}, nil
}

// SessionID identifies a Session without disclosing routing or authorization data.
type SessionID string

// NewSessionID creates a SessionID from the generator's injected source.
func (g Generator) NewSessionID() (SessionID, error) {
	payload, err := g.source.Next()
	if err != nil {
		return "", errors.Wrap(err, "generate session ID")
	}
	id, err := parseSessionID(sessionPrefix + payload)
	if err != nil {
		return "", errors.Wrap(err, "generate session ID")
	}
	return id, nil
}

// ParseSessionID validates an externally supplied SessionID.
func ParseSessionID(value string) (SessionID, error) {
	return parseSessionID(value)
}

func parseSessionID(value string) (SessionID, error) {
	if !strings.HasPrefix(value, sessionPrefix) || !validPayload(strings.TrimPrefix(value, sessionPrefix)) {
		return "", errors.New("parse session ID: invalid value")
	}
	return SessionID(value), nil
}

func validPayload(payload string) bool {
	if len(payload) != 16 {
		return false
	}
	for _, character := range payload {
		if !isASCIIAlphaNumeric(character) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(character rune) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
}

// String returns the canonical identifier value for protocol use.
func (id SessionID) String() string {
	return string(id)
}

// Redacted returns a safe diagnostic representation of the ID.
func (id SessionID) Redacted() string {
	value := id.String()
	if len(value) < len(sessionPrefix)+4 {
		return "[INVALID SESSION ID]"
	}
	return fmt.Sprintf("%s...%s", sessionPrefix, value[len(value)-4:])
}

// LogValue implements slog.LogValuer with a redacted value.
func (id SessionID) LogValue() slog.Value {
	return slog.StringValue(id.Redacted())
}

// MarshalJSON serializes a validated SessionID as a JSON string.
func (id SessionID) MarshalJSON() ([]byte, error) {
	if _, err := ParseSessionID(id.String()); err != nil {
		return nil, errors.Wrap(err, "encode session ID")
	}
	return json.Marshal(id.String())
}

// UnmarshalJSON validates a JSON SessionID string before accepting it.
func (id *SessionID) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.Wrap(err, "decode session ID")
	}
	parsed, err := ParseSessionID(value)
	if err != nil {
		return errors.Wrap(err, "decode session ID")
	}
	*id = parsed
	return nil
}
