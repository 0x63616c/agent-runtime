// Package runtimeerror adds safe context at runtime boundaries.
package runtimeerror

import (
	"log/slog"

	"github.com/cockroachdb/errors"
)

// SafeIdentity is bounded ASCII text approved for errors and logs.
type SafeIdentity struct{ value string }

// NewSafeIdentity validates a diagnostic identity before use.
func NewSafeIdentity(value string) (SafeIdentity, error) {
	if !safe(value) {
		return SafeIdentity{}, errors.New("create safe error identity: invalid value")
	}
	return SafeIdentity{value: value}, nil
}

// String returns the validated safe value.
func (identity SafeIdentity) String() string { return identity.value }

// LogValue implements slog.LogValuer using only validated safe text.
func (identity SafeIdentity) LogValue() slog.Value { return slog.StringValue(identity.value) }

// Wrap annotates cause with a safe operation and identity while preserving errors.Is and errors.As.
func Wrap(operation string, identity SafeIdentity, cause error) error {
	if !safeOperation(operation) {
		return errors.New("wrap runtime error: invalid operation")
	}
	if cause == nil {
		return errors.Newf("%s %s failed", operation, identity.String())
	}
	return errors.Wrapf(cause, "%s %s", operation, identity.String())
}

func safe(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !safeCharacter(character) {
			return false
		}
	}
	return true
}

func safeCharacter(character rune) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.'
}

func safeOperation(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character != ' ' {
				return false
			}
		}
	}
	return true
}
