// Package subscriptioncanary validates the operator contract required before a
// protected subscription-model canary. It intentionally cannot call a model
// provider: local validation is preparation, never canary evidence.
package subscriptioncanary

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const ContractVersion = "subscription-model-canary/v1"

// Config is a redacted preflight projection. Capability and credential values
// are checked only for presence and are deliberately not retained here.
type Config struct {
	CapabilityEnvironment string
	CredentialEnvironment string
	ModelProfile          string
	Revision              string
	Timeout               time.Duration
	CancelMode            string
	RecoveryMode          string
}

// Load requires every explicit canary control. lookup is intentionally used
// instead of reading os.Environ so neither secret values nor unrelated process
// state can be copied into a diagnostic or report.
func Load(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		return Config{}, errors.New("subscription model canary preflight: environment lookup is required")
	}
	capabilityEnvironment, err := referencedEnvironment(lookup, "AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV")
	if err != nil {
		return Config{}, err
	}
	credentialEnvironment, err := referencedEnvironment(lookup, "AR_SUBSCRIPTION_CANARY_CREDENTIAL_ENV")
	if err != nil {
		return Config{}, err
	}
	if capabilityEnvironment == credentialEnvironment {
		return Config{}, errors.New("subscription model canary preflight: capability and credential environments must be distinct")
	}
	modelProfile := required(lookup, "AR_SUBSCRIPTION_CANARY_MODEL_PROFILE")
	if !validIdentifier(modelProfile) {
		return Config{}, errors.New("subscription model canary preflight: bounded model profile is required")
	}
	revision := required(lookup, "AR_SUBSCRIPTION_CANARY_REVISION")
	if !validRevision(revision) {
		return Config{}, errors.New("subscription model canary preflight: immutable source revision is required")
	}
	timeout, err := time.ParseDuration(required(lookup, "AR_SUBSCRIPTION_CANARY_TIMEOUT"))
	if err != nil || timeout < time.Second || timeout > 5*time.Minute {
		return Config{}, errors.New("subscription model canary preflight: timeout from one second through five minutes is required")
	}
	cancelMode := required(lookup, "AR_SUBSCRIPTION_CANARY_CANCEL_MODE")
	if cancelMode != "explicit-cancel" {
		return Config{}, errors.New("subscription model canary preflight: cancel mode must be explicit-cancel")
	}
	recoveryMode := required(lookup, "AR_SUBSCRIPTION_CANARY_RECOVERY_MODE")
	if recoveryMode != "reconcile-on-restart" {
		return Config{}, errors.New("subscription model canary preflight: recovery mode must be reconcile-on-restart")
	}
	return Config{
		CapabilityEnvironment: capabilityEnvironment,
		CredentialEnvironment: credentialEnvironment,
		ModelProfile:          modelProfile,
		Revision:              revision,
		Timeout:               timeout,
		CancelMode:            cancelMode,
		RecoveryMode:          recoveryMode,
	}, nil
}

func referencedEnvironment(lookup func(string) (string, bool), selector string) (string, error) {
	name := required(lookup, selector)
	if !validEnvironmentName(name) {
		return "", fmt.Errorf("subscription model canary preflight: %s must name an opaque environment variable", selector)
	}
	value, present := lookup(name)
	if !present || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("subscription model canary preflight: named %s is absent", opaqueRole(selector))
	}
	return name, nil
}

func required(lookup func(string) (string, bool), name string) string {
	value, present := lookup(name)
	if !present {
		return ""
	}
	return value
}

func opaqueRole(selector string) string {
	if selector == "AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV" {
		return "capability environment"
	}
	return "credential environment"
}

func validEnvironmentName(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character != '_' && (character < 'A' || character > 'Z') && (index == 0 || character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := strconv.ParseUint(value[:16], 16, 64)
	if err != nil {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
