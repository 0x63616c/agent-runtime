// Package codexsubscription owns the fail-closed Codex subscription release
// gate. It intentionally does not read, copy, parse, refresh, or transport a
// credential.
package codexsubscription

import (
	"errors"
	"fmt"
	"strings"
)

// Surface identifies the official Codex integration surface reviewed by an
// operator. It is metadata, never a credential or endpoint.
type Surface string

const (
	// SurfaceAppServer is the official Codex app-server integration surface.
	SurfaceAppServer Surface = "app-server"
)

// Assessment is the bounded, secret-safe result of the required official
// support review. It is deliberately separate from a credential source: a
// support decision must not become a reason to expose a credential value.
type Assessment struct {
	Surface                    Surface
	CodexVersion               string
	ProductionSupported        bool
	ModelOnlyToolBoundary      bool
	IsolatedCredentialIdentity bool
	ProtectedCanaryAuthorized  bool
}

// Disposition reports whether a production Codex subscription adapter can be
// composed. It does not assert that a canary has run.
type Disposition struct {
	Eligible bool
	Reason   string
}

const (
	blockedUnsupportedSurface = "official Codex subscription surface is not approved for production model use"
	blockedToolBoundary       = "Codex-owned tool boundary is not verified for the runtime model seam"
	blockedIdentity           = "credential identity isolation is not verified"
	blockedCanary             = "protected subscription canary authority is not configured"
)

// Evaluate fails closed unless the retained official review proves every
// production prerequisite. The protocol documentation has stable base APIs as
// well as explicit experimental opt-ins, but the exact pinned CLI can still
// label its app-server command experimental. ProductionSupported records the
// review's approval of that exact executable and Model use; a stable protocol
// subset alone does not prove it. It also never proves the separate
// no-Codex-tools boundary required by this runtime.
func Evaluate(assessment Assessment) (Disposition, error) {
	if assessment.Surface != SurfaceAppServer {
		return Disposition{}, errors.New("evaluate Codex subscription support: official surface is required")
	}
	if strings.TrimSpace(assessment.CodexVersion) == "" || len(assessment.CodexVersion) > 128 {
		return Disposition{}, errors.New("evaluate Codex subscription support: pinned Codex version is required")
	}
	if !assessment.ProductionSupported {
		return Disposition{Reason: blockedUnsupportedSurface}, nil
	}
	if !assessment.ModelOnlyToolBoundary {
		return Disposition{Reason: blockedToolBoundary}, nil
	}
	if !assessment.IsolatedCredentialIdentity {
		return Disposition{Reason: blockedIdentity}, nil
	}
	if !assessment.ProtectedCanaryAuthorized {
		return Disposition{Reason: blockedCanary}, nil
	}
	return Disposition{Eligible: true}, nil
}

// RequireProductionSupport turns a non-eligible assessment into a stable,
// credential-safe composition failure. Callers must not treat this error as a
// provider failure to retry or silently fall back to an API credential.
func RequireProductionSupport(assessment Assessment) error {
	disposition, err := Evaluate(assessment)
	if err != nil {
		return err
	}
	if !disposition.Eligible {
		return fmt.Errorf("compose Codex subscription model adapter: %s", disposition.Reason)
	}
	return nil
}
