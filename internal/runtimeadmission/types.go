// Package runtimeadmission owns the content-reference and durable SendInput admission seam.
package runtimeadmission

import (
	"context"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

const (
	// InputMediaTypeV1 identifies the versioned canonical input envelope.
	InputMediaTypeV1  = "application/vnd.agent-runtime.input+cbor;version=1"
	maximumInputBytes = 2<<20 + 4<<10
)

var (
	// ErrNotFoundOrDenied prevents artifact/content existence disclosure.
	ErrNotFoundOrDenied = errors.New("runtime admission resource not found or denied")
	// ErrConflict reports a durable idempotency or lifecycle conflict.
	ErrConflict = errors.New("runtime admission conflict")
	// ErrUnavailable reports an object-store or PostgreSQL failure safe to retry.
	ErrUnavailable = errors.New("runtime admission unavailable")
	// ErrIntegrity reports content that no longer matches its durable reference.
	ErrIntegrity = errors.New("runtime admission content integrity failure")
)

// Owner is the exact authenticated tenant/principal authorization boundary.
type Owner struct {
	TenantID    string
	PrincipalID string
}

// ContentReference is immutable metadata; it never contains an object key.
type ContentReference struct {
	Digest    string
	MediaType string
	SizeBytes int64
}

// Clock supplies admission timestamps.
type Clock interface{ Now() time.Time }

// IDSource supplies the sixteen-character opaque ID payload used by runtime IDs.
type IDSource interface{ Next() (string, error) }

type authorizedInputLocator struct {
	owner     Owner
	sessionID agentruntime.SessionID
	inputID   agentruntime.InputID
	reference ContentReference
}

// ContentStore owns immutable canonical input bytes.
type ContentStore interface {
	PutInput(context.Context, Owner, []agentruntime.ContentPart) (ContentReference, error)
	GetInput(context.Context, authorizedInputLocator) ([]agentruntime.ContentPart, error)
}

// ArtifactCatalog authorizes immutable artifact metadata before input staging.
type ArtifactCatalog interface {
	AuthorizeInputReferences(context.Context, Owner, []agentruntime.ArtifactReference) error
}

// PreparedInput contains only a content reference and bounded command metadata.
type PreparedInput struct {
	ID             agentruntime.InputID
	SessionID      agentruntime.SessionID
	IdempotencyKey string
	RequestDigest  string
	Content        ContentReference
	AcceptedAt     time.Time
}

// AdmissionResult is the durable result before input content is hydrated.
type AdmissionResult struct {
	InputID    agentruntime.InputID
	AcceptedAt time.Time
	Turn       agentruntime.Turn
}

// Repository commits only one prepared SendInput against an existing Session.
type Repository interface {
	Admit(context.Context, Owner, PreparedInput, IDSource) (AdmissionResult, error)
	AuthorizeInputRead(context.Context, Owner, agentruntime.SessionID, agentruntime.InputID) (authorizedInputLocator, error)
}
