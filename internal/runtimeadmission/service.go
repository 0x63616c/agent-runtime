package runtimeadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

// Service composes content ingress, artifact admission, and durable SendInput.
type Service struct {
	content    ContentStore
	artifacts  ArtifactCatalog
	repository Repository
	clock      Clock
	ids        IDSource
}

// NewService constructs a fail-closed durable SendInput composition.
func NewService(content ContentStore, artifacts ArtifactCatalog, repository Repository, clock Clock, ids IDSource) (*Service, error) {
	if content == nil || artifacts == nil || repository == nil || clock == nil || ids == nil {
		return nil, errors.New("create runtime admission service: all dependencies are required")
	}
	return &Service{content: content, artifacts: artifacts, repository: repository, clock: clock, ids: ids}, nil
}

// SendInput validates artifacts before staging content, commits a prepared reference, then hydrates from the authorized locator.
func (service *Service) SendInput(ctx context.Context, owner Owner, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	if err := validateOwner(owner); err != nil {
		return agentruntime.SendInputResult{}, err
	}
	if err := validateRequest(request); err != nil {
		return agentruntime.SendInputResult{}, err
	}
	references := artifactReferences(request.Parts)
	if err := service.artifacts.AuthorizeInputReferences(ctx, owner, references); err != nil {
		return agentruntime.SendInputResult{}, err
	}
	content, err := service.content.PutInput(ctx, owner, request.Parts)
	if err != nil {
		return agentruntime.SendInputResult{}, err
	}
	inputID, err := newID[agentruntime.InputID](service.ids, "inpt_")
	if err != nil {
		return agentruntime.SendInputResult{}, err
	}
	prepared := PreparedInput{ID: inputID, SessionID: request.SessionID, IdempotencyKey: request.IdempotencyKey, RequestDigest: requestDigest(request.SessionID, content), Content: content, AcceptedAt: service.clock.Now().UTC()}
	admission, err := service.repository.Admit(ctx, owner, prepared, service.ids)
	if err != nil {
		return agentruntime.SendInputResult{}, err
	}
	locator, err := service.repository.AuthorizeInputRead(ctx, owner, request.SessionID, admission.InputID)
	if err != nil {
		return agentruntime.SendInputResult{}, err
	}
	parts, err := service.content.GetInput(ctx, locator)
	if err != nil {
		return agentruntime.SendInputResult{}, err
	}
	return agentruntime.SendInputResult{Input: agentruntime.Input{ID: admission.InputID, Parts: parts, AcceptedAt: admission.AcceptedAt}, Turn: admission.Turn}, nil
}

func validateOwner(owner Owner) error {
	if !bounded(owner.TenantID, 128) || !bounded(owner.PrincipalID, 128) {
		return errors.New("invalid runtime admission owner")
	}
	return nil
}
func validateRequest(request agentruntime.SendInputRequest) error {
	if _, err := agentruntime.ParseSessionID(request.SessionID.String()); err != nil || !bounded(request.IdempotencyKey, agentruntime.MaxIdempotencyKeyBytes) || len(request.Parts) == 0 || len(request.Parts) > agentruntime.MaxInputParts {
		return errors.New("invalid SendInput request")
	}
	return validateParts(request.Parts)
}
func validateParts(parts []agentruntime.ContentPart) error {
	for _, part := range parts {
		switch part.Kind {
		case agentruntime.ContentText:
			if part.Text == "" || len(part.Text) > agentruntime.MaxTextPartBytes || !utf8.ValidString(part.Text) || part.Artifact != nil {
				return errors.New("invalid text input part")
			}
		case agentruntime.ContentArtifact:
			if part.Text != "" || part.Artifact == nil || part.Artifact.SizeBytes < 0 || !utf8.ValidString(part.Artifact.MediaType) || part.Artifact.MediaType == "" || len(part.Artifact.MediaType) > 255 || len(part.Artifact.SHA256) != 64 || strings.Trim(part.Artifact.SHA256, "0123456789abcdef") != "" {
				return errors.New("invalid artifact input part")
			}
			if _, err := agentruntime.ParseArtifactID(part.Artifact.ID.String()); err != nil {
				return errors.New("invalid artifact input part")
			}
		default:
			return errors.New("unsupported input part")
		}
	}
	return nil
}
func artifactReferences(parts []agentruntime.ContentPart) []agentruntime.ArtifactReference {
	result := make([]agentruntime.ArtifactReference, 0, len(parts))
	for _, part := range parts {
		if part.Kind == agentruntime.ContentArtifact {
			result = append(result, *part.Artifact)
		}
	}
	return result
}
func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\n\r")
}
func requestDigest(session agentruntime.SessionID, content ContentReference) string {
	sum := sha256.Sum256([]byte("send-input/v1\x00" + session.String() + "\x00" + content.Digest + "\x00" + content.MediaType + "\x00" + strconv.FormatInt(content.SizeBytes, 10)))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func newID[T ~string](source IDSource, prefix string) (T, error) {
	value, err := source.Next()
	if err != nil {
		return "", errors.Wrap(err, "allocate runtime admission identifier")
	}
	if len(value) != 16 || strings.ContainsAny(value, "_- ") {
		return "", errors.New("invalid runtime admission identifier payload")
	}
	candidate := prefix + value
	if err := validateTypedID(prefix, candidate); err != nil {
		return "", err
	}
	return T(candidate), nil
}

func validateTypedID(prefix, candidate string) error {
	var err error
	switch prefix {
	case "inpt_":
		_, err = agentruntime.ParseInputID(candidate)
	case "turn_":
		_, err = agentruntime.ParseTurnID(candidate)
	case "evt_":
		_, err = agentruntime.ParseEventID(candidate)
	case "cur_":
		_, err = agentruntime.ParseCursor(candidate)
	case "aud_":
		return nil // audit IDs are internal but retain the same generated-payload validation above.
	default:
		return errors.New("unsupported runtime admission identifier prefix")
	}
	if err != nil {
		return errors.Wrap(err, "parse generated runtime admission identifier")
	}
	return nil
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type sequenceIDs struct{}

func (sequenceIDs) Next() (string, error) { return "0000000000000001", nil }
