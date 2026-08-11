package runtimecontent

import (
	"context"
	"strings"
)

const maximumErasureReferences = 1024

// ErasureRequest is an operator-only request to remove exact immutable objects.
type ErasureRequest struct {
	Tenant          TenantID
	AuthorizationID string
	References      []Reference
}

// ErasureAuthorizer accepts one tenant-bound operator deletion request.
type ErasureAuthorizer interface {
	AuthorizeErasure(context.Context, ErasureRequest) error
}

// ImmutableObjectDeleter is an operator capability for removing one private object key.
// It is deliberately not part of ImmutableObjectStore used by runtime request paths.
type ImmutableObjectDeleter interface {
	DeleteExact(context.Context, string) error
}

// ErasureReceipt reports bounded progress without storage keys or authorization material.
type ErasureReceipt struct {
	Tenant  TenantID
	Deleted []Reference
	Failed  *Reference
}

// TenantErasureController deletes only explicitly authorized exact references.
type TenantErasureController struct {
	store      *Store
	authorizer ErasureAuthorizer
	deleter    ImmutableObjectDeleter
}

// NewTenantErasureController constructs the isolated content-deletion authority.
func NewTenantErasureController(store *Store, authorizer ErasureAuthorizer, deleter ImmutableObjectDeleter) (*TenantErasureController, error) {
	if store == nil || authorizer == nil || deleter == nil {
		return nil, ErrNotFoundOrDenied
	}
	return &TenantErasureController{store: store, authorizer: authorizer, deleter: deleter}, nil
}

// Erase deletes every exact reference in order and returns a retry-safe partial receipt on failure.
func (controller *TenantErasureController) Erase(ctx context.Context, request ErasureRequest) (ErasureReceipt, error) {
	if err := ctx.Err(); err != nil {
		return ErasureReceipt{}, err
	}
	if controller == nil || controller.store == nil || controller.authorizer == nil || controller.deleter == nil || !validErasureRequest(request) {
		return ErasureReceipt{}, ErrNotFoundOrDenied
	}
	if err := controller.authorizer.AuthorizeErasure(ctx, cloneErasureRequest(request)); err != nil {
		return ErasureReceipt{}, ErrNotFoundOrDenied
	}
	receipt := ErasureReceipt{Tenant: request.Tenant, Deleted: make([]Reference, 0, len(request.References))}
	for _, reference := range request.References {
		if err := ctx.Err(); err != nil {
			failed := reference
			receipt.Failed = &failed
			return receipt, err
		}
		if err := controller.deleter.DeleteExact(ctx, controller.store.key(request.Tenant, reference.Digest)); err != nil {
			failed := reference
			receipt.Failed = &failed
			return receipt, ErrUnavailable
		}
		receipt.Deleted = append(receipt.Deleted, reference)
	}
	return receipt, nil
}

func validErasureRequest(request ErasureRequest) bool {
	if !validTenantID(request.Tenant) || len(request.AuthorizationID) < 16 || len(request.AuthorizationID) > 128 || strings.ContainsAny(request.AuthorizationID, "\x00\r\n") || len(request.References) == 0 || len(request.References) > maximumErasureReferences {
		return false
	}
	seen := make(map[string]struct{}, len(request.References))
	for _, reference := range request.References {
		if !validLifecycleReference(reference) {
			return false
		}
		key := reference.Digest + "\x00" + reference.MediaType
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func validLifecycleReference(reference Reference) bool {
	return validReference(reference) || validAgentSpecificationBodyReference(reference) || validInputEnvelopeReference(reference) || validArtifactReference(reference) || validConversationEntryReference(reference)
}

func cloneErasureRequest(request ErasureRequest) ErasureRequest {
	request.References = append([]Reference(nil), request.References...)
	return request
}
