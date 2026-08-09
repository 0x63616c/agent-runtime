package runtimeadmission

import (
	"context"
	"sync"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// MemoryArtifactCatalog is a deterministic owner-scoped immutable catalog.
type MemoryArtifactCatalog struct {
	mu     sync.RWMutex
	values map[string]agentruntime.ArtifactReference
}

// NewMemoryArtifactCatalog creates an empty catalog.
func NewMemoryArtifactCatalog() *MemoryArtifactCatalog {
	return &MemoryArtifactCatalog{values: make(map[string]agentruntime.ArtifactReference)}
}

// Seed registers one immutable artifact for focused tests.
func (catalog *MemoryArtifactCatalog) Seed(owner Owner, reference agentruntime.ArtifactReference) {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	catalog.values[artifactKey(owner, reference.ID)] = reference
}

// AuthorizeInputReferences verifies every exact immutable reference for owner.
func (catalog *MemoryArtifactCatalog) AuthorizeInputReferences(ctx context.Context, owner Owner, references []agentruntime.ArtifactReference) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	catalog.mu.RLock()
	defer catalog.mu.RUnlock()
	for _, reference := range references {
		stored, found := catalog.values[artifactKey(owner, reference.ID)]
		if !found || stored != reference {
			return ErrNotFoundOrDenied
		}
	}
	return nil
}

func artifactKey(owner Owner, id agentruntime.ArtifactID) string {
	return owner.TenantID + "\x00" + owner.PrincipalID + "\x00" + id.String()
}
