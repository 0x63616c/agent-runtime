package runtimepostgres_test

import (
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

func TestNewRuntimeStateStoreRequiresAPool(t *testing.T) {
	if _, err := runtimepostgres.NewRuntimeStateStore(nil); err == nil {
		t.Fatal("NewRuntimeStateStore(nil) error = nil")
	}
}

func TestRuntimeStateStoreImplementsThePlansOnlyAuthority(t *testing.T) {
	// This compile-time contract prevents the PostgreSQL constructor from being
	// mistaken for a usable authority while it still lacks the complete
	// plans-only query and persistence surface.
	var _ runtimestate.RuntimeStateStore = (*runtimepostgres.RuntimeStateStore)(nil)
}
