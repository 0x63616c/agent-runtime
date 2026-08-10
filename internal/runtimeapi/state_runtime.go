package runtimeapi

import (
	"errors"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

// StateRuntimeConfig supplies the complete metadata/content authority required
// by the state-backed public runtime.
type StateRuntimeConfig struct {
	Content  *runtimecontent.Store
	Compiler *runtimestate.Compiler
	Planner  *runtimestate.RuntimeStatePlanner
	Store    runtimestate.RuntimeStateStore
}

// StateRuntime is the application seam that will route every public operation
// through content staging, compiler, planner, and state persistence.
type StateRuntime struct {
	content  *runtimecontent.Store
	compiler *runtimestate.Compiler
	planner  *runtimestate.RuntimeStatePlanner
	store    runtimestate.RuntimeStateStore
}

// NewStateRuntime validates the non-fallback durable runtime composition.
func NewStateRuntime(config StateRuntimeConfig) (*StateRuntime, error) {
	if config.Content == nil || config.Compiler == nil || config.Planner == nil || config.Store == nil {
		return nil, errors.New("create state runtime: content, compiler, planner, and state store are required")
	}
	return &StateRuntime{content: config.Content, compiler: config.Compiler, planner: config.Planner, store: config.Store}, nil
}
