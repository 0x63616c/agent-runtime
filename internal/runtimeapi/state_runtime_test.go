package runtimeapi_test

import (
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
)

func TestNewStateRuntimeRequiresTheCompleteStateAndContentAuthority(t *testing.T) {
	if _, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{}); err == nil {
		t.Fatal("NewStateRuntime(empty) error = nil")
	}
}
