package runtimepostgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

func TestEraseTenantRefusesUncomposedOrMalformedOperatorRequests(t *testing.T) {
	tenant, err := runtimecontent.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	var store *runtimepostgres.RuntimeStateStore
	for _, request := range []runtimepostgres.LifecycleRequest{
		{Action: runtimepostgres.LifecycleEraseTenant, Tenant: tenant, AuthorizationID: "short"},
		{Action: runtimepostgres.LifecycleEraseTenant, Tenant: tenant, AuthorizationID: "authorization-000000"},
	} {
		if err := store.EraseTenant(context.Background(), nil, request); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
			t.Fatalf("EraseTenant(%#v) error = %v, want non-enumerating refusal", request, err)
		}
	}
}
