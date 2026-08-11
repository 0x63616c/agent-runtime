package sandboxbootprobehostprocess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
)

func TestSubmitStageReadyRefusesAnUncompiledIdentityBeforeNetworkIO(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, context.Canceled
	})}
	_, err = SubmitStageReady(context.Background(), client, "https://control.invalid", firecrackerbootprobev2.Snapshot{}, firecracker.TrustedM4Identity{}, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", privateKey, time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC), nil)
	if err == nil {
		t.Fatal("SubmitStageReady() error = nil, want uncompiled-identity refusal")
	}
	if called {
		t.Fatal("SubmitStageReady() performed network I/O for an uncompiled identity")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
