package runtimemodel_test

import (
	"context"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimemodel"
)

func TestProfileAdapterSelectsOnlyRevisionPinnedProviderForInvokeAndReconcile(t *testing.T) {
	balanced := &profileRecordingAdapter{output: "balanced"}
	precise := &profileRecordingAdapter{output: "precise"}
	adapter, err := runtimemodel.NewProfileAdapter(runtimemodel.ProfileAdapterConfig{Profiles: []runtimemodel.ProviderProfile{
		{Profile: "balanced", Provider: "fixture-a", Adapter: balanced},
		{Profile: "precise", Provider: "fixture-b", Adapter: precise},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(adapter.Profiles(), ","); got != "balanced,precise" {
		t.Fatalf("profiles = %q", got)
	}
	request := runtimemodel.Request{ModelProfile: "precise"}
	response, err := adapter.Invoke(context.Background(), request)
	if err != nil || string(response.Output) != "precise" || precise.invocations != 1 || balanced.invocations != 0 {
		t.Fatalf("invoke selection = response=%#v err=%v balanced=%d precise=%d", response, err, balanced.invocations, precise.invocations)
	}
	response, err = adapter.Reconcile(context.Background(), request)
	if err != nil || string(response.Output) != "precise" || precise.reconciliations != 1 || balanced.reconciliations != 0 {
		t.Fatalf("reconcile selection = response=%#v err=%v balanced=%d precise=%d", response, err, balanced.reconciliations, precise.reconciliations)
	}
}

func TestProfileAdapterFailsClosedForUnknownOrUnsafeProfiles(t *testing.T) {
	called := &profileRecordingAdapter{}
	adapter, err := runtimemodel.NewProfileAdapter(runtimemodel.ProfileAdapterConfig{Profiles: []runtimemodel.ProviderProfile{{Profile: "balanced", Provider: "fixture", Adapter: called}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"missing", "token-looking-value\n"} {
		if _, err := adapter.Invoke(context.Background(), runtimemodel.Request{ModelProfile: profile}); err == nil || strings.Contains(err.Error(), "token-looking") {
			t.Fatalf("unsafe profile %q error = %v", profile, err)
		}
	}
	if called.invocations != 0 || called.reconciliations != 0 {
		t.Fatalf("unknown profile reached provider = %#v", called)
	}
	for _, config := range []runtimemodel.ProfileAdapterConfig{
		{},
		{Profiles: []runtimemodel.ProviderProfile{{Profile: "balanced", Provider: "fixture", Adapter: called}, {Profile: "balanced", Provider: "other", Adapter: called}}},
		{Profiles: []runtimemodel.ProviderProfile{{Profile: "../unsafe", Provider: "fixture", Adapter: called}}},
		{Profiles: []runtimemodel.ProviderProfile{{Profile: "balanced", Provider: "https://provider", Adapter: called}}},
		{Profiles: []runtimemodel.ProviderProfile{{Profile: "balanced", Provider: "fixture"}}},
	} {
		if _, err := runtimemodel.NewProfileAdapter(config); err == nil {
			t.Fatalf("invalid profile config accepted: %#v", config)
		}
	}
}

type profileRecordingAdapter struct {
	output          string
	invocations     int
	reconciliations int
}

func (adapter *profileRecordingAdapter) Invoke(_ context.Context, _ runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.invocations++
	return runtimemodel.Response{Output: []byte(adapter.output)}, nil
}

func (adapter *profileRecordingAdapter) Reconcile(_ context.Context, _ runtimemodel.Request) (runtimemodel.Response, error) {
	adapter.reconciliations++
	return runtimemodel.Response{Output: []byte(adapter.output)}, nil
}
