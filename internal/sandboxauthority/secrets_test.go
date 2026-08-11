package sandboxauthority

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManagerDeliversOnlyEphemerallyThenRevokesAndZeroizesAfterTreeReap(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	resolver := &testResolver{value: SecretValue{Version: "v3", ExpiresAt: now.Add(time.Minute), Bytes: []byte("never-persist")}}
	sink := &testSink{}
	audit := &testAudit{}
	manager, err := NewManager(resolver, sink, audit)
	if err != nil {
		t.Fatal(err)
	}
	request := testSecretRequest(now)
	if err := manager.Deliver(context.Background(), request, now); err != nil {
		t.Fatal(err)
	}
	if got := string(sink.delivered); got != "never-persist" || string(resolver.value.Bytes) != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" {
		t.Fatalf("delivery/zeroization = %q / %q", got, resolver.value.Bytes)
	}
	if err := manager.RevokeAfterTreeReap(context.Background(), request.ProcessID); err != nil {
		t.Fatal(err)
	}
	if !sink.revoked || len(manager.RedactionValues(request.ProcessID)) != 0 || len(audit.facts) != 2 || audit.facts[1].Event != "revoked-after-tree-reap" {
		t.Fatalf("revoke lifecycle = %#v %#v", sink, audit.facts)
	}
}

func TestManagerRetainsSecretUntilTheSinkConfirmsCompleteTreeReap(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	sink := &testSink{revokeErr: errors.New("tree still alive")}
	manager, err := NewManager(&testResolver{value: SecretValue{Version: "v1", ExpiresAt: now.Add(time.Minute), Bytes: []byte("secret")}}, sink, &testAudit{})
	if err != nil {
		t.Fatal(err)
	}
	request := testSecretRequest(now)
	if err := manager.Deliver(context.Background(), request, now); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokeAfterTreeReap(context.Background(), request.ProcessID); err == nil || len(manager.RedactionValues(request.ProcessID)) != 1 {
		t.Fatalf("premature revoke = %v", err)
	}
}

func TestManagerClearsARejectedDeliveryReservationForARetry(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	sink := &testSink{deliverErr: errors.New("not ready")}
	manager, err := NewManager(&testResolver{value: SecretValue{Version: "v1", ExpiresAt: now.Add(time.Minute), Bytes: []byte("secret")}}, sink, &testAudit{})
	if err != nil {
		t.Fatal(err)
	}
	request := testSecretRequest(now)
	if err := manager.Deliver(context.Background(), request, now); err == nil {
		t.Fatal("first delivery succeeded")
	}
	sink.deliverErr = nil
	if err := manager.Deliver(context.Background(), request, now); err != nil {
		t.Fatalf("retry after rejected delivery = %v", err)
	}
}

func TestManagerAbortsOnlyASinkProvenPrestartDeliveryAndZeroizesIt(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	sink := &testSink{prestartAbort: true}
	manager, err := NewManager(&testResolver{value: SecretValue{Version: "v1", ExpiresAt: now.Add(time.Minute), Bytes: []byte("secret")}}, sink, &testAudit{})
	if err != nil {
		t.Fatal(err)
	}
	request := testSecretRequest(now)
	if err := manager.Deliver(context.Background(), request, now); err != nil {
		t.Fatal(err)
	}
	if err := manager.AbortBeforeStart(context.Background(), request.ProcessID); err != nil {
		t.Fatalf("AbortBeforeStart() error = %v", err)
	}
	if !sink.aborted || len(manager.RedactionValues(request.ProcessID)) != 0 {
		t.Fatalf("prestart abort = %#v", sink)
	}
}

type testResolver struct{ value SecretValue }

func (resolver *testResolver) Resolve(context.Context, SecretRequest) (SecretValue, error) {
	return resolver.value, nil
}

type testSink struct {
	delivered     []byte
	revoked       bool
	deliverErr    error
	revokeErr     error
	prestartAbort bool
	aborted       bool
}

func (sink *testSink) Deliver(_ context.Context, _ SecretRequest, value []byte) error {
	if sink.deliverErr != nil {
		return sink.deliverErr
	}
	sink.delivered = append([]byte(nil), value...)
	return nil
}
func (sink *testSink) RevokeAfterTreeReap(context.Context, SecretRequest) error {
	if sink.revokeErr != nil {
		return sink.revokeErr
	}
	sink.revoked = true
	return nil
}
func (sink *testSink) AbortBeforeStart(context.Context, SecretRequest) error {
	if !sink.prestartAbort {
		return errors.New("prestart abort unsupported")
	}
	sink.aborted = true
	return nil
}

type testAudit struct{ facts []SecretAuditFact }

func (audit *testAudit) RecordSecretDelivery(_ context.Context, fact SecretAuditFact) error {
	audit.facts = append(audit.facts, fact)
	return nil
}
func testSecretRequest(now time.Time) SecretRequest {
	return SecretRequest{Principal: "tenant:alice", SandboxID: "sbx_01", ProcessID: "prc_01", OperationID: "op_01", Binding: "model", Purpose: "command", ExpiresAt: now.Add(time.Minute)}
}
