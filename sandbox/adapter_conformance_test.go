package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestAdapterCapabilityConformance(t *testing.T) {
	clock, err := NewFakeClock(time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewFakeClock() error = %v", err)
	}
	for name, factory := range map[string]func(t *testing.T) Client{
		"local-unsafe": func(t *testing.T) Client {
			client, err := NewLocalUnsafeClient(LocalUnsafeConfig{Acknowledgement: LocalUnsafeAcknowledgement, Principal: "conformance-local", Now: clock.Now(), AdmissionPolicy: operationAdmissionPolicyForTest(testLimitPolicy())})
			if err != nil {
				t.Fatalf("NewLocalUnsafeClient() error = %v", err)
			}
			return client
		},
		"deterministic-fake": func(t *testing.T) Client {
			client, err := NewFakeControlClient(FakeControlConfig{Principal: "conformance-fake", Clock: clock, AdmissionPolicy: operationAdmissionPolicyForTest(testLimitPolicy())})
			if err != nil {
				t.Fatalf("NewFakeControlClient() error = %v", err)
			}
			return client
		},
	} {
		t.Run(name, func(t *testing.T) {
			runCapabilityConformance(t, factory(t))
		})
	}
}

func runCapabilityConformance(t *testing.T, client Client) {
	t.Helper()
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	if !validDigest(capabilities.Digest) || capabilities.SchemaVersion == "" {
		t.Fatalf("Capabilities() = %#v, want versioned snapshot and derived digest", capabilities)
	}
	for name, descriptor := range map[string]CapabilityDescriptor{
		"control":         capabilities.ControlProtocol,
		"isolation":       capabilities.Isolation,
		"guest":           capabilities.Guest,
		"resources":       capabilities.Resources,
		"reconnect":       capabilities.Reconnect,
		"image-admission": capabilities.ImageAdmission,
		"output":          capabilities.Output,
		"transfer":        capabilities.Transfer,
		"mounts":          capabilities.Mounts,
		"volumes":         capabilities.Volumes,
		"snapshots":       capabilities.Snapshots,
		"egress":          capabilities.Egress,
		"secrets":         capabilities.Secrets,
	} {
		if descriptor.State == "" || descriptor.ContractVersion == "" || descriptor.ConformanceVersion == "" || descriptor.DataPlane == "" {
			t.Fatalf("%s descriptor is not structured/versioned: %#v", name, descriptor)
		}
	}

	request := validCreateRequest("op_conformance_" + OperationID(capabilities.Isolation.DataPlane))
	request.CreateSandbox.Spec.Capabilities = CapabilityRequirements{Required: []CapabilityRequirement{{Feature: CapabilityIsolation, Minimum: CapabilityDeclared}}}
	if _, err := client.Submit(context.Background(), request); err == nil {
		t.Fatal("Submit() error = nil, want unsupported isolation capability to fail closed")
	} else {
		failureCode(t, err, FailureCapabilityUnavailable)
	}
}
