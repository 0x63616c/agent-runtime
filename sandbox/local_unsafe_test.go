package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestNewLocalUnsafeClientRequiresAcknowledgementAndSanitizesDeveloperEnvironment(t *testing.T) {
	policy := testLimitPolicy()
	config := LocalUnsafeConfig{
		Principal:            "developer",
		Now:                  time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		AdmissionPolicy:      operationAdmissionPolicyForTest(policy),
		DeveloperEnvironment: map[string]string{"LANG": "C.UTF-8", "GITHUB_TOKEN": "must-not-survive", "HTTPS_PROXY": "http://proxy.invalid", "SSH_AUTH_SOCK": "/tmp/agent.sock"},
	}
	if _, err := NewLocalUnsafeClient(config); err == nil {
		t.Fatal("NewLocalUnsafeClient() accepted a missing local-unsafe acknowledgement")
	} else {
		failureCode(t, err, FailureInvalidArgument)
	}

	config.Acknowledgement = LocalUnsafeAcknowledgement
	client, err := NewLocalUnsafeClient(config)
	if err != nil {
		t.Fatalf("NewLocalUnsafeClient() error = %v", err)
	}
	if got, want := client.SanitizedDeveloperEnvironment(), map[string]string{"LANG": "C.UTF-8"}; !sameStringMap(got, want) {
		t.Fatalf("SanitizedDeveloperEnvironment() = %#v, want %#v", got, want)
	}
	copy := client.SanitizedDeveloperEnvironment()
	copy["LANG"] = "mutated"
	if got, want := client.SanitizedDeveloperEnvironment()["LANG"], "C.UTF-8"; got != want {
		t.Fatalf("SanitizedDeveloperEnvironment returned caller-owned state: %q, want %q", got, want)
	}
}

func TestLocalUnsafeClientRefusesSecurityAuthorityItCannotEnforce(t *testing.T) {
	policy := testLimitPolicy()
	client, err := NewLocalUnsafeClient(LocalUnsafeConfig{
		Acknowledgement: LocalUnsafeAcknowledgement,
		Principal:       "developer",
		Now:             time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		AdmissionPolicy: operationAdmissionPolicyForTest(policy),
	})
	if err != nil {
		t.Fatalf("NewLocalUnsafeClient() error = %v", err)
	}

	for name, mutate := range map[string]func(*SandboxSpec){
		"secret": func(spec *SandboxSpec) {
			spec.SecretBindings = []SecretBinding{{Name: "build-token", Purpose: "build"}}
		},
		"mount": func(spec *SandboxSpec) {
			spec.Mounts = []MountRequest{{Name: "source", Target: "/work/source", Mode: MountReadOnly, View: MountFrozen}}
		},
		"volume": func(spec *SandboxSpec) {
			spec.VolumeAttachments = []VolumeAttachment{{VolumeID: "vol_01", Target: "/work/data", Mode: AttachmentReadWrite}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := validCreateRequest(OperationID("op_local_" + name))
			mutate(&request.CreateSandbox.Spec)
			if _, err := client.Submit(context.Background(), request); err == nil {
				t.Fatal("Submit() error = nil, want unavailable authority refusal")
			} else {
				failureCode(t, err, FailureCapabilityUnavailable)
			}
		})
	}

	request := validCreateRequest("op_local_capability")
	request.CreateSandbox.Spec.Capabilities.Required = []CapabilityRequirement{{Feature: CapabilityIsolation, Minimum: CapabilityDeclared}}
	if _, err := client.Submit(context.Background(), request); err == nil {
		t.Fatal("Submit() error = nil, want local isolation capability refusal")
	} else {
		failureCode(t, err, FailureCapabilityUnavailable)
	}

	create := validCreateRequest("op_local_advertisement")
	if _, err := client.Submit(context.Background(), create); err != nil {
		t.Fatalf("Submit() ordinary local operation error = %v", err)
	}
	info, err := client.GetSandbox(context.Background(), "sbx_local_advertisement")
	if err != nil {
		t.Fatalf("GetSandbox() error = %v", err)
	}
	if got, want := info.Capabilities.Isolation.DataPlane, LocalUnsafeAcknowledgement; got != want {
		t.Fatalf("local isolation data plane = %q, want explicit %q advertisement", got, want)
	}
	if got, want := info.Capabilities.Isolation.State, CapabilityUnavailable; got != want {
		t.Fatalf("local isolation state = %q, want %q", got, want)
	}
}

func operationAdmissionPolicyForTest(policy limitPolicy) OperationAdmissionPolicy {
	return OperationAdmissionPolicy{
		Defaults: policy.defaults,
		Maximum:  policy.maximum,
	}
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
