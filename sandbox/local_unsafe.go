package sandbox

import (
	"strings"
	"time"
)

// LocalUnsafeAcknowledgement is the exact acknowledgement required before a
// caller can construct the non-isolating local adapter.
const LocalUnsafeAcknowledgement = "local-unsafe"

// LocalUnsafeConfig configures the explicit developer-only local adapter. It
// never reads ambient process state; callers provide any convenience
// environment that they want sanitized for local use.
type LocalUnsafeConfig struct {
	Acknowledgement      string
	Principal            string
	Now                  time.Time
	AdmissionPolicy      OperationAdmissionPolicy
	DeveloperEnvironment map[string]string
}

// LocalUnsafeClient is an in-memory, developer-only sandbox control client.
// It is intentionally incapable of claiming host, filesystem, network, or
// secret isolation and must never be used as security evidence.
type LocalUnsafeClient struct {
	*coreClient
	developerEnvironment map[string]string
}

// NewLocalUnsafeClient constructs a developer-only client after an exact
// local-unsafe acknowledgement. The client does not execute a process or
// inherit ambient credentials, proxies, or SSH agents.
func NewLocalUnsafeClient(config LocalUnsafeConfig) (*LocalUnsafeClient, error) {
	if config.Acknowledgement != LocalUnsafeAcknowledgement {
		return nil, newFailure(FailureInvalidArgument, "local-unsafe adapter requires explicit acknowledgement", RetryNever)
	}
	if config.Principal == "" || config.Now.IsZero() {
		return nil, newFailure(FailureInvalidArgument, "local-unsafe adapter requires principal and injected clock", RetryNever)
	}
	policy := limitPolicyFromAdmission(config.AdmissionPolicy)
	policy.capabilities = localUnsafeCapabilities()
	client, err := newCoreClientWithPolicy(config.Principal, config.Now.UTC(), policy)
	if err != nil {
		return nil, err
	}
	return &LocalUnsafeClient{coreClient: client, developerEnvironment: sanitizeLocalDeveloperEnvironment(config.DeveloperEnvironment)}, nil
}

// SanitizedDeveloperEnvironment returns the bounded convenience environment
// after credential, proxy, and SSH-agent variables have been removed.
func (client *LocalUnsafeClient) SanitizedDeveloperEnvironment() map[string]string {
	if client == nil {
		return nil
	}
	return copyStringMap(client.developerEnvironment)
}

func limitPolicyFromAdmission(policy OperationAdmissionPolicy) limitPolicy {
	return limitPolicy{
		defaults:              policy.Defaults,
		maximum:               policy.Maximum,
		version:               policy.Version,
		canonicalizerVersion:  policy.CanonicalizerVersion,
		capabilityVersion:     policy.CapabilityVersion,
		imageAdmissionVersion: policy.ImageAdmissionVersion,
		admittedImages:        policy.AdmittedImages,
		capabilities:          policy.Capabilities,
	}
}

func localUnsafeCapabilities() CapabilitySnapshot {
	unavailable := CapabilityDescriptor{
		State:              CapabilityUnavailable,
		ContractVersion:    "sandbox.local-unsafe/v1",
		ConformanceVersion: "not-security-evidence",
		DataPlane:          LocalUnsafeAcknowledgement,
	}
	return CapabilitySnapshot{
		SchemaVersion:   "sandbox.capabilities/v1",
		ControlProtocol: unavailable,
		Isolation:       unavailable,
		Guest:           unavailable,
		Resources:       unavailable,
		Reconnect:       unavailable,
		ImageAdmission:  unavailable,
		Output:          unavailable,
		Transfer:        unavailable,
		Mounts:          unavailable,
		Volumes:         unavailable,
		Snapshots:       unavailable,
		Egress:          unavailable,
		Secrets:         unavailable,
	}
}

func sanitizeLocalDeveloperEnvironment(environment map[string]string) map[string]string {
	if len(environment) == 0 {
		return nil
	}
	sanitized := make(map[string]string, len(environment))
	for key, value := range environment {
		if !validLocalEnvironmentEntry(key, value) || localUnsafeSensitiveEnvironmentKey(key) {
			continue
		}
		sanitized[key] = value
	}
	return sanitized
}

func validLocalEnvironmentEntry(key, value string) bool {
	if len(key) == 0 || len(key) > 128 || len(value) > 4096 {
		return false
	}
	for index, character := range key {
		if !(character == '_' || (character >= 'A' && character <= 'Z') || (index > 0 && character >= '0' && character <= '9')) {
			return false
		}
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func localUnsafeSensitiveEnvironmentKey(key string) bool {
	for _, prefix := range []string{"AWS_", "AZURE_", "GOOGLE_", "GITHUB_", "SSH_", "HTTP_", "HTTPS_", "ALL_PROXY", "NO_PROXY"} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	switch key {
	case "GIT_ASKPASS", "NETRC", "DOCKER_CONFIG", "KUBECONFIG", "VAULT_TOKEN":
		return true
	default:
		return false
	}
}

var _ Client = (*LocalUnsafeClient)(nil)
