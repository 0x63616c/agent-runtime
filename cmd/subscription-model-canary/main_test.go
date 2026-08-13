package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/subscriptioncanary"
)

func TestRunRequiresPreflightAndNeverPrintsOpaqueValues(t *testing.T) {
	values := map[string]string{
		"AR_SUBSCRIPTION_CANARY_RUNNER_CONTRACT":    subscriptioncanary.RunnerContract,
		"AR_SUBSCRIPTION_CANARY_GITHUB_ENVIRONMENT": "subscription-model-canary",
		"AR_SUBSCRIPTION_CANARY_RUNNER_LABELS":      "self-hosted,linux,x64,subscription-model-canary-protected",
		"GITHUB_WORKFLOW":                           "subscription-model-canary",
		"GITHUB_REF_PROTECTED":                      "true",
		"RUNNER_ENVIRONMENT":                        "self-hosted",
		"AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV":     "SUBSCRIPTION_CANARY_CAPABILITY",
		"AR_SUBSCRIPTION_CANARY_CREDENTIAL_ENV":     "SUBSCRIPTION_CANARY_CREDENTIAL",
		"SUBSCRIPTION_CANARY_CAPABILITY":            "capability-secret-value",
		"SUBSCRIPTION_CANARY_CREDENTIAL":            "credential-secret-value",
		"AR_SUBSCRIPTION_CANARY_MODEL_PROFILE":      "codex-subscription",
		"AR_SUBSCRIPTION_CANARY_REVISION":           "abcdef0123456789abcdef0123456789abcdef01",
		"AR_SUBSCRIPTION_CANARY_TIMEOUT":            "30s",
		"AR_SUBSCRIPTION_CANARY_CANCEL_MODE":        "explicit-cancel",
		"AR_SUBSCRIPTION_CANARY_RECOVERY_MODE":      "reconcile-on-restart",
	}
	lookup := func(key string) (string, bool) { value, found := values[key]; return value, found }
	var output bytes.Buffer
	if err := run([]string{"-preflight"}, &output, lookup); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := output.String()
	if strings.Contains(got, "secret-value") || !strings.Contains(got, "no provider call or evidence artifact") {
		t.Fatalf("unsafe preflight output: %q", got)
	}
	if err := run(nil, &output, lookup); err == nil {
		t.Fatal("missing -preflight was accepted")
	}
	if err := run([]string{"-preflight", "argument"}, &output, lookup); err == nil {
		t.Fatal("argument was accepted")
	}
}
