package subscriptioncanary

import (
	"reflect"
	"testing"
	"time"
)

func TestLoadRequiresBoundedOpaqueControlsWithoutRetainingValues(t *testing.T) {
	values := map[string]string{
		"AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV": "SUBSCRIPTION_CANARY_CAPABILITY",
		"AR_SUBSCRIPTION_CANARY_CREDENTIAL_ENV": "SUBSCRIPTION_CANARY_CREDENTIAL",
		"SUBSCRIPTION_CANARY_CAPABILITY":        "opaque-capability-value-must-not-escape",
		"SUBSCRIPTION_CANARY_CREDENTIAL":        "credential-value-must-not-escape",
		"AR_SUBSCRIPTION_CANARY_MODEL_PROFILE":  "codex-subscription",
		"AR_SUBSCRIPTION_CANARY_REVISION":       "abcdef0123456789abcdef0123456789abcdef01",
		"AR_SUBSCRIPTION_CANARY_TIMEOUT":        "30s",
		"AR_SUBSCRIPTION_CANARY_CANCEL_MODE":    "explicit-cancel",
		"AR_SUBSCRIPTION_CANARY_RECOVERY_MODE":  "reconcile-on-restart",
	}
	lookup := func(key string) (string, bool) { value, found := values[key]; return value, found }
	config, err := Load(lookup)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := Config{CapabilityEnvironment: "SUBSCRIPTION_CANARY_CAPABILITY", CredentialEnvironment: "SUBSCRIPTION_CANARY_CREDENTIAL", ModelProfile: "codex-subscription", Revision: "abcdef0123456789abcdef0123456789abcdef01", Timeout: 30 * time.Second, CancelMode: "explicit-cancel", RecoveryMode: "reconcile-on-restart"}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("config = %#v, want %#v", config, want)
	}
	for _, name := range []string{"AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV", "AR_SUBSCRIPTION_CANARY_CREDENTIAL_ENV", "AR_SUBSCRIPTION_CANARY_MODEL_PROFILE", "AR_SUBSCRIPTION_CANARY_REVISION", "AR_SUBSCRIPTION_CANARY_TIMEOUT", "AR_SUBSCRIPTION_CANARY_CANCEL_MODE", "AR_SUBSCRIPTION_CANARY_RECOVERY_MODE"} {
		delete(values, name)
		if _, err := Load(lookup); err == nil {
			t.Fatalf("missing %s was accepted", name)
		}
		values[name] = wantValue(name)
	}
	values["AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV"] = "SUBSCRIPTION_CANARY_CREDENTIAL"
	if _, err := Load(lookup); err == nil {
		t.Fatal("shared capability and credential environment was accepted")
	}
}

func TestLoadRejectsUnsafeOrIncompleteCanaryInputs(t *testing.T) {
	values := map[string]string{
		"AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV": "SUBSCRIPTION_CANARY_CAPABILITY",
		"AR_SUBSCRIPTION_CANARY_CREDENTIAL_ENV": "SUBSCRIPTION_CANARY_CREDENTIAL",
		"SUBSCRIPTION_CANARY_CAPABILITY":        "opaque",
		"SUBSCRIPTION_CANARY_CREDENTIAL":        "opaque",
		"AR_SUBSCRIPTION_CANARY_MODEL_PROFILE":  "codex-subscription",
		"AR_SUBSCRIPTION_CANARY_REVISION":       "abcdef0123456789abcdef0123456789abcdef01",
		"AR_SUBSCRIPTION_CANARY_TIMEOUT":        "30s",
		"AR_SUBSCRIPTION_CANARY_CANCEL_MODE":    "explicit-cancel",
		"AR_SUBSCRIPTION_CANARY_RECOVERY_MODE":  "reconcile-on-restart",
	}
	lookup := func(key string) (string, bool) { value, found := values[key]; return value, found }
	for name, value := range map[string]string{
		"AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV": "https://token.example",
		"AR_SUBSCRIPTION_CANARY_MODEL_PROFILE":  "unsafe profile",
		"AR_SUBSCRIPTION_CANARY_REVISION":       "not-a-revision",
		"AR_SUBSCRIPTION_CANARY_TIMEOUT":        "6m",
		"AR_SUBSCRIPTION_CANARY_CANCEL_MODE":    "best-effort",
		"AR_SUBSCRIPTION_CANARY_RECOVERY_MODE":  "retry",
	} {
		original := values[name]
		values[name] = value
		if _, err := Load(lookup); err == nil {
			t.Fatalf("unsafe %s=%q was accepted", name, value)
		}
		values[name] = original
	}
	delete(values, "SUBSCRIPTION_CANARY_CREDENTIAL")
	if _, err := Load(lookup); err == nil {
		t.Fatal("absent named credential environment was accepted")
	}
}

func wantValue(name string) string {
	return map[string]string{
		"AR_SUBSCRIPTION_CANARY_CAPABILITY_ENV": "SUBSCRIPTION_CANARY_CAPABILITY",
		"AR_SUBSCRIPTION_CANARY_CREDENTIAL_ENV": "SUBSCRIPTION_CANARY_CREDENTIAL",
		"AR_SUBSCRIPTION_CANARY_MODEL_PROFILE":  "codex-subscription",
		"AR_SUBSCRIPTION_CANARY_REVISION":       "abcdef0123456789abcdef0123456789abcdef01",
		"AR_SUBSCRIPTION_CANARY_TIMEOUT":        "30s",
		"AR_SUBSCRIPTION_CANARY_CANCEL_MODE":    "explicit-cancel",
		"AR_SUBSCRIPTION_CANARY_RECOVERY_MODE":  "reconcile-on-restart",
	}[name]
}
