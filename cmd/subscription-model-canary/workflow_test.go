package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedWorkflowUsesOnlyTheDedicatedPreflightContract(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "subscription-model-canary.yml"))
	if err != nil {
		t.Fatalf("read protected workflow: %v", err)
	}
	contents := string(workflow)
	for _, want := range []string{
		"workflow_dispatch:",
		"runs-on: [self-hosted, linux, x64, subscription-model-canary-protected]",
		"environment: subscription-model-canary",
		"AR_SUBSCRIPTION_CANARY_RUNNER_CONTRACT: protected-subscription-model-canary/v1",
		"AR_SUBSCRIPTION_CANARY_GITHUB_ENVIRONMENT: subscription-model-canary",
		"AR_SUBSCRIPTION_CANARY_RUNNER_LABELS: self-hosted,linux,x64,subscription-model-canary-protected",
		"run: just subscription-model-canary-preflight",
		"uses: actions/upload-artifact@",
		"subscription-model-canary-preflight-${{ github.sha }}",
	} {
		if !strings.Contains(contents, want) {
			t.Errorf("protected workflow is missing %q", want)
		}
	}
	for _, forbidden := range []string{"curl ", "wget ", "go run ./cmd/subscription-model-canary -report", "provider call"} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("protected workflow contains forbidden live action %q", forbidden)
		}
	}
}
