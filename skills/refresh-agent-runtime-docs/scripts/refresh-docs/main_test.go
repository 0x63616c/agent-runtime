package main

import (
	"strings"
	"testing"
)

func TestGoSDKListEnvironmentPinsTheDocumentationTarget(t *testing.T) {
	environment := goSDKListEnvironment([]string{
		"PATH=/bin",
		"GOOS=darwin",
		"GOARCH=arm64",
		"GOFLAGS=-tags=experimental",
		"CGO_ENABLED=1",
	})
	joined := "\n" + strings.Join(environment, "\n") + "\n"
	for _, expected := range []string{
		"\nGOOS=linux\n",
		"\nGOARCH=amd64\n",
		"\nGOFLAGS=\n",
		"\nCGO_ENABLED=0\n",
		"\nPATH=/bin\n",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("go SDK list environment = %q, want %q", environment, expected)
		}
	}
	for _, unexpected := range []string{"\nGOOS=darwin\n", "\nGOARCH=arm64\n", "\nGOFLAGS=-tags=experimental\n", "\nCGO_ENABLED=1\n"} {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("go SDK list environment = %q, unexpectedly retained %q", environment, unexpected)
		}
	}
}
