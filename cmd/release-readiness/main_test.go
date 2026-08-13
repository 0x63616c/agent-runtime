package main

import (
	"errors"
	"strings"
	"testing"
)

const readinessRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRunWritesAnExactMainBoundReleaseManifest(t *testing.T) {
	report, err := run("v1.2.3", successfulGit(readinessRevision))
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if report.SourceRevision != readinessRevision || report.SourceRef != "refs/heads/main" || report.Result != "external-release-actions-required" {
		t.Fatalf("report does not bind the release to main: %#v", report)
	}
	if got, want := workflowNames(report), "main-ci,documentation-pages,firecracker-kvm,runtime-operations-drill,publish-production-image"; got != want {
		t.Fatalf("required hosted workflows = %q, want %q", got, want)
	}
	if !strings.Contains(report.PublicDocsVerification.Command, readinessRevision) || !strings.Contains(report.PublicDocsVerification.Command, "-require-source-sha-marker") {
		t.Fatalf("docs verification command = %q, want exact revision marker check", report.PublicDocsVerification.Command)
	}
	if !strings.Contains(report.ReleaseAssets[1].Expectation, "@v1.2.3") || !strings.Contains(report.ReleaseAssets[2].Expectation, readinessRevision) {
		t.Fatalf("release asset expectations = %#v, want tag and revision", report.ReleaseAssets)
	}
	if len(report.ExternalActions) != 5 || !strings.Contains(report.ExternalActions[2].Action, "does not create") {
		t.Fatalf("external actions = %#v, want explicit non-mutating publication boundary", report.ExternalActions)
	}
}

func TestRunRefusesNonMainOrDirtyCheckout(t *testing.T) {
	for name, runner := range map[string]commandRunner{
		"different main": func(_ string, arguments ...string) ([]byte, error) {
			if strings.Join(arguments, " ") == "rev-parse refs/heads/main" {
				return []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"), nil
			}
			return gitAnswer(readinessRevision)("git", arguments...)
		},
		"detached": func(_ string, arguments ...string) ([]byte, error) {
			if strings.Join(arguments, " ") == "symbolic-ref --quiet --short HEAD" {
				return nil, errors.New("detached")
			}
			return gitAnswer(readinessRevision)("git", arguments...)
		},
		"dirty": func(_ string, arguments ...string) ([]byte, error) {
			if strings.Join(arguments, " ") == "diff --quiet" {
				return nil, errors.New("dirty")
			}
			return gitAnswer(readinessRevision)("git", arguments...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := run("v1.2.3", runner); err == nil {
				t.Fatal("run() succeeded for an unsafe release checkout")
			}
		})
	}
}

func TestRunRefusesNonStableTag(t *testing.T) {
	if _, err := run("v1.2.3-rc.1", successfulGit(readinessRevision)); err == nil {
		t.Fatal("run() accepted pre-release tag")
	}
}

func successfulGit(revision string) commandRunner {
	return func(_ string, arguments ...string) ([]byte, error) {
		return gitAnswer(revision)("git", arguments...)
	}
}

func gitAnswer(revision string) commandRunner {
	return func(_ string, arguments ...string) ([]byte, error) {
		switch strings.Join(arguments, " ") {
		case "rev-parse HEAD", "rev-parse refs/heads/main":
			return []byte(revision + "\n"), nil
		case "symbolic-ref --quiet --short HEAD":
			return []byte("main\n"), nil
		case "diff --quiet", "diff --cached --quiet":
			return nil, nil
		default:
			return nil, errors.New("unexpected git command")
		}
	}
}

func workflowNames(report report) string {
	names := make([]string, 0, len(report.RequiredHostedWorkflows))
	for _, workflow := range report.RequiredHostedWorkflows {
		names = append(names, workflow.Name)
	}
	return strings.Join(names, ",")
}
