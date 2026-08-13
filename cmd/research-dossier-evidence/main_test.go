package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const evidenceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestBuildReportIsCurrentRevisionBoundAndExplicitlyLimited(t *testing.T) {
	report := buildReport(evidenceRevision, time.Date(2026, 8, 13, 18, 0, 0, 0, time.UTC))
	if _, err := parse(strings.NewReader(mustJSON(t, report))); err != nil {
		t.Fatalf("parse built report: %v", err)
	}
	if report.Command != "just research-dossier-e2e" || !strings.Contains(report.Limitations[0], "not a Tilt") {
		t.Fatalf("report boundary = %#v", report)
	}
}

func TestParseRejectsWeakOrSecretBearingReport(t *testing.T) {
	base := buildReport(evidenceRevision, time.Date(2026, 8, 13, 18, 0, 0, 0, time.UTC))
	for name, mutate := range map[string]func(*report){
		"short revision": func(report *report) { report.SourceRevision = "abc" },
		"wrong ref":      func(report *report) { report.SourceRef = "refs/heads/feature" },
		"wrong command":  func(report *report) { report.Command = "just two-stack-smoke" },
		"false hosted assertion": func(report *report) {
			report.Assertions[0] = "hosted production proof passed"
		},
		"missing limitation": func(report *report) { report.Limitations = report.Limitations[:1] },
		"secret-bearing statement": func(report *report) {
			report.Assertions[0] = "bearer credential secret dsn api key authorization password token"
		},
		"unsupported schema version": func(report *report) { report.SchemaVersion = "agent-runtime.research-dossier-public-e2e/v2" },
	} {
		t.Run(name, func(t *testing.T) {
			report := base
			report.Assertions = append([]string(nil), base.Assertions...)
			report.Limitations = append([]string(nil), base.Limitations...)
			mutate(&report)
			if _, err := parse(strings.NewReader(mustJSON(t, report))); err == nil {
				t.Fatal("parse() accepted weak report")
			}
		})
	}
}

func TestVerifyCurrentMainBindsTheProofToTheSameCleanRevision(t *testing.T) {
	for name, runner := range map[string]commandRunner{
		"exact clean main": fakeGit(evidenceRevision),
		"wrong head": func(_ string, arguments ...string) ([]byte, error) {
			if strings.HasSuffix(strings.Join(arguments, " "), "rev-parse HEAD") {
				return []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"), nil
			}
			return fakeGit(evidenceRevision)("git", arguments...)
		},
		"dirty": func(_ string, arguments ...string) ([]byte, error) {
			if strings.HasSuffix(strings.Join(arguments, " "), "diff --quiet") {
				return nil, errDirty
			}
			return fakeGit(evidenceRevision)("git", arguments...)
		},
		"untracked": func(_ string, arguments ...string) ([]byte, error) {
			if strings.HasSuffix(strings.Join(arguments, " "), "status --porcelain") {
				return []byte("?? untracked.go\n"), nil
			}
			return fakeGit(evidenceRevision)("git", arguments...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyCurrentMain(".", evidenceRevision, runner)
			if name == "exact clean main" && err != nil {
				t.Fatalf("verifyCurrentMain() error = %v", err)
			}
			if name != "exact clean main" && err == nil {
				t.Fatal("verifyCurrentMain() accepted an unsafe checkout")
			}
		})
	}
}

var errDirty = &dirtyError{}

type dirtyError struct{}

func (*dirtyError) Error() string { return "dirty" }

func fakeGit(revision string) commandRunner {
	return func(_ string, arguments ...string) ([]byte, error) {
		switch {
		case strings.HasSuffix(strings.Join(arguments, " "), "symbolic-ref --quiet --short HEAD"):
			return []byte("main\n"), nil
		case strings.HasSuffix(strings.Join(arguments, " "), "rev-parse HEAD"), strings.HasSuffix(strings.Join(arguments, " "), "rev-parse refs/heads/main"):
			return []byte(revision + "\n"), nil
		case strings.HasSuffix(strings.Join(arguments, " "), "diff --quiet"), strings.HasSuffix(strings.Join(arguments, " "), "diff --cached --quiet"):
			return nil, nil
		case strings.HasSuffix(strings.Join(arguments, " "), "status --porcelain"):
			return nil, nil
		default:
			return nil, errDirty
		}
	}
}

func mustJSON(t *testing.T, report report) string {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return string(encoded)
}
