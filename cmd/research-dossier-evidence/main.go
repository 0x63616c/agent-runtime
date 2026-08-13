// Command research-dossier-evidence records and validates the bounded report
// produced only after the Research Dossier public E2E has passed.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const schemaVersion = "agent-runtime.research-dossier-public-e2e/v1"

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var (
	requiredDependencies = []string{"disposable PostgreSQL", "disposable MinIO", "disposable Temporal dev server"}
	requiredPublicPaths  = []string{"public HTTP/Go SDK", "shipped terminal binary", "loopback web binary"}
	requiredAssertions   = []string{"three ordered approval-gated research tool operations retain public artifacts", "public cursor resume survives runtime API restart", "terminal and loopback web clients list and download the recovered artifacts", "the final public artifact exceeds 512 KiB and preserves its cited source"}
	requiredLimitations  = []string{"This is a disposable local integration proof, not a Tilt, Kubernetes, hosted CI, production provider, Linux/KVM, or Firecracker claim.", "Private model, tool, and orchestration adapters are deterministic test seams; the public application uses only HTTP and the public Go SDK."}
)

type report struct {
	SchemaVersion  string   `json:"schema_version"`
	Result         string   `json:"result"`
	SourceRevision string   `json:"source_revision"`
	SourceRef      string   `json:"source_ref"`
	CompletedAt    string   `json:"completed_at"`
	Command        string   `json:"command"`
	Dependencies   []string `json:"dependencies"`
	PublicPaths    []string `json:"public_paths"`
	Assertions     []string `json:"assertions"`
	Limitations    []string `json:"limitations"`
}

func main() {
	mode := flag.String("mode", "validate", "validate or record")
	file := flag.String("file", "", "report file to validate or write")
	revision := flag.String("revision", "", "exact source revision for record")
	repositoryRoot := flag.String("repository-root", ".", "clean main checkout that ran the proof")
	completedAt := flag.String("completed-at", "", "RFC3339 UTC completion timestamp for record")
	flag.Parse()
	if flag.NArg() != 0 || *file == "" {
		fail(errors.New("usage: research-dossier-evidence -mode validate|record -file path"))
	}
	switch *mode {
	case "validate":
		input, err := os.Open(*file)
		if err != nil {
			fail(fmt.Errorf("open report: %w", err))
		}
		defer func() { _ = input.Close() }()
		if _, err := parse(input); err != nil {
			fail(err)
		}
	case "record":
		if err := verifyCurrentMain(*repositoryRoot, *revision, runCommand); err != nil {
			fail(err)
		}
		completed, err := time.Parse(time.RFC3339, *completedAt)
		if err != nil {
			fail(fmt.Errorf("parse completed-at: %w", err))
		}
		encoded, err := json.Marshal(buildReport(*revision, completed))
		if err != nil {
			fail(fmt.Errorf("encode report: %w", err))
		}
		if _, err := parse(strings.NewReader(string(encoded))); err != nil {
			fail(err)
		}
		if err := os.WriteFile(*file, append(encoded, '\n'), 0o600); err != nil {
			fail(fmt.Errorf("write report: %w", err))
		}
	default:
		fail(errors.New("mode must be validate or record"))
	}
}

func buildReport(revision string, completed time.Time) report {
	return report{
		SchemaVersion:  schemaVersion,
		Result:         "passed",
		SourceRevision: revision,
		SourceRef:      "refs/heads/main",
		CompletedAt:    completed.UTC().Format(time.RFC3339),
		Command:        "just research-dossier-e2e",
		Dependencies:   requiredDependencies,
		PublicPaths:    requiredPublicPaths,
		Assertions:     requiredAssertions,
		Limitations:    requiredLimitations,
	}
}

func parse(input io.Reader) (report, error) {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var value report
	if err := decoder.Decode(&value); err != nil {
		return report{}, fmt.Errorf("decode report: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return report{}, errors.New("decode report: must contain exactly one JSON value")
	}
	if value.SchemaVersion != schemaVersion || value.Result != "passed" {
		return report{}, errors.New("report must declare the supported schema and passed result")
	}
	if !revisionPattern.MatchString(value.SourceRevision) {
		return report{}, errors.New("report source_revision must be a full lowercase git revision")
	}
	if value.SourceRef != "refs/heads/main" {
		return report{}, errors.New("report source_ref must be refs/heads/main")
	}
	completed, err := time.Parse(time.RFC3339, value.CompletedAt)
	if err != nil || !strings.HasSuffix(value.CompletedAt, "Z") || !completed.Equal(completed.UTC()) {
		return report{}, errors.New("report completed_at must be an RFC3339 UTC timestamp")
	}
	if value.Command != "just research-dossier-e2e" {
		return report{}, errors.New("report must name the reviewed public E2E command")
	}
	if !sameStrings(value.Dependencies, requiredDependencies) ||
		!sameStrings(value.PublicPaths, requiredPublicPaths) ||
		!sameStrings(value.Assertions, requiredAssertions) ||
		!sameStrings(value.Limitations, requiredLimitations) {
		return report{}, errors.New("report has an incomplete evidence boundary")
	}
	for _, field := range append(append([]string{}, value.Assertions...), value.Limitations...) {
		lower := strings.ToLower(field)
		if strings.TrimSpace(field) == "" || containsSensitiveTerm(lower) {
			return report{}, errors.New("report must contain bounded redacted statements")
		}
	}
	return value, nil
}

func containsSensitiveTerm(value string) bool {
	for _, term := range []string{"token", "password", "secret", "bearer", "authorization", "credential", "dsn", "api key"} {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

type commandRunner func(string, ...string) ([]byte, error)

func runCommand(name string, arguments ...string) ([]byte, error) {
	return exec.Command(name, arguments...).Output()
}

// verifyCurrentMain closes the report-binding window: the caller captures the
// expected revision before executing the proof, then this verifies that the
// same clean main checkout still exists immediately before report emission.
func verifyCurrentMain(root, expectedRevision string, run commandRunner) error {
	if !revisionPattern.MatchString(expectedRevision) {
		return errors.New("expected revision must be a full lowercase git revision")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	git := func(arguments ...string) (string, error) {
		output, commandErr := run("git", append([]string{"-C", absRoot}, arguments...)...)
		if commandErr != nil {
			return "", fmt.Errorf("run git %s: %w", strings.Join(arguments, " "), commandErr)
		}
		return strings.TrimSpace(string(output)), nil
	}
	branch, err := git("symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || branch != "main" {
		return errors.New("report requires a clean checkout on main")
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil || head != expectedRevision {
		return errors.New("report checkout head differs from the revision that ran the proof")
	}
	main, err := git("rev-parse", "refs/heads/main")
	if err != nil || main != expectedRevision {
		return errors.New("report checkout main differs from the revision that ran the proof")
	}
	if _, err := git("diff", "--quiet"); err != nil {
		return errors.New("report requires a clean working tree")
	}
	if _, err := git("diff", "--cached", "--quiet"); err != nil {
		return errors.New("report requires a clean index")
	}
	status, err := git("status", "--porcelain")
	if err != nil || status != "" {
		return errors.New("report requires no untracked or modified files")
	}
	return nil
}

func sameStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "research-dossier-evidence:", err)
	os.Exit(1)
}
