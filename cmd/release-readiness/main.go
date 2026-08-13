// Command release-readiness writes the immutable release hand-off for the
// current clean main checkout. It has no network client and never tags,
// publishes, deploys, or records evidence.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	repository        = "0x63616c/agent-runtime"
	publicDocsBaseURL = "https://0x63616c.github.io/agent-runtime"
)

type commandRunner func(string, ...string) ([]byte, error)

type report struct {
	SchemaVersion           string           `json:"schema_version"`
	Result                  string           `json:"result"`
	Repository              string           `json:"repository"`
	ReleaseTag              string           `json:"release_tag"`
	SourceRevision          string           `json:"source_revision"`
	SourceRef               string           `json:"source_ref"`
	RequiredLocalGates      []localGate      `json:"required_local_gates"`
	RequiredHostedWorkflows []hostedWorkflow `json:"required_hosted_workflows"`
	PublicDocsVerification  docsVerification `json:"public_docs_verification"`
	ReleaseAssets           []releaseAsset   `json:"release_assets"`
	ExternalActions         []externalAction `json:"external_actions"`
}

type localGate struct {
	Command string `json:"command"`
	Purpose string `json:"purpose"`
}

type hostedWorkflow struct {
	Name     string `json:"name"`
	Required string `json:"required"`
}

type docsVerification struct {
	BaseURL string `json:"base_url"`
	Command string `json:"command"`
}

type releaseAsset struct {
	Name        string `json:"name"`
	Expectation string `json:"expectation"`
}

type externalAction struct {
	Order  int    `json:"order"`
	Action string `json:"action"`
}

func main() {
	tag := flag.String("tag", "", "required immutable semantic-version release tag, for example v1.0.0")
	flag.Parse()
	if flag.NArg() != 0 || *tag == "" {
		fmt.Fprintln(os.Stderr, "usage: release-readiness -tag vX.Y.Z")
		os.Exit(2)
	}
	result, err := run(*tag, runCommand)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-readiness:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "release-readiness: write report:", err)
		os.Exit(1)
	}
}

func run(tag string, command commandRunner) (report, error) {
	if !semverTag.MatchString(tag) {
		return report{}, errors.New("tag must be an exact stable semantic-version tag in the form vX.Y.Z")
	}
	revision, err := cleanMainRevision(command)
	if err != nil {
		return report{}, err
	}
	return buildReport(tag, revision), nil
}

func buildReport(tag, revision string) report {
	docsCommand := fmt.Sprintf("go run ./cmd/docs-publication-verify -base-url %s -expected-sha %s -require-source-sha-marker", publicDocsBaseURL, revision)
	return report{
		SchemaVersion:  "agent-runtime.release-readiness/v1",
		Result:         "external-release-actions-required",
		Repository:     repository,
		ReleaseTag:     tag,
		SourceRevision: revision,
		SourceRef:      "refs/heads/main",
		RequiredLocalGates: []localGate{
			{Command: "just verify", Purpose: "proves the complete canonical ledger at this exact revision"},
			{Command: "just docs-check", Purpose: "proves checked-in documentation sources and production build inputs"},
		},
		RequiredHostedWorkflows: []hostedWorkflow{
			{Name: "main-ci", Required: "successful run for this exact source revision"},
			{Name: "documentation-pages", Required: "successful build and Pages deployment for this exact source revision"},
			{Name: "firecracker-kvm", Required: "successful protected Linux/x86_64/KVM evidence run for this exact source revision"},
			{Name: "runtime-operations-drill", Required: "successful protected database, audit, and PITR drill retained for this exact source revision"},
			{Name: "publish-production-image", Required: "successful immutable multi-architecture image publication with provenance and SBOM for this exact source revision"},
		},
		PublicDocsVerification: docsVerification{BaseURL: publicDocsBaseURL, Command: docsCommand},
		ReleaseAssets: []releaseAsset{
			{Name: "source archive", Expectation: "GitHub release source archive for " + tag + " resolves to " + revision},
			{Name: "root Go module", Expectation: "github.com/0x63616c/agent-runtime@" + tag + " is consumable without go.work"},
			{Name: "production container", Expectation: "ghcr.io/0x63616c/agent-runtime:" + revision + " has immutable digest, provenance, and SBOM"},
			{Name: "release notes", Expectation: "public notes identify " + tag + ", " + revision + ", compatibility decision, and evidence links without secrets"},
		},
		ExternalActions: []externalAction{
			{Order: 1, Action: "Confirm every listed hosted workflow succeeded for source_revision; do not treat a different SHA, skipped job, or queued job as success."},
			{Order: 2, Action: "Run public_docs_verification.command after Pages deployment and retain its bounded output."},
			{Order: 3, Action: "Create the immutable GitHub release and tag only after the preceding evidence is green; this command does not create either."},
			{Order: 4, Action: "From a clean external consumer with GOWORK=off, fetch release_tag and compile the public SDK and temporalpayload packages."},
			{Order: 5, Action: "Independently verify release assets, image digest, provenance, SBOM, and retained evidence links; then send and retain the redacted final status notification."},
		},
	}
}

func cleanMainRevision(command commandRunner) (string, error) {
	if command == nil {
		return "", errors.New("command runner is required")
	}
	head, err := command("git", "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("read HEAD: %w", err)
	}
	main, err := command("git", "rev-parse", "refs/heads/main")
	if err != nil {
		return "", fmt.Errorf("read main revision: %w", err)
	}
	revision := strings.TrimSpace(string(head))
	if !validSHA(revision) || revision != strings.TrimSpace(string(main)) {
		return "", errors.New("HEAD must be the exact current refs/heads/main revision")
	}
	branch, err := command("git", "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || strings.TrimSpace(string(branch)) != "main" {
		return "", errors.New("checkout must be attached to main")
	}
	for _, arguments := range [][]string{{"diff", "--quiet"}, {"diff", "--cached", "--quiet"}} {
		if _, err := command("git", arguments...); err != nil {
			return "", errors.New("checkout must be clean before release readiness")
		}
	}
	return revision, nil
}

func runCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func validSHA(value string) bool {
	return len(value) == 40 && strings.Trim(value, "0123456789abcdef") == ""
}

var semverTag = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
