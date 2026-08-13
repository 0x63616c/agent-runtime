package architecture_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestArchitecture(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Architecture Governance Suite")
}

var _ = Describe("binding governance", func() {
	It("keeps the mandatory engineering provenance and direct-main contract", func() {
		agents := read("AGENTS.md")
		for _, required := range []string{
			"Legibility > Correctness > Operability > Economy",
			"docs/planning/requirements/master-requirements.md",
			"CONTEXT.md",
			"docs/adr/",
			"skills/refresh-agent-runtime-docs/SKILL.md",
			"just check",
			"Direct-main AFK policy",
			"silently down-scope an uncompleted requirement",
		} {
			Expect(agents).To(ContainSubstring(required))
		}
	})

	It("keeps every binding public concept in the implementation-free glossary", func() {
		context := read("CONTEXT.md")
		for _, term := range []string{"Agent specification", "Session", "Turn", "Input", "Model invocation", "Tool call", "Tool execution", "Policy", "Capability grant", "Capability profile", "Sandbox", "Operation", "Approval", "Artifact", "Product event", "Cursor", "Audit record"} {
			Expect(context).To(MatchRegexp(`(?m)^\*\*` + regexp.QuoteMeta(term) + `\*\*:`))
		}
		Expect(context).NotTo(ContainSubstring("github.com/"))
	})

	It("indexes accepted and superseded ADRs explicitly", func() {
		index := read("docs/adr/README.md")
		matches := regexp.MustCompile(`\]\((\d{4}[^)]+\.md)\)`).FindAllStringSubmatch(index, -1)
		Expect(matches).NotTo(BeEmpty())
		for _, match := range matches {
			decision := read(filepath.Join("docs/adr", match[1]))
			if match[1] == "0010-documentation-deployment.md" || match[1] == "0013-temporary-documentation-audit-exception.md" {
				Expect(decision).To(ContainSubstring("status: superseded"))
				continue
			}
			Expect(decision).To(ContainSubstring("status: accepted"))
		}
		architecture := read("docs/architecture/system.md")
		Expect(architecture).To(ContainSubstring("Status: accepted M0 architecture"))
		Expect(architecture).To(ContainSubstring("only binding implementation contract"))
		Expect(architecture).To(ContainSubstring("superseded"))
	})

	It("documents contributor, configuration, evidence, compatibility, and generated ownership policy", func() {
		for _, path := range []string{"CONTRIBUTING.md", "docs/reference/configuration.md", "docs/operations/direct-main.md", "docs/operations/evidence-and-status.md", "docs/engineering/go-compatibility.md", "docs/engineering/generated-ownership.md", "docs/engineering/testing.md"} {
			Expect(read(path)).NotTo(BeEmpty(), path)
		}
	})

	It("retains main-CI evidence while preserving the incremental gate outcome", func() {
		workflow := read(".github/workflows/ci.yml")
		Expect(workflow).To(ContainSubstring("Install pinned Linux lint tool"))
		Expect(workflow).To(ContainSubstring("github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2"))
		Expect(workflow).To(ContainSubstring("run: just check"))
		Expect(workflow).NotTo(ContainSubstring("golangci-lint-action"))
		Expect(workflow).To(ContainSubstring("id: incremental"))
		Expect(workflow).To(ContainSubstring("if: always() && steps.incremental.outcome != 'skipped'"))
		Expect(workflow).To(ContainSubstring("-proof-level main_ci"))
		Expect(workflow).To(ContainSubstring("retention-days: 90"))
		Expect(workflow).NotTo(ContainSubstring("continue-on-error: true"))
		Expect(workflow).NotTo(ContainSubstring("Halt on red main"))
		Expect(workflow).NotTo(ContainSubstring("pull_request:"))
	})

	It("publishes the minimal production image from a sealed source context", func() {
		workflow := read(".github/workflows/publish-production-image.yml")
		required := []string{
			"branches: [main]",
			"contents: read",
			"packages: write",
			"attestations: write",
			"id-token: write",
			"docker/setup-buildx-action@e468171a9de216ec08956ac3ada2f0791b6bd435 # v3.11.1",
			"docker/login-action@74a5d142397b4f367a81961eba4e8cd7edddf772 # v3.4.0",
			"docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83 # v6.18.0",
			"actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a # v3.0.0",
			"file: deploy/production/Dockerfile",
			"platforms: linux/amd64,linux/arm64",
			"push: true",
			"provenance: mode=max",
			"sbom: true",
			"subject-digest: ${{ steps.build.outputs.digest }}",
		}
		for _, required := range required {
			Expect(workflow).To(ContainSubstring(required))
		}
		// The image is revision-addressed, so a fragile partial path allowlist
		// cannot safely decide which main commits need an image publication.
		Expect(workflow).NotTo(ContainSubstring("    paths:"))
		Expect(workflow).NotTo(ContainSubstring("    paths-ignore:"))
		Expect(workflow).NotTo(ContainSubstring("pull_request:"))

		contextIgnore := read(".dockerignore")
		for _, excluded := range []string{"deploy/", "docs/", "website/", "evidence/"} {
			Expect(contextIgnore).To(ContainSubstring(excluded))
		}
		Expect(contextIgnore).To(ContainSubstring("!temporalpayload/**"))
		Expect(contextIgnore).To(ContainSubstring("!cmd/agent-runtime-api/**"))
		Expect(contextIgnore).To(ContainSubstring("!internal/**"))
		Expect(contextIgnore).To(ContainSubstring("!sandbox/**"))
		Expect(contextIgnore).To(ContainSubstring("!sdk/**"))
		dockerfile := read("deploy/production/Dockerfile")
		for _, required := range []string{
			"COPY internal ./internal",
			"COPY sandbox ./sandbox",
			"COPY temporalpayload ./temporalpayload",
			"COPY sdk ./sdk",
			"COPY cmd/agent-runtime-api ./cmd/agent-runtime-api",
			"/out/agent-runtime-api ./cmd/agent-runtime-api",
			"go build -mod=readonly",
		} {
			Expect(dockerfile).To(ContainSubstring(required))
		}
	})

	It("keeps the documented Stack image and role handoff reviewable", func() {
		document := read("docs/operations/self-hosted-deployment.md")
		Expect(document).To(ContainSubstring("jq -c '.orchestration')"))
		Expect(document).To(ContainSubstring("--role orchestration --check"))
		Expect(document).To(ContainSubstring("publish and attest the exact source SHA"))
		Expect(document).To(ContainSubstring("reviewed Stack change must pin that new immutable digest"))
	})
})

func read(path string) string {
	data, err := os.ReadFile(filepath.Join("..", "..", path))
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), path)
	return string(data)
}
