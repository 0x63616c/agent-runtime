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

	It("indexes accepted ADRs and marks external drafts as superseded", func() {
		index := read("docs/adr/README.md")
		matches := regexp.MustCompile(`\]\((\d{4}[^)]+\.md)\)`).FindAllStringSubmatch(index, -1)
		Expect(matches).NotTo(BeEmpty())
		for _, match := range matches {
			Expect(read(filepath.Join("docs/adr", match[1]))).To(ContainSubstring("status: accepted"))
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
		Expect(workflow).To(ContainSubstring("id: incremental"))
		Expect(workflow).To(ContainSubstring("if: always() && steps.incremental.outcome != 'skipped'"))
		Expect(workflow).To(ContainSubstring("-proof-level main_ci"))
		Expect(workflow).To(ContainSubstring("retention-days: 90"))
		Expect(workflow).NotTo(ContainSubstring("continue-on-error: true"))
		Expect(workflow).NotTo(ContainSubstring("Halt on red main"))
		Expect(workflow).NotTo(ContainSubstring("pull_request:"))
	})
})

func read(path string) string {
	data, err := os.ReadFile(filepath.Join("..", "..", path))
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), path)
	return string(data)
}
