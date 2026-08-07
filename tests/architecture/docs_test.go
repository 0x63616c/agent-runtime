package architecture_test

import (
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("public documentation foundation", func() {
	It("locks the current Docusaurus and Node toolchain in the public site root", func() {
		var packageJSON struct {
			PackageManager  string            `json:"packageManager"`
			Engines         map[string]string `json:"engines"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "website", "package.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(json.Unmarshal(data, &packageJSON)).To(Succeed())
		Expect(packageJSON.Engines["node"]).To(Equal("24.19.0"))
		Expect(packageJSON.Engines["npm"]).To(Equal("11.17.0"))
		Expect(packageJSON.PackageManager).To(Equal("npm@11.17.0"))
		Expect(packageJSON.Dependencies["@docusaurus/core"]).To(Equal("3.10.2"))
		Expect(packageJSON.Dependencies["@docusaurus/faster"]).To(Equal("3.10.2"))
		Expect(packageJSON.Dependencies["@docusaurus/preset-classic"]).To(Equal("3.10.2"))
		for dependency, version := range packageJSON.Dependencies {
			if len(dependency) >= len("@docusaurus/") && dependency[:len("@docusaurus/")] == "@docusaurus/" {
				Expect(version).To(Equal("3.10.2"), dependency)
			}
		}
		for dependency, version := range packageJSON.DevDependencies {
			if len(dependency) >= len("@docusaurus/") && dependency[:len("@docusaurus/")] == "@docusaurus/" {
				Expect(version).To(Equal("3.10.2"), dependency)
			}
		}
		Expect(read(".nvmrc")).To(Equal("24.19.0\n"))
		Expect(read("website/package-lock.json")).NotTo(BeEmpty())
	})

	It("declares strict project-site routing and a truthful pre-crawl search state", func() {
		config := read("website/docusaurus.config.ts")
		for _, required := range []string{
			"url: 'https://0x63616c.github.io'",
			"baseUrl: '/agent-runtime/'",
			"onBrokenLinks: 'throw'",
			"onBrokenAnchors: 'throw'",
			"search: false",
		} {
			Expect(config).To(ContainSubstring(required))
		}
		startHere := read("website/docs/start-here/index.mdx")
		Expect(startHere).To(ContainSubstring(":::caution[Implementation status]"))
		Expect(startHere).NotTo(ContainSubstring(":::caution Implementation status"))
	})

	It("declares least-privilege Pages deployment independently of main CI", func() {
		workflow := read(".github/workflows/docs-pages.yml")
		for _, required := range []string{
			"contents: read",
			"pages: write",
			"id-token: write",
			"github-pages",
			"actions/configure-pages@",
			"actions/upload-pages-artifact@",
			"actions/deploy-pages@",
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0",
			"go-version-file: go.mod",
		} {
			Expect(workflow).To(ContainSubstring(required))
		}
		Expect(workflow).NotTo(ContainSubstring("pull_request:"))
		Expect(read(".github/workflows/ci.yml")).NotTo(ContainSubstring("pages: write"))
	})

	It("documents versioning, search privacy and cost, accessibility, permissions, and rollback", func() {
		operations := read("website/docs/help/publication-operations.mdx")
		for _, required := range []string{
			"one current version",
			"Algolia DocSearch",
			"crawler",
			"privacy",
			"accessibility",
			"least-privilege",
			"rollback",
		} {
			Expect(operations).To(ContainSubstring(required))
		}
	})

	It("keeps the documented skill path and real commands aligned", func() {
		agents := read("AGENTS.md")
		skill := read("skills/refresh-agent-runtime-docs/SKILL.md")
		justfile := read("Justfile")
		Expect(agents).To(ContainSubstring("skills/refresh-agent-runtime-docs/SKILL.md"))
		Expect(skill).To(ContainSubstring("just docs-generate"))
		Expect(skill).To(ContainSubstring("just docs-check"))
		Expect(justfile).To(MatchRegexp(`(?m)^docs-generate:`))
		Expect(justfile).To(MatchRegexp(`(?m)^docs-check:`))
		Expect(justfile).To(MatchRegexp(`(?m)^docs:`))
	})
})
