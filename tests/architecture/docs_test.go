package architecture_test

import (
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("public documentation foundation", func() {
	It("locks the Astro Starlight and Node toolchain in the public site root", func() {
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
		Expect(packageJSON.Dependencies["astro"]).To(Equal("7.2.0"))
		Expect(packageJSON.Dependencies["@astrojs/starlight"]).To(Equal("0.41.7"))
		Expect(packageJSON.DevDependencies["@astrojs/check"]).To(Equal("0.9.10"))
		Expect(packageJSON.Dependencies).NotTo(HaveKey("@docusaurus/core"))
		Expect(read(".nvmrc")).To(Equal("24.19.0\n"))
		Expect(read("website/package-lock.json")).NotTo(BeEmpty())
	})

	It("declares project-site routing, Starlight navigation, Pagefind search, and legacy redirects", func() {
		config := read("website/astro.config.mjs")
		for _, required := range []string{
			"site: 'https://0x63616c.github.io'",
			"base: '/agent-runtime'",
			"trailingSlash: 'never'",
			"starlight({",
			"docs/start-here",
			"docs/reference/sandbox-host-control",
			"'/start-here': '/docs/start-here'",
		} {
			Expect(config).To(ContainSubstring(required))
		}
		startHere := read("website/src/content/docs/docs/start-here/index.mdx")
		Expect(startHere).To(ContainSubstring(":::caution[Implementation status]"))
		Expect(startHere).NotTo(ContainSubstring(":::caution Implementation status"))
		routes := read("website/route-manifest.json")
		Expect(routes).To(ContainSubstring("/docs/start-here"))
		Expect(routes).To(ContainSubstring("/start-here"))
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
			"path: website/dist",
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0",
			"go-version-file: go.mod",
		} {
			Expect(workflow).To(ContainSubstring(required))
		}
		Expect(workflow).NotTo(ContainSubstring("pull_request:"))
		Expect(read(".github/workflows/ci.yml")).NotTo(ContainSubstring("pages: write"))
	})

	It("documents versioning, local search, accessibility, permissions, rollback, and the clean audit policy", func() {
		operations := read("website/src/content/docs/docs/help/publication-operations.mdx")
		for _, required := range []string{
			"one current version",
			"Pagefind",
			"third-party crawler",
			"privacy",
			"accessibility",
			"least-privilege",
			"rollback",
			"npm audit --omit=dev --audit-level=high",
		} {
			Expect(operations).To(ContainSubstring(required))
		}
	})

	It("keeps the documented skill path, source manifest, and real commands aligned", func() {
		agents := read("AGENTS.md")
		skill := read("skills/refresh-agent-runtime-docs/SKILL.md")
		justfile := read("Justfile")
		Expect(agents).To(ContainSubstring("skills/refresh-agent-runtime-docs/SKILL.md"))
		Expect(skill).To(ContainSubstring("just docs-generate"))
		Expect(skill).To(ContainSubstring("just docs-check"))
		Expect(justfile).To(MatchRegexp(`(?m)^docs-generate:`))
		Expect(justfile).To(MatchRegexp(`(?m)^docs-check:`))
		Expect(justfile).To(MatchRegexp(`(?m)^docs:`))
		Expect(justfile).To(ContainSubstring("npm --prefix website run check:routes"))
	})

	It("publishes the private host-control boundary through Starlight navigation and refresh inventory", func() {
		config := read("website/astro.config.mjs")
		manifestContents := read("skills/refresh-agent-runtime-docs/source-manifest.json")
		page := read("website/src/content/docs/docs/reference/sandbox-host-control.mdx")
		inventory := read("website/src/content/docs/docs/reference/generated/source-inventory.mdx")
		var manifest struct {
			Generated []struct {
				Output string   `json:"output"`
				Inputs []string `json:"inputs"`
			} `json:"generated"`
		}

		Expect(json.Unmarshal([]byte(manifestContents), &manifest)).To(Succeed())
		var inventoryInputs []string
		for _, artifact := range manifest.Generated {
			if artifact.Output == "website/src/content/docs/docs/reference/generated/source-inventory.mdx" {
				inventoryInputs = artifact.Inputs
			}
		}

		Expect(config).To(ContainSubstring("docs/reference/sandbox-host-control"))
		Expect(inventoryInputs).To(ContainElement("website/src/content/docs/docs/reference/sandbox-host-control.mdx"))
		Expect(inventory).To(ContainSubstring("`website/src/content/docs/docs/reference/sandbox-host-control.mdx`"))
		Expect(page).To(ContainSubstring("host topology out of its public Go and HTTP contracts"))
	})

	It("publishes generated OpenAPI operations from the declared contract", func() {
		config := read("website/astro.config.mjs")
		manifestContents := read("skills/refresh-agent-runtime-docs/source-manifest.json")
		page := read("website/src/content/docs/docs/reference/generated/http-operations.mdx")
		var manifest struct {
			Generated []struct {
				Output string   `json:"output"`
				Inputs []string `json:"inputs"`
				Kind   string   `json:"artifactKind"`
			} `json:"generated"`
		}

		Expect(json.Unmarshal([]byte(manifestContents), &manifest)).To(Succeed())
		Expect(config).To(ContainSubstring("docs/reference/generated/http-operations"))
		Expect(manifest.Generated).To(ContainElement(And(
			HaveField("Output", "website/src/content/docs/docs/reference/generated/http-operations.mdx"),
			HaveField("Inputs", []string{"api/openapi/openapi.yaml"}),
			HaveField("Kind", "openapi-operation-index"),
		)))
		Expect(page).To(ContainSubstring("# HTTP operation index"))
		Expect(page).To(ContainSubstring("`createSession`"))
	})
})
