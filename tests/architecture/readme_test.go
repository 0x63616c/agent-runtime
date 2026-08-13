package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("README landing page", func() {
	It("keeps the promise, safety boundary, local start, and release commands visible", func() {
		contents := read("README.md")
		for _, required := range []string{
			"# Agent Runtime",
			"## Safety and evidence boundary",
			"## Architecture",
			"## Five-minute local start",
			"## Commands",
			"## Examples and tutorials",
			"## Documentation, support, and contributing",
			"## License",
			"just check",
			"just docs-check",
			"just verify",
			"docs/planning/requirements-dashboard.html",
			"not Firecracker isolation",
			"https://0x63616c.github.io/agent-runtime/",
		} {
			Expect(contents).To(ContainSubstring(required), required)
		}
	})

	It("keeps the README local-start configuration executable without starting a listener", func() {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		Expect(err).NotTo(HaveOccurred())
		config := filepath.Join(root, "deploy", "runtimeapi", "api.example.json")
		command := exec.Command("go", "run", "./cmd/agent-runtime-api", "--config", config, "--check")
		command.Dir = root
		command.Env = append(os.Environ(),
			"AGENT_RUNTIME_ADMIN_TOKEN=readme-admin-token-0000",
			"AGENT_RUNTIME_DEVELOPER_TOKEN=readme-developer-token-0000",
		)
		output, err := command.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(output))
		Expect(strings.TrimSpace(string(output))).To(BeEmpty())
	})

	It("does not ship broken repository-local README links", func() {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		Expect(err).NotTo(HaveOccurred())
		links := regexp.MustCompile(`\[[^]]+\]\(([^)#]+)(?:#[^)]*)?\)`).FindAllStringSubmatch(read("README.md"), -1)
		Expect(links).NotTo(BeEmpty())
		for _, match := range links {
			target := match[1]
			if strings.Contains(target, "://") {
				continue
			}
			Expect(filepath.IsAbs(target)).To(BeFalse(), target)
			_, err := os.Stat(filepath.Join(root, filepath.FromSlash(target)))
			Expect(err).NotTo(HaveOccurred(), target)
		}
	})
})
