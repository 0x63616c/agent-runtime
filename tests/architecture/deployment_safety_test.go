package architecture_test

import (
	"os"
	"path/filepath"

	"github.com/0x63616c/agent-runtime/internal/afkevidence"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("M1 deployment safety boundaries", func() {
	It("uses audited bootstrap and teardown with generated file-backed smoke credentials", func() {
		script := read("deploy/production/run-kubernetes-smoke.sh")
		for _, required := range []string{
			`AGENT_RUNTIME_SMOKE_KUBECONFIG:?`,
			`AGENT_RUNTIME_SMOKE_CONTEXT:?`,
			`AGENT_RUNTIME_SMOKE_AUDIT:?`,
			`AGENT_RUNTIME_SMOKE_EVIDENCE:?`,
			`profile="local"`,
			`stackctl" bootstrap`,
			`stackctl" apply`,
			`stackctl" teardown`,
			`mktemp -d`,
			`openssl rand -hex 32`,
			`tr -d '\n'`,
			`--from-file=`,
			`create -f -`,
			`stackctl" reconcile`,
		} {
			Expect(script).To(ContainSubstring(required))
		}
		for _, forbidden := range []string{
			"delete namespace",
			"--from-literal",
			"fixture-password",
			"minioadmin",
			`SMOKE_CONTEXT:-`,
			`apply -f -`,
		} {
			Expect(script).NotTo(ContainSubstring(forbidden))
		}
	})

	It("validates every AFK record and keeps integration-specific evidence outside that schema", func() {
		paths, err := filepath.Glob(filepath.Join("..", "..", "evidence", "afk", "*.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).NotTo(BeEmpty())
		for _, path := range paths {
			file, openErr := os.Open(path)
			Expect(openErr).NotTo(HaveOccurred(), path)
			_, parseErr := afkevidence.Parse(file)
			Expect(file.Close()).To(Succeed())
			Expect(parseErr).NotTo(HaveOccurred(), path)
		}
		_, err = os.Stat(filepath.Join("..", "..", "evidence", "afk", "m1-self-hosted-runtime.json"))
		Expect(os.IsNotExist(err)).To(BeTrue())
		Expect(read("evidence/issue-14-deployment-e2e.json")).To(ContainSubstring(`"milestone": "M1 self-hosted roles and deployment"`))
		Expect(read("Justfile")).To(ContainSubstring(`for evidence_file in evidence/afk/*.json`))
	})

	It("keeps repository-reading deployment assertions out of product package tests", func() {
		_, err := os.Stat(filepath.Join("..", "..", "internal", "roles", "production_stack_test.go"))
		Expect(os.IsNotExist(err)).To(BeTrue())
		Expect(read("tests/architecture/production_stack_test.go")).To(ContainSubstring("Self-hosted production Stack"))
	})
})
