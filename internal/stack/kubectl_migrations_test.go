package stack_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Kubectl migrations", func() {
	It("retries readiness and uses each target workload's declared PostgreSQL user", func() {
		for _, targetUser := range []string{"postgres", "temporal"} {
			root := GinkgoT().TempDir()
			upgrade := []byte("CREATE TABLE readiness_probe (id integer primary key);\n")
			rollback := []byte("DROP TABLE readiness_probe;\n")
			Expect(os.WriteFile(filepath.Join(root, "v1.up.sql"), upgrade, 0o600)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(root, "v1.down.sql"), rollback, 0o600)).To(Succeed())
			payload := fmt.Sprintf(`{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":%q,"rollback_digest":%q,"upgrade_artifact":"v1.up.sql","rollback_artifact":"v1.down.sql"}]}`,
				migrationDigest(upgrade), migrationDigest(rollback))
			document := databaseStack(payload)
			if targetUser != "postgres" {
				document = strings.ReplaceAll(document, `"service_account":"runtime-api","readiness"`, `"service_account":"runtime-api","environment":[{"name":"POSTGRES_USER","value":"temporal"}],"readiness"`)
			}
			spec, err := stack.Parse(strings.NewReader(document))
			Expect(err).NotTo(HaveOccurred())
			rendered, err := stack.Render(spec, stack.ProfileLocal)
			Expect(err).NotTo(HaveOccurred())
			authority := stack.BootstrapAuthority{Stack: "feature-a", Profile: stack.ProfileLocal, Namespace: "ar-feature-a", NamespaceUID: "uid-namespace", RenderDigest: rendered.Digest(), Nonce: "private-bootstrap-nonce"}
			namespace := fmt.Sprintf(`{"metadata":{"uid":"uid-namespace","labels":{"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":"feature-a","agent-runtime.dev/profile":"local"},"annotations":{"agent-runtime.dev/bootstrap-nonce-sha256":%q}}}`, authority.NonceDigest())
			runner := &bootstrapRunner{results: []stack.KubectlCommandResult{
				{Output: []byte(namespace)},
				{},
				{ExitCode: 2},
				{},
				{},
			}}
			adapter, err := stack.NewKubectlAdapter(runner)
			Expect(err).NotTo(HaveOccurred())

			err = adapter.Upgrade(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable", MigrationRoot: root}, rendered, authority)

			Expect(err).NotTo(HaveOccurred())
			Expect(runner.commands).To(HaveLen(5))
			probe := "psql -At -v ON_ERROR_STOP=1 -U " + targetUser + " -d agent_runtime -c SELECT 1"
			Expect(strings.Join(runner.commands[2].arguments, " ")).To(ContainSubstring(probe))
			Expect(strings.Join(runner.commands[3].arguments, " ")).To(ContainSubstring(probe))
			Expect(strings.Join(runner.commands[4].arguments, " ")).To(ContainSubstring("psql -v ON_ERROR_STOP=1 -U " + targetUser + " -d agent_runtime -f -"))
			Expect(runner.commands[4].input).To(Equal(upgrade))
		}
	})
})

func migrationDigest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return fmt.Sprintf("sha256:%x", sum)
}
