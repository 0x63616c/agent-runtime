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
				{Output: []byte(namespace)},
				{},
			}}
			adapter, err := stack.NewKubectlAdapter(runner)
			Expect(err).NotTo(HaveOccurred())

			err = adapter.Upgrade(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable", MigrationRoot: root}, rendered, authority)

			Expect(err).NotTo(HaveOccurred())
			Expect(runner.commands).To(HaveLen(6))
			probe := "psql -At -v ON_ERROR_STOP=1 -U " + targetUser + " -d agent_runtime -c SELECT 1"
			Expect(strings.Join(runner.commands[2].arguments, " ")).To(ContainSubstring(probe))
			Expect(strings.Join(runner.commands[3].arguments, " ")).To(ContainSubstring(probe))
			Expect(runner.commands[4].arguments).To(ContainElements("get", "Namespace/ar-feature-a"))
			Expect(strings.Join(runner.commands[5].arguments, " ")).To(ContainSubstring("psql -v ON_ERROR_STOP=1 -U " + targetUser + " -d agent_runtime -f -"))
			Expect(runner.commands[5].input).To(Equal(upgrade))
		}
	})

	It("skips a recorded migration version without replaying its historical schema assertion", func() {
		root := GinkgoT().TempDir()
		v1 := []byte("CREATE SCHEMA IF NOT EXISTS runtime;\n")
		v2 := []byte("CREATE TABLE IF NOT EXISTS runtime.schema_migrations (migration_version bigint primary key);\n")
		for name, contents := range map[string][]byte{"v1.up.sql": v1, "v1.down.sql": []byte("DROP SCHEMA runtime;\n"), "v2.up.sql": v2, "v2.down.sql": []byte("DROP TABLE runtime.schema_migrations;\n")} {
			Expect(os.WriteFile(filepath.Join(root, name), contents, 0o600)).To(Succeed())
		}
		payload := fmt.Sprintf(`{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":%q,"rollback_digest":%q,"upgrade_artifact":"v1.up.sql","rollback_artifact":"v1.down.sql"},{"version":2,"upgrade_digest":%q,"rollback_digest":%q,"upgrade_artifact":"v2.up.sql","rollback_artifact":"v2.down.sql"}]}`,
			migrationDigest(v1), migrationDigest([]byte("DROP SCHEMA runtime;\n")), migrationDigest(v2), migrationDigest([]byte("DROP TABLE runtime.schema_migrations;\n")))
		spec, err := stack.Parse(strings.NewReader(databaseStack(payload)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		authority := stack.BootstrapAuthority{Stack: "feature-a", Profile: stack.ProfileLocal, Namespace: "ar-feature-a", NamespaceUID: "uid-namespace", RenderDigest: rendered.Digest(), Nonce: "private-bootstrap-nonce"}
		namespace := fmt.Sprintf(`{"metadata":{"uid":"uid-namespace","labels":{"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":"feature-a","agent-runtime.dev/profile":"local"},"annotations":{"agent-runtime.dev/bootstrap-nonce-sha256":%q}}}`, authority.NonceDigest())
		runner := &bootstrapRunner{results: []stack.KubectlCommandResult{
			{Output: []byte(namespace)}, {}, {}, {Output: []byte(namespace)}, {},
			{Output: []byte("recorded\n")},
		}}
		adapter, err := stack.NewKubectlAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		Expect(adapter.Upgrade(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable", MigrationRoot: root}, rendered, authority)).To(Succeed())

		Expect(runner.commands).To(HaveLen(6))
		Expect(strings.Join(runner.commands[5].arguments, " ")).To(ContainSubstring("psql -At -v ON_ERROR_STOP=1 -U postgres -d agent_runtime -c SELECT CASE"))
		Expect(string(runner.commands[5].input)).To(BeEmpty())
	})

	It("executes only the removed reviewed migration rollback through an explicit revision transition", func() {
		root := GinkgoT().TempDir()
		v1Upgrade := []byte("CREATE TABLE v1 (id integer primary key);\n")
		v1Rollback := []byte("DROP TABLE v1;\n")
		v2Upgrade := []byte("CREATE TABLE v2 (id integer primary key);\n")
		v2Rollback := []byte("DROP TABLE v2;\n")
		for name, contents := range map[string][]byte{
			"v1.up.sql": v1Upgrade, "v1.down.sql": v1Rollback,
			"v2.up.sql": v2Upgrade, "v2.down.sql": v2Rollback,
		} {
			Expect(os.WriteFile(filepath.Join(root, name), contents, 0o600)).To(Succeed())
		}
		v1 := fmt.Sprintf(`{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":%q,"rollback_digest":%q,"upgrade_artifact":"v1.up.sql","rollback_artifact":"v1.down.sql"}]}`,
			migrationDigest(v1Upgrade), migrationDigest(v1Rollback))
		v2 := strings.TrimSuffix(v1, `]}`) + fmt.Sprintf(`,{"version":2,"upgrade_digest":%q,"rollback_digest":%q,"upgrade_artifact":"v2.up.sql","rollback_artifact":"v2.down.sql"}]}`,
			migrationDigest(v2Upgrade), migrationDigest(v2Rollback))
		previousSpec, err := stack.Parse(strings.NewReader(databaseStack(v1)))
		Expect(err).NotTo(HaveOccurred())
		previous, err := stack.Render(previousSpec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		currentSpec, err := stack.Parse(strings.NewReader(databaseStack(v2)))
		Expect(err).NotTo(HaveOccurred())
		current, err := stack.Render(currentSpec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		authority := stack.BootstrapAuthority{Stack: "feature-a", Profile: stack.ProfileLocal, Namespace: "ar-feature-a", NamespaceUID: "uid-namespace", RenderDigest: previous.Digest(), Nonce: "private-bootstrap-nonce"}
		namespace := fmt.Sprintf(`{"metadata":{"uid":"uid-namespace","labels":{"app.kubernetes.io/part-of":"agent-runtime","agent-runtime.dev/stack":"feature-a","agent-runtime.dev/profile":"local"},"annotations":{"agent-runtime.dev/bootstrap-nonce-sha256":%q}}}`, authority.NonceDigest())
		runner := &bootstrapRunner{results: []stack.KubectlCommandResult{
			{Output: []byte(namespace)}, {}, {}, {Output: []byte(namespace)}, {},
		}}
		adapter, err := stack.NewKubectlAdapter(runner)
		Expect(err).NotTo(HaveOccurred())

		err = adapter.Rollback(context.Background(), stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable", MigrationRoot: root}, current, previous, authority)

		Expect(err).NotTo(HaveOccurred())
		Expect(runner.commands).To(HaveLen(5))
		Expect(string(runner.commands[4].input)).To(Equal(string(v2Rollback)))
		Expect(strings.Join(runner.commands[4].arguments, " ")).To(ContainSubstring("psql -v ON_ERROR_STOP=1 -U postgres -d agent_runtime -f -"))
	})
})

func migrationDigest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return fmt.Sprintf("sha256:%x", sum)
}
