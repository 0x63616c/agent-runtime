package roles_test

import (
	"context"
	"os"
	"path/filepath"

	"github.com/0x63616c/agent-runtime/internal/roles"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Checked-in production role configurations", func() {
	It("compose every declared role with only its reviewed credentials", func() {
		entries, err := os.ReadDir("../../deploy/production/role-configs")
		Expect(err).NotTo(HaveOccurred())
		expectations := map[roles.Role][]string{
			roles.RoleAPI:            {},
			roles.RoleOrchestration:  {"STATE_DATABASE_DSN", "TEMPORAL_AUTH_TOKEN"},
			roles.RoleModel:          {"CONVERSATION_ACCESS_TOKEN", "MODEL_API_KEY"},
			roles.RoleTool:           {"SANDBOX_CONTROL_TOKEN", "TOOL_BROKER_TOKEN"},
			roles.RoleBlob:           {"BLOB_STORAGE_CREDENTIAL"},
			roles.RoleCodec:          {"CODEC_BLOB_CREDENTIAL"},
			roles.RoleSandboxControl: {"SANDBOX_HOST_CA", "SANDBOX_STATE_DSN"},
			roles.RoleSandboxHost:    {"SANDBOX_CONTROL_TOKEN", "SANDBOX_HOST_IDENTITY"},
		}
		Expect(entries).To(HaveLen(len(expectations)))
		for _, entry := range entries {
			file, openErr := os.Open(filepath.Join("../../deploy/production/role-configs", entry.Name()))
			Expect(openErr).NotTo(HaveOccurred(), entry.Name())
			config, parseErr := roles.Parse(file)
			Expect(file.Close()).To(Succeed())
			Expect(parseErr).NotTo(HaveOccurred(), entry.Name())
			plan, prepareErr := roles.Prepare(context.Background(), config, universalFixtureSecrets{})
			Expect(prepareErr).NotTo(HaveOccurred(), entry.Name())
			Expect(plan.SecretEnvironmentNames()).To(ConsistOf(expectations[config.Role()]), entry.Name())
		}
	})
})

type universalFixtureSecrets struct{}

func (universalFixtureSecrets) Lookup(_ context.Context, _ string) (string, bool, error) {
	return "fixture-secret", true, nil
}
