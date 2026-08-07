package architecture_test

import (
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("public Agent Runtime Go contract", func() {
	It("remains consumable from an independent module without repository workspace state", func() {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		Expect(err).NotTo(HaveOccurred())
		consumer := GinkgoT().TempDir()
		writeConsumerFile(consumer, "go.mod", "module example.com/runtime-consumer\n\ngo 1.26\n\nrequire github.com/0x63616c/agent-runtime v0.0.0\n\nreplace github.com/0x63616c/agent-runtime => "+root+"\n")
		writeConsumerFile(consumer, "main_test.go", `package consumer

import (
    "context"
    "testing"

    agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestPublicRuntimeContract(t *testing.T) {
    sessionID, err := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
    if err != nil {
        t.Fatalf("parse Session ID: %v", err)
    }
    request := agentruntime.SendInputRequest{
        SessionID: sessionID,
        IdempotencyKey: "consumer-input-1",
        Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}},
    }
    if request.SessionID != sessionID {
        t.Fatal("public request did not retain typed Session ID")
    }
    var client agentruntime.Client
    _ = client
    _ = context.Background()
}
`)
		for _, arguments := range [][]string{{"mod", "tidy"}, {"test", "."}} {
			command := exec.Command("go", arguments...)
			command.Dir = consumer
			output, commandErr := command.CombinedOutput()
			Expect(commandErr).NotTo(HaveOccurred(), string(output))
		}
	})

	It("has no Temporal or implementation SDK in its transitive import graph", func() {
		command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./sdk/go")
		command.Dir = filepath.Join("..", "..")
		output, err := command.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(output))
		imports := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, imported := range imports {
			for _, forbidden := range []string{
				"go.temporal.io/",
				"github.com/0x63616c/agent-runtime/internal/",
				"github.com/0x63616c/agent-runtime/sandbox",
				"github.com/0x63616c/agent-runtime/temporalpayload",
				"github.com/jackc/pgx/",
				"github.com/minio/",
			} {
				Expect(imported).NotTo(HavePrefix(forbidden), imported)
			}
		}
	})
})
