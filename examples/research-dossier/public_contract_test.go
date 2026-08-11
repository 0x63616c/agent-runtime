package researchdossier

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestResearchDossierShippedBinariesUseOnlyPublicRuntimeContracts is the M8
// mechanical EX-004 guard. The application and its command may depend on the
// public SDK and their own package, but never runtime internals, Temporal, or
// object-store implementation clients.
func TestResearchDossierShippedBinariesUseOnlyPublicRuntimeContracts(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./examples/research-dossier", "./examples/research-dossier/cmd/research-dossier")
	command.Dir = repositoryRoot
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list shipped Research Dossier dependencies: %v", err)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if strings.HasPrefix(dependency, "github.com/0x63616c/agent-runtime/internal/") || strings.HasPrefix(dependency, "go.temporal.io/") || strings.HasPrefix(dependency, "github.com/minio/") {
			t.Fatalf("shipped Research Dossier dependency %q bypasses the public runtime SDK", dependency)
		}
	}
}
