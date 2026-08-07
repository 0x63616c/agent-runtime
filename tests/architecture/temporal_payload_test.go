package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Temporal payload composition", func() {
	It("keeps raw Temporal client and remote-codec construction in the private factory seam", func() {
		root := filepath.Join("..", "..")
		allowed := filepath.Join("internal", "temporalpayloadruntime", "factory.go")
		for _, path := range goSourceFiles(root) {
			relative, err := filepath.Rel(root, path)
			Expect(err).NotTo(HaveOccurred())
			if relative == allowed || strings.HasSuffix(relative, "_test.go") {
				continue
			}
			contents, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred(), relative)
			constructors, err := rawTemporalConstructors(path)
			Expect(err).NotTo(HaveOccurred(), relative)
			Expect(constructors).To(BeEmpty(), relative)
			for _, forbidden := range []string{
				"NewRemotePayloadCodec(",
				"NewRemoteDataConverter(",
			} {
				Expect(string(contents)).NotTo(ContainSubstring(forbidden), relative)
			}
		}
	})

	It("rejects every Temporal client constructor even when the package is aliased", func() {
		fixture := filepath.Join("testdata", "temporal_client_constructors.go")
		constructors, err := rawTemporalConstructors(fixture)
		Expect(err).NotTo(HaveOccurred())
		Expect(constructors).To(ConsistOf(
			"client.Dial",
			"client.Dial",
			"client.DialContext",
			"client.NewClient",
			"client.NewClientFromExisting",
			"client.NewClientFromExistingWithContext",
			"client.NewLazyClient",
			"worker.New",
		))
	})

	It("keeps application code from depending on payload representation details", func() {
		root := filepath.Join("..", "..")
		for _, path := range goSourceFiles(root) {
			relative, err := filepath.Rel(root, path)
			Expect(err).NotTo(HaveOccurred())
			if strings.HasPrefix(relative, "temporalpayload"+string(filepath.Separator)) ||
				relative == filepath.Join("internal", "temporalpayloadruntime", "factory.go") ||
				strings.HasSuffix(relative, "_test.go") {
				continue
			}
			contents, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred(), relative)
			Expect(string(contents)).NotTo(ContainSubstring("github.com/0x63616c/agent-runtime/temporalpayload"), relative)
		}
	})

	It("keeps encryption configuration and claims outside the unencrypted codec contract", func() {
		root := filepath.Join("..", "..")
		for _, path := range goSourceFiles(filepath.Join(root, "temporalpayload")) {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			contents, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred(), path)
			for _, forbidden := range []string{"WithEncryption", "EncryptionKey", "KMSKey", "CipherKey"} {
				Expect(string(contents)).NotTo(ContainSubstring(forbidden), path)
			}
		}
		reference, err := os.ReadFile(filepath.Join(root, "docs", "reference", "temporal-payloads.md"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(reference)).To(ContainSubstring("does **not** encrypt payloads"))
	})

	It("remains consumable from an independent Go module", func() {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		Expect(err).NotTo(HaveOccurred())
		consumer := GinkgoT().TempDir()
		writeConsumerFile(consumer, "go.mod", "module example.com/payload-consumer\n\ngo 1.26\n\nrequire github.com/0x63616c/agent-runtime v0.0.0\n\nreplace github.com/0x63616c/agent-runtime => "+root+"\n")
		writeConsumerFile(consumer, "main_test.go", `package consumer

import (
    "testing"

    "github.com/0x63616c/agent-runtime/temporalpayload"
)

func TestPublicPayloadPackage(t *testing.T) {
    store := temporalpayload.NewMemoryBlobStore()
    codec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix("tenant-a"))
    if err != nil || codec == nil {
        t.Fatalf("construct public codec: %v", err)
    }
}
`)
		for _, arguments := range [][]string{{"mod", "tidy"}, {"test", "."}} {
			command := exec.Command("go", arguments...)
			command.Dir = consumer
			output, commandErr := command.CombinedOutput()
			Expect(commandErr).NotTo(HaveOccurred(), string(output))
		}
	})
})

func goSourceFiles(root string) []string {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
		}
		return nil
	})
	Expect(err).NotTo(HaveOccurred())
	return paths
}

func rawTemporalConstructors(path string) ([]string, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		return nil, err
	}
	imports := make(map[string]string)
	for _, imported := range file.Imports {
		pathValue := strings.Trim(imported.Path.Value, "\"")
		name := filepath.Base(pathValue)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		imports[name] = pathValue
	}
	clientConstructors := map[string]bool{
		"Dial": true, "DialContext": true, "NewLazyClient": true, "NewClient": true,
		"NewClientFromExisting": true, "NewClientFromExistingWithContext": true,
	}
	var constructors []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.SelectorExpr:
			packageName, ok := function.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch imports[packageName.Name] {
			case "go.temporal.io/sdk/client":
				if clientConstructors[function.Sel.Name] {
					constructors = append(constructors, "client."+function.Sel.Name)
				}
			case "go.temporal.io/sdk/worker":
				if function.Sel.Name == "New" {
					constructors = append(constructors, "worker.New")
				}
			}
		case *ast.Ident:
			if imports["."] == "go.temporal.io/sdk/client" && clientConstructors[function.Name] {
				constructors = append(constructors, "client."+function.Name)
			}
			if imports["."] == "go.temporal.io/sdk/worker" && function.Name == "New" {
				constructors = append(constructors, "worker.New")
			}
		}
		return true
	})
	sort.Strings(constructors)
	return constructors, nil
}

func writeConsumerFile(directory, name, contents string) {
	Expect(os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600)).To(Succeed())
}
