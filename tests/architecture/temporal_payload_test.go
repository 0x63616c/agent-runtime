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
			constructors, err := rawTemporalSymbols(path)
			Expect(err).NotTo(HaveOccurred(), relative)
			Expect(constructors).To(BeEmpty(), relative)
		}
	})

	It("rejects every Temporal client constructor even when the package is aliased", func() {
		fixture := filepath.Join("testdata", "temporal_client_constructors.go")
		constructors, err := rawTemporalSymbols(fixture)
		Expect(err).NotTo(HaveOccurred())
		Expect(constructors).To(ConsistOf(
			"client.Dial",
			"client.DialContext",
			"client.NewClient",
			"client.NewClientFromExisting",
			"client.NewClientFromExistingWithContext",
			"client.NewLazyClient",
			"client.NewNamespaceClient",
			"worker.New",
		))
	})

	It("rejects remote codec constructors used through aliases and dot imports", func() {
		fixture := filepath.Join("testdata", "temporal_remote_codec_constructors.go")
		constructors, err := rawTemporalSymbols(fixture)
		Expect(err).NotTo(HaveOccurred())
		Expect(constructors).To(ConsistOf(
			"converter.NewRemoteDataConverter",
			"converter.NewRemotePayloadCodec",
		))
	})

	It("keeps application code from depending on payload representation details", func() {
		root := filepath.Join("..", "..")
		uiProcess := filepath.Join("internal", "temporalpayloaduiprocess", "run.go")
		for _, path := range goSourceFiles(root) {
			relative, err := filepath.Rel(root, path)
			Expect(err).NotTo(HaveOccurred())
			if strings.HasPrefix(relative, "temporalpayload"+string(filepath.Separator)) ||
				relative == filepath.Join("internal", "temporalpayloadruntime", "factory.go") ||
				relative == uiProcess ||
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

func rawTemporalSymbols(path string) ([]string, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		return nil, err
	}
	imports := make(map[string]string)
	var dotImports []string
	for _, imported := range file.Imports {
		pathValue := strings.Trim(imported.Path.Value, "\"")
		name := filepath.Base(pathValue)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		if name == "." {
			dotImports = append(dotImports, pathValue)
			continue
		}
		imports[name] = pathValue
	}
	forbiddenByImport := map[string]map[string]string{
		"go.temporal.io/sdk/client": {
			"Dial": "client.Dial", "DialContext": "client.DialContext", "NewLazyClient": "client.NewLazyClient",
			"NewClient": "client.NewClient", "NewClientFromExisting": "client.NewClientFromExisting",
			"NewClientFromExistingWithContext": "client.NewClientFromExistingWithContext",
			"NewNamespaceClient":               "client.NewNamespaceClient",
		},
		"go.temporal.io/sdk/worker": {
			"New": "worker.New",
		},
		"go.temporal.io/sdk/converter": {
			"NewRemotePayloadCodec":  "converter.NewRemotePayloadCodec",
			"NewRemoteDataConverter": "converter.NewRemoteDataConverter",
		},
	}
	var constructors []string
	ast.Inspect(file, func(node ast.Node) bool {
		switch function := node.(type) {
		case *ast.SelectorExpr:
			packageName, ok := function.X.(*ast.Ident)
			if !ok {
				return true
			}
			if symbol := forbiddenByImport[imports[packageName.Name]][function.Sel.Name]; symbol != "" {
				constructors = append(constructors, symbol)
			}
			return false
		case *ast.Ident:
			for _, importPath := range dotImports {
				if symbol := forbiddenByImport[importPath][function.Name]; symbol != "" {
					constructors = append(constructors, symbol)
				}
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
