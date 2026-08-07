package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
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
			for _, forbidden := range []string{
				"client.Dial(",
				"client.DialContext(",
				"client.NewLazyClient(",
				"worker.New(",
				"NewRemotePayloadCodec(",
				"NewRemoteDataConverter(",
			} {
				Expect(string(contents)).NotTo(ContainSubstring(forbidden), relative)
			}
		}
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
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "node_modules") {
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

func writeConsumerFile(directory, name, contents string) {
	Expect(os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600)).To(Succeed())
}
