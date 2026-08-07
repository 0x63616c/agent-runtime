package docsrefresh_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0x63616c/agent-runtime/internal/docsrefresh"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("refreshing public documentation", func() {
	var files *memoryFiles
	var changes *fakeChanges
	var manifest docsrefresh.Manifest

	BeforeEach(func() {
		files = &memoryFiles{content: map[string][]byte{
			"README.md":                          []byte("# Agent Runtime\n"),
			"website/docusaurus.config.ts":       []byte("baseUrl: '/agent-runtime/'\n"),
			"website/docs/security/overview.mdx": []byte("operator-owned prose\n"),
		}}
		changes = &fakeChanges{}
		manifest = docsrefresh.Manifest{
			SchemaVersion:   1,
			RendererVersion: "source-inventory/v1",
			Generated: []docsrefresh.Artifact{{
				Output:       "website/docs/reference/generated/source-inventory.mdx",
				Inputs:       []string{"website/docusaurus.config.ts", "README.md"},
				Kind:         "source-inventory",
				PublicStatus: "foundation",
			}},
			Curated: []string{"website/docs/security/overview.mdx"},
		}
	})

	It("reports stale output in check mode without writing or creating directories", func() {
		result, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{Check: true})

		Expect(err).To(MatchError(docsrefresh.ErrStale))
		Expect(result.Stale).To(Equal([]string{"website/docs/reference/generated/source-inventory.mdx"}))
		Expect(files.atomicWrites).To(BeEmpty())
		Expect(files.content).NotTo(HaveKey("website/docs/reference/generated/source-inventory.mdx"))
	})

	It("writes changed allow-listed output atomically and is byte-identical on repeat", func() {
		first, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Changed).To(Equal([]string{"website/docs/reference/generated/source-inventory.mdx"}))
		Expect(files.atomicWrites).To(Equal([]string{"website/docs/reference/generated/source-inventory.mdx"}))

		second, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Changed).To(BeEmpty())
		Expect(files.atomicWrites).To(HaveLen(1))
	})

	It("rejects input and output paths that escape the repository", func() {
		manifest.Generated[0].Inputs = append(manifest.Generated[0].Inputs, "../secret")
		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).To(MatchError(ContainSubstring("escapes repository")))
		Expect(files.reads).To(BeEmpty())
		Expect(files.atomicWrites).To(BeEmpty())
	})

	It("refuses to replace a changed generated output", func() {
		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		files.content[manifest.Generated[0].Output] = []byte("local edit\n")
		changes.dirty = map[string]bool{manifest.Generated[0].Output: true}

		_, err = docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(errors.Is(err, docsrefresh.ErrDirty)).To(BeTrue())
		Expect(err).To(MatchError(ContainSubstring(manifest.Generated[0].Output)))
		Expect(files.content[manifest.Generated[0].Output]).To(Equal([]byte("local edit\n")))
	})

	It("detects declared route, configuration, example, and reference drift", func() {
		manifest.Generated[0].Inputs = []string{
			"website/docusaurus.config.ts",
			"website/docs/examples/index.mdx",
			"website/docs/reference/overview.mdx",
			"deploy/catalog.yaml",
		}
		for _, path := range manifest.Generated[0].Inputs {
			files.content[path] = []byte("initial\n")
		}
		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())

		for _, path := range manifest.Generated[0].Inputs {
			files.content[path] = []byte("changed " + path + "\n")
			_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{Check: true})
			Expect(err).To(MatchError(docsrefresh.ErrStale), path)
			files.content[path] = []byte("initial\n")
		}
	})

	It("never rewrites curated security content", func() {
		curatedPath := manifest.Curated[0]
		files.content[curatedPath] = []byte("carefully revised operator claim\n")
		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(files.content[curatedPath]).To(Equal([]byte("carefully revised operator claim\n")))
		Expect(files.atomicWrites).NotTo(ContainElement(curatedPath))
	})

	It("rejects a stale curated manifest entry without writing", func() {
		manifest.Curated = append(manifest.Curated, "website/docs/security/missing.mdx")
		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).To(MatchError(ContainSubstring("read curated documentation")))
		Expect(files.atomicWrites).To(BeEmpty())
	})

	It("leaves existing output intact when an atomic replacement fails", func() {
		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		original := append([]byte(nil), files.content[manifest.Generated[0].Output]...)
		files.content["README.md"] = []byte("changed input\n")
		files.writeErr = errors.New("injected atomic failure")

		_, err = docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).To(MatchError(ContainSubstring("injected atomic failure")))
		Expect(files.content[manifest.Generated[0].Output]).To(Equal(original))
	})

	It("uses the exact bounded paths for final diff review", func() {
		Expect(docsrefresh.ReviewDiffArgs()).To(Equal([]string{
			"diff", "--no-ext-diff", "HEAD", "--",
			"website/",
			"skills/refresh-agent-runtime-docs/",
			"skills/develop-with-agent-runtime/",
			"deploy/catalog.yaml",
		}))
	})

	It("includes staged changes in the bounded final diff", func() {
		root := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(root, "website"), 0o755)).To(Succeed())
		path := filepath.Join(root, "website", "tracked.mdx")
		Expect(os.WriteFile(path, []byte("before\n"), 0o644)).To(Succeed())
		runGit(root, "init")
		runGit(root, "config", "user.name", "Docs Fixture")
		runGit(root, "config", "user.email", "docs-fixture@example.invalid")
		runGit(root, "add", "website/tracked.mdx")
		runGit(root, "commit", "-m", "fixture baseline")
		Expect(os.WriteFile(path, []byte("after\n"), 0o644)).To(Succeed())
		runGit(root, "add", "website/tracked.mdx")

		command := exec.Command("git", docsrefresh.ReviewDiffArgs()...)
		command.Dir = root
		output, err := command.Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(ContainSubstring("+after"))
	})

	It("rejects stale or ambiguous manifest documents", func() {
		_, err := docsrefresh.LoadManifest([]byte(`{"schemaVersion":2,"rendererVersion":"source-inventory/v1","generated":[]}`))
		Expect(err).To(MatchError(ContainSubstring("unsupported docs source manifest schema")))

		_, err = docsrefresh.LoadManifest([]byte(`{"schemaVersion":1,"rendererVersion":"source-inventory/v1","generated":[]} {}`))
		Expect(err).To(MatchError(ContainSubstring("multiple JSON values")))
	})

	It("atomically creates an OS-backed output with stable permissions", func() {
		root := GinkgoT().TempDir()
		path := filepath.Join(root, "generated", "page.mdx")
		Expect((docsrefresh.OSFiles{Root: root}).WriteFileAtomic(path, []byte("first\n"))).To(Succeed())
		content, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(content).To(Equal([]byte("first\n")))
		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)))
		entries, err := os.ReadDir(filepath.Dir(path))
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
	})

	It("rejects an OS-backed source symlink that leaves the repository", func() {
		root := GinkgoT().TempDir()
		outside := filepath.Join(GinkgoT().TempDir(), "outside.md")
		Expect(os.WriteFile(outside, []byte("secret\n"), 0o600)).To(Succeed())
		link := filepath.Join(root, "source.md")
		Expect(os.Symlink(outside, link)).To(Succeed())
		_, err := (docsrefresh.OSFiles{Root: root}).ReadFile(link)
		Expect(err).To(MatchError(ContainSubstring("escapes repository")))
	})

	It("bootstraps a missing OS output but refuses to replace it while untracked", func() {
		root := GinkgoT().TempDir()
		for path, content := range map[string]string{
			"README.md":                          "initial\n",
			"website/docusaurus.config.ts":       "config\n",
			"website/docs/security/overview.mdx": "curated\n",
		} {
			absolute := filepath.Join(root, filepath.FromSlash(path))
			Expect(os.MkdirAll(filepath.Dir(absolute), 0o755)).To(Succeed())
			Expect(os.WriteFile(absolute, []byte(content), 0o644)).To(Succeed())
		}
		runGit(root, "init")
		osFiles := docsrefresh.OSFiles{Root: root}
		gitChanges := docsrefresh.GitChanges{Root: root}

		first, err := docsrefresh.Refresh(context.Background(), root, manifest, osFiles, gitChanges, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Changed).To(Equal([]string{manifest.Generated[0].Output}))

		_, err = docsrefresh.Refresh(context.Background(), root, manifest, osFiles, gitChanges, docsrefresh.Options{})
		Expect(errors.Is(err, docsrefresh.ErrDirty)).To(BeTrue())

		checked, err := docsrefresh.Refresh(context.Background(), root, manifest, osFiles, gitChanges, docsrefresh.Options{Check: true})
		Expect(err).NotTo(HaveOccurred())
		Expect(checked.Stale).To(BeEmpty())
	})
})

func runGit(root string, arguments ...string) {
	command := exec.Command("git", arguments...)
	command.Dir = root
	output, err := command.CombinedOutput()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), string(output))
}

type memoryFiles struct {
	content      map[string][]byte
	reads        []string
	atomicWrites []string
	writeErr     error
}

func (f *memoryFiles) ReadFile(path string) ([]byte, error) {
	path = filepath.ToSlash(path)
	f.reads = append(f.reads, path)
	content, ok := f.content[path]
	if !ok {
		return nil, docsrefresh.ErrNotExist
	}
	return append([]byte(nil), content...), nil
}

func (f *memoryFiles) WriteFileAtomic(path string, content []byte) error {
	path = filepath.ToSlash(path)
	f.atomicWrites = append(f.atomicWrites, path)
	if f.writeErr != nil {
		return f.writeErr
	}
	f.content[path] = append([]byte(nil), content...)
	return nil
}

type fakeChanges struct{ dirty map[string]bool }

func (f *fakeChanges) Dirty(_ context.Context, path string) (bool, error) {
	return f.dirty[path], nil
}
