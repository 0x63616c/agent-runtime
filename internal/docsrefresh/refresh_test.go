package docsrefresh_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
			"website/astro.config.mjs":       []byte("base: '/agent-runtime'\n"),
			"website/src/content/docs/docs/security/overview.mdx": []byte("operator-owned prose\n"),
		}}
		changes = &fakeChanges{}
		manifest = docsrefresh.Manifest{
			SchemaVersion:   1,
			RendererVersion: "source-inventory/v1",
			Generated: []docsrefresh.Artifact{{
				Output:       "website/src/content/docs/docs/reference/generated/source-inventory.mdx",
				Inputs:       []string{"website/astro.config.mjs", "README.md"},
				Kind:         "source-inventory",
				PublicStatus: "foundation",
			}},
			Curated: []string{"website/src/content/docs/docs/security/overview.mdx"},
		}
	})

	It("reports stale output in check mode without writing or creating directories", func() {
		result, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{Check: true})

		Expect(err).To(MatchError(docsrefresh.ErrStale))
		Expect(result.Stale).To(Equal([]string{"website/src/content/docs/docs/reference/generated/source-inventory.mdx"}))
		Expect(files.atomicWrites).To(BeEmpty())
		Expect(files.content).NotTo(HaveKey("website/src/content/docs/docs/reference/generated/source-inventory.mdx"))
	})

	It("writes changed allow-listed output atomically and is byte-identical on repeat", func() {
		first, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Changed).To(Equal([]string{"website/src/content/docs/docs/reference/generated/source-inventory.mdx"}))
		Expect(files.atomicWrites).To(Equal([]string{"website/src/content/docs/docs/reference/generated/source-inventory.mdx"}))

		second, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Changed).To(BeEmpty())
		Expect(files.atomicWrites).To(HaveLen(1))
	})

	It("renders a sorted HTTP operation index from the declared OpenAPI contract", func() {
		manifest.Generated[0] = docsrefresh.Artifact{
			Output:       "website/src/content/docs/docs/reference/generated/http-operations.mdx",
			Inputs:       []string{"api/openapi/openapi.yaml"},
			Kind:         "openapi-operation-index",
			PublicStatus: "current public contract; runtime transport remains development evidence",
		}
		files.content["api/openapi/openapi.yaml"] = validOpenAPIContract("v1")

		result, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Changed).To(Equal([]string{"website/src/content/docs/docs/reference/generated/http-operations.mdx"}))
		output := string(files.content[manifest.Generated[0].Output])
		Expect(output).To(ContainSubstring("# HTTP operation index"))
		Expect(output).To(ContainSubstring("`3.1.0`"))
		Expect(output).To(ContainSubstring("| `POST` | `/v1/sessions` | `createSession` | `201` |"))
		Expect(output).To(ContainSubstring("| `GET` | `/v1/sessions/{session_id}` | `inspectSession` | `200` |"))
		Expect(output).To(HavePrefix("---\ntitle: HTTP operation index\n"))
		Expect(strings.Index(output, "`POST` | `/v1/sessions`")).To(BeNumerically("<", strings.Index(output, "`GET` | `/v1/sessions/{session_id}`")))
	})

	It("renders a documented public Go SDK symbol index from declared source files", func() {
		manifest.Generated[0] = docsrefresh.Artifact{
			Output: "website/src/content/docs/docs/reference/generated/go-sdk-symbols.mdx",
			Inputs: []string{
				"sdk/go/client.go",
				"sdk/go/doc.go",
				"sdk/go/types.go",
			},
			Kind:         "go-sdk-symbol-index",
			PublicStatus: "current public Go SDK contract",
		}
		files.content["sdk/go/doc.go"] = []byte("// Package agentruntime defines the stable Go contract.\npackage agentruntime\n")
		files.content["sdk/go/client.go"] = []byte("package agentruntime\n\n// RuntimeClient is the public command contract.\ntype RuntimeClient interface {\n\t// CreateSession creates a durable Session.\n\tCreateSession()\n}\n\n// NewClient constructs the public client.\nfunc NewClient() {}\n")
		files.content["sdk/go/types.go"] = []byte("package agentruntime\n\n// Session is a durable interaction.\ntype Session struct{}\n\n// Clone returns an independent Session snapshot.\nfunc (Session) Clone() Session { return Session{} }\n\n// SessionOpen accepts input.\nconst SessionOpen = \"open\"\n")

		result, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Changed).To(Equal([]string{"website/src/content/docs/docs/reference/generated/go-sdk-symbols.mdx"}))
		output := string(files.content[manifest.Generated[0].Output])
		Expect(output).To(ContainSubstring("# Go SDK symbol index"))
		Expect(output).To(ContainSubstring("`github.com/0x63616c/agent-runtime/sdk/go`"))
		Expect(output).To(ContainSubstring("| `const` | `SessionOpen` | SessionOpen accepts input. |"))
		Expect(output).To(ContainSubstring("| `func` | `NewClient` | NewClient constructs the public client. |"))
		Expect(output).To(ContainSubstring("| `method` | `Session.Clone` | Clone returns an independent Session snapshot. |"))
		Expect(output).To(ContainSubstring("| `method` | `RuntimeClient.CreateSession` | CreateSession creates a durable Session. |"))
		Expect(output).To(ContainSubstring("| `type` | `RuntimeClient` | RuntimeClient is the public command contract. |"))
		Expect(strings.Index(output, "`NewClient`")).To(BeNumerically("<", strings.Index(output, "`RuntimeClient`")))
	})

	It("rejects an undocumented public Go SDK symbol without writing", func() {
		manifest.Generated[0] = docsrefresh.Artifact{
			Output:       "website/src/content/docs/docs/reference/generated/go-sdk-symbols.mdx",
			Inputs:       []string{"sdk/go/doc.go", "sdk/go/types.go"},
			Kind:         "go-sdk-symbol-index",
			PublicStatus: "current public Go SDK contract",
		}
		files.content["sdk/go/doc.go"] = []byte("// Package agentruntime defines the stable Go contract.\npackage agentruntime\n")
		files.content["sdk/go/types.go"] = []byte("package agentruntime\n\ntype Session struct{}\n")

		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})

		Expect(err).To(MatchError(ContainSubstring("undocumented public Go SDK type Session")))
		Expect(files.atomicWrites).To(BeEmpty())
	})

	It("rejects a Go SDK source manifest that omits a discovered package file", func() {
		manifest.Generated[0] = docsrefresh.Artifact{
			Output:       "website/src/content/docs/docs/reference/generated/go-sdk-symbols.mdx",
			Inputs:       []string{"sdk/go/doc.go", "sdk/go/types.go"},
			Kind:         "go-sdk-symbol-index",
			PublicStatus: "current public Go SDK contract",
		}

		err := docsrefresh.ValidateGoSDKSourceList(context.Background(), manifest, fakeGoSDKSourceLister{files: []string{"sdk/go/doc.go", "sdk/go/new-public-file.go", "sdk/go/types.go"}})

		Expect(err).To(MatchError(ContainSubstring("Go SDK source manifest differs from go list")))
	})

	It("refuses an OpenAPI operation without a successful response before writing", func() {
		manifest.Generated[0] = docsrefresh.Artifact{
			Output:       "website/src/content/docs/docs/reference/generated/http-operations.mdx",
			Inputs:       []string{"api/openapi/openapi.yaml"},
			Kind:         "openapi-operation-index",
			PublicStatus: "current public contract; runtime transport remains development evidence",
		}
		files.content["api/openapi/openapi.yaml"] = []byte(strings.Replace(string(validOpenAPIContract("v1")), `"responses":{"201":{"description":"success"},"default":{"description":"failure"}}`, `"responses":{"400":{"description":"failure"},"default":{"description":"failure"}}`, 1))

		_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})

		Expect(err).To(MatchError(ContainSubstring("expected success and default failure responses")))
		Expect(files.atomicWrites).To(BeEmpty())
	})

	It("refuses an incomplete or unsafe OpenAPI document before writing an index", func() {
		manifest.Generated[0] = docsrefresh.Artifact{
			Output:       "website/src/content/docs/docs/reference/generated/http-operations.mdx",
			Inputs:       []string{"api/openapi/openapi.yaml"},
			Kind:         "openapi-operation-index",
			PublicStatus: "current public contract; runtime transport remains development evidence",
		}
		for _, test := range []struct {
			name, expected string
			document       []byte
		}{
			{
				name:     "wrong OpenAPI version",
				expected: "version must be 3.1.0",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"openapi":"3.1.0"`, `"openapi":"3.1.1"`, 1)),
			},
			{
				name:     "unsafe API info version",
				expected: "v1 info version",
				document: validOpenAPIContract("v1\n\n<script>alert(1)</script>"),
			},
			{
				name:     "reference path item",
				expected: "decode runtime OpenAPI authority",
				document: withOpenAPIPathItem(`"/v1/hidden":{"$ref":"#/components/pathItems/Hidden"}`),
			},
			{
				name:     "null path item",
				expected: "not a concrete versioned path item",
				document: withOpenAPIPathItem(`"/v1/null":null`),
			},
			{
				name:     "duplicate operation ID",
				expected: "operation createSession",
				document: withOpenAPIPathItem(`"/v1/duplicate":{"get":{"operationId":"createSession","parameters":[{"$ref":"#/components/parameters/RequestID"}],"responses":{"200":{"description":"success"},"default":{"description":"failure"}}}}`),
			},
			{
				name:     "incomplete authority document",
				expected: "title, v1 info version, and servers are required",
				document: []byte(`{"openapi":"3.1.0","info":{"title":"Agent Runtime API","version":"v1"},"paths":{}}`),
			},
			{
				name:     "empty security authority",
				expected: "security requirements are required",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"security":[{"bearerAuth":[]}]`, `"security":[]`, 1)),
			},
			{
				name:     "empty security requirement",
				expected: "security requirement",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"security":[{"bearerAuth":[]}]`, `"security":[{}]`, 1)),
			},
			{
				name:     "null security requirement",
				expected: "security requirement",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"security":[{"bearerAuth":[]}]`, `"security":[null]`, 1)),
			},
			{
				name:     "unknown security scheme",
				expected: "unknown security scheme",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"security":[{"bearerAuth":[]}]`, `"security":[{"unknown":[]}]`, 1)),
			},
			{
				name:     "null mutation request body",
				expected: "request body is invalid",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"requestBody":{"$ref":"#/components/requestBodies/EmptyMutation"}`, `"requestBody":null`, 1)),
			},
			{
				name:     "scalar mutation request body",
				expected: "request body is invalid",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"requestBody":{"$ref":"#/components/requestBodies/EmptyMutation"}`, `"requestBody":true`, 1)),
			},
			{
				name:     "null success response",
				expected: "expected success and default failure responses are required",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"responses":{"201":{"description":"success"},"default":{"description":"failure"}}`, `"responses":{"201":null,"default":{"description":"failure"}}`, 1)),
			},
			{
				name:     "scalar default response",
				expected: "expected success and default failure responses are required",
				document: []byte(strings.Replace(string(validOpenAPIContract("v1")), `"responses":{"201":{"description":"success"},"default":{"description":"failure"}}`, `"responses":{"201":{"description":"success"},"default":false}`, 1)),
			},
		} {
			files.content["api/openapi/openapi.yaml"] = test.document

			_, err := docsrefresh.Refresh(context.Background(), ".", manifest, files, changes, docsrefresh.Options{})

			Expect(err).To(MatchError(ContainSubstring(test.expected)), test.name)
			Expect(files.atomicWrites).To(BeEmpty(), test.name)
		}
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
			"website/astro.config.mjs",
			"website/src/content/docs/docs/examples/index.mdx",
			"website/src/content/docs/docs/reference/overview.mdx",
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
		manifest.Curated = append(manifest.Curated, "website/src/content/docs/docs/security/missing.mdx")
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
			"website/astro.config.mjs":       "config\n",
			"website/src/content/docs/docs/security/overview.mdx": "curated\n",
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

func validOpenAPIContract(infoVersion string) []byte {
	operations := []struct {
		id, method, path, status string
		mutation                 bool
	}{
		{"createAgent", "post", "/v1/admin/agents", "201", true},
		{"reviseAgent", "post", "/v1/admin/agents/{agent_id}/revisions", "201", true},
		{"getAgentRevision", "get", "/v1/admin/agents/{agent_id}/revisions/{revision_id}", "200", false},
		{"createSession", "post", "/v1/sessions", "201", true},
		{"inspectSession", "get", "/v1/sessions/{session_id}", "200", false},
		{"sendInput", "post", "/v1/sessions/{session_id}/inputs", "202", true},
		{"inspectTurn", "get", "/v1/sessions/{session_id}/turns/{turn_id}", "200", false},
		{"listEvents", "get", "/v1/sessions/{session_id}/events", "200", false},
		{"cancelTurn", "post", "/v1/sessions/{session_id}/turns/{turn_id}/cancel", "200", true},
		{"closeSession", "post", "/v1/sessions/{session_id}/close", "200", true},
	}
	var paths strings.Builder
	for index, operation := range operations {
		if index > 0 {
			paths.WriteByte(',')
		}
		parameters := `[ {"$ref":"#/components/parameters/RequestID"} ]`
		requestBody := ""
		if operation.mutation {
			parameters = `[ {"$ref":"#/components/parameters/RequestID"}, {"$ref":"#/components/parameters/IdempotencyKey"} ]`
			requestBody = `,"requestBody":{"$ref":"#/components/requestBodies/EmptyMutation"}`
		}
		fmt.Fprintf(&paths, `%q:{%q:{"operationId":%q,"parameters":%s%s,"responses":{%q:{"description":"success"},"default":{"description":"failure"}}}}`, operation.path, operation.method, operation.id, parameters, requestBody, operation.status)
	}
	return []byte(fmt.Sprintf(`{"openapi":"3.1.0","info":{"title":"Agent Runtime API","version":%q},"servers":[{"url":"https://runtime.example.invalid"}],"security":[{"bearerAuth":[]}],"paths":{%s},"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}},"schemas":{}}}`, infoVersion, paths.String()))
}

func withOpenAPIPathItem(pathItem string) []byte {
	return []byte(strings.Replace(string(validOpenAPIContract("v1")), `},"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}},"schemas":{}}}`, `,`+pathItem+`},"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}},"schemas":{}}}`, 1))
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

type fakeGoSDKSourceLister struct {
	files []string
	err   error
}

func (lister fakeGoSDKSourceLister) GoSDKFiles(context.Context) ([]string, error) {
	return append([]string(nil), lister.files...), lister.err
}
