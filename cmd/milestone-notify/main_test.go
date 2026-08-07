package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeconfig"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMilestoneNotify(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Milestone Notify Command Suite")
}

var _ = Describe("milestone-notify", func() {
	It("retains and posts the selected bounded milestone through injected time and HTTP", func() {
		root, err := filepath.Abs("../..")
		Expect(err).NotTo(HaveOccurred())
		directory := GinkgoT().TempDir()
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 23, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		client := &recordingHTTPClient{statusCode: http.StatusOK}
		var output bytes.Buffer

		err = run([]string{
			"-milestone", "M0",
			"-catalog", filepath.Join(root, "evidence/requirements-catalog.json"),
			"-ledger", filepath.Join(root, "evidence/requirements-ledger.json"),
			"-record-dir", directory,
			"-revision", "4439138",
		}, &output, fakeClock, client, func(string) (string, bool) { return "", false })
		Expect(err).NotTo(HaveOccurred())
		Expect(client.requests).To(HaveLen(1))
		Expect(client.requests[0].URL.String()).To(Equal(runtimeconfig.NtfyTopic))
		var payload map[string]json.RawMessage
		Expect(json.Unmarshal(client.bodies[0], &payload)).To(Succeed())
		Expect(payload).To(HaveLen(7))
		Expect(string(payload["status"])).To(Equal(`"completed"`))
		var evidence []map[string]string
		Expect(json.Unmarshal(payload["evidence_summary"], &evidence)).To(Succeed())
		Expect(evidence).To(HaveLen(7))
		entries, err := os.ReadDir(directory)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
		Expect(output.String()).To(ContainSubstring(`"delivery":"sent"`))
	})

	It("retains and posts the bounded M2 completion record", func() {
		root, err := filepath.Abs("../..")
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 7, 7, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())
		client := &recordingHTTPClient{statusCode: http.StatusOK}
		var output bytes.Buffer

		err = run([]string{
			"-milestone", "M2",
			"-catalog", filepath.Join(root, "evidence/requirements-catalog.json"),
			"-ledger", filepath.Join(root, "evidence/requirements-ledger.json"),
			"-record-dir", GinkgoT().TempDir(),
			"-revision", "8c7b9ef3c61acf27959ee12fbdd51c695ffe5795",
		}, &output, fakeClock, client, func(string) (string, bool) { return "", false })
		Expect(err).NotTo(HaveOccurred())
		Expect(client.requests).To(HaveLen(1))
		var payload map[string]json.RawMessage
		Expect(json.Unmarshal(client.bodies[0], &payload)).To(Succeed())
		Expect(string(payload["milestone"])).To(Equal(`"M2 payload and blob infrastructure"`))
		Expect(string(payload["next_milestone"])).To(Equal(`"M3 durable sandbox control"`))
		var evidence []map[string]string
		Expect(json.Unmarshal(payload["evidence_summary"], &evidence)).To(Succeed())
		Expect(evidence).To(HaveLen(10))
		Expect(output.String()).To(ContainSubstring(`"status":"completed"`))
	})

	It("refuses a caller-supplied terminal requirement subset", func() {
		root, err := filepath.Abs("../..")
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 23, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())

		err = run([]string{
			"-milestone", "M0",
			"-catalog", filepath.Join(root, "evidence/requirements-catalog.json"),
			"-ledger", filepath.Join(root, "evidence/requirements-ledger.json"),
			"-record-dir", GinkgoT().TempDir(),
			"-revision", "4439138",
			"-requirements", "DOC-005",
		}, io.Discard, fakeClock, &recordingHTTPClient{statusCode: http.StatusOK}, func(string) (string, bool) { return "", false })
		Expect(err).To(MatchError(ContainSubstring("flag provided but not defined: -requirements")))
	})

	It("refuses a catalog whose M0 ownership is not exactly the seven terminal rows", func() {
		root, err := filepath.Abs("../..")
		Expect(err).NotTo(HaveOccurred())
		catalogData, err := os.ReadFile(filepath.Join(root, "evidence/requirements-catalog.json"))
		Expect(err).NotTo(HaveOccurred())
		mutated := bytes.Replace(catalogData, []byte(`"milestone": "M0"`), []byte(`"milestone": "M1"`), 1)
		Expect(mutated).NotTo(Equal(catalogData))
		catalogPath := filepath.Join(GinkgoT().TempDir(), "catalog.json")
		Expect(os.WriteFile(catalogPath, mutated, 0o600)).To(Succeed())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 6, 23, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())

		err = run([]string{
			"-milestone", "M0",
			"-catalog", catalogPath,
			"-ledger", filepath.Join(root, "evidence/requirements-ledger.json"),
			"-record-dir", GinkgoT().TempDir(),
			"-revision", "4439138",
		}, io.Discard, fakeClock, &recordingHTTPClient{statusCode: http.StatusOK}, func(string) (string, bool) { return "", false })
		Expect(err).To(MatchError("validate M0 terminal requirements: catalog ownership mismatch"))
	})

	It("requires a supported milestone instead of accepting caller-authored report labels", func() {
		root, err := filepath.Abs("../..")
		Expect(err).NotTo(HaveOccurred())
		fakeClock, err := clock.NewFake(time.Date(2026, 8, 7, 7, 0, 0, 0, time.UTC))
		Expect(err).NotTo(HaveOccurred())

		err = run([]string{
			"-milestone", "M99",
			"-catalog", filepath.Join(root, "evidence/requirements-catalog.json"),
			"-ledger", filepath.Join(root, "evidence/requirements-ledger.json"),
			"-record-dir", GinkgoT().TempDir(),
			"-revision", "8c7b9ef3c61acf27959ee12fbdd51c695ffe5795",
		}, io.Discard, fakeClock, &recordingHTTPClient{statusCode: http.StatusOK}, func(string) (string, bool) { return "", false })
		Expect(err).To(MatchError("milestone notification does not support milestone M99"))
	})
})

type recordingHTTPClient struct {
	statusCode int
	requests   []*http.Request
	bodies     [][]byte
}

func (client *recordingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	client.requests = append(client.requests, request)
	client.bodies = append(client.bodies, body)
	return &http.Response{StatusCode: client.statusCode, Body: io.NopCloser(bytes.NewBufferString("ok")), Header: make(http.Header)}, nil
}
