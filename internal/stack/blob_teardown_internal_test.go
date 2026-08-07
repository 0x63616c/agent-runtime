package stack

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Blob teardown script", func() {
	It("accepts only MinIO's definitive missing-bucket result as already removed", func() {
		Expect(runTeardownBlobScript("The specified bucket does not exist.", 1)).To(Succeed())
		Expect(runTeardownBlobScript("Bucket `bucket` does not exist.", 1)).To(Succeed())
	})

	It("fails closed when the bucket check has any other error", func() {
		err := runTeardownBlobScript("dial tcp: connection refused", 1)
		Expect(err).To(HaveOccurred())
	})
})

func runTeardownBlobScript(listOutput string, listExitCode int) error {
	directory := GinkgoT().TempDir()
	logPath := filepath.Join(directory, "mc.log")
	mcPath := filepath.Join(directory, "mc")
	script := `#!/bin/sh
printf '%s\n' "$1" >> "$MC_CALL_LOG"
case "$1" in
  alias) exit 0 ;;
  ls) printf '%s\n' "$MC_LIST_OUTPUT"; exit "$MC_LIST_EXIT_CODE" ;;
  rm|rb) exit 0 ;;
esac
exit 64
`
	if err := os.WriteFile(mcPath, []byte(script), 0o700); err != nil {
		return err
	}
	command := exec.Command("sh", "-c", teardownBlobScript, "provider-blob", "bucket", "prefix", "http://blob:9000")
	command.Env = append(os.Environ(), "PATH="+directory+":"+os.Getenv("PATH"), "MC_CALL_LOG="+logPath, "MC_LIST_OUTPUT="+listOutput, "MC_LIST_EXIT_CODE="+strconv.Itoa(listExitCode), "MINIO_ROOT_USER=test-user", "MINIO_ROOT_PASSWORD=test-password")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run fake blob teardown: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
