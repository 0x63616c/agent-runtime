// Command firecracker-smoke records a fail-closed protected-runner preflight.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

const runnerContract = "protected-linux-kvm-v1"

type report struct {
	SchemaVersion string                     `json:"schema_version"`
	ProofLevel    string                     `json:"proof_level"`
	Result        firecracker.EvidenceResult `json:"result"`
	Preflight     firecracker.KVMPreflight   `json:"preflight"`
	Reason        string                     `json:"reason,omitempty"`
}

func main() {
	reportPath := flag.String("report", "", "required path for a redacted smoke report")
	flag.Parse()
	if *reportPath == "" {
		fmt.Fprintln(os.Stderr, "firecracker-smoke: -report is required")
		os.Exit(2)
	}
	preflight := firecracker.InspectLocalKVMPreflight()
	record := report{SchemaVersion: "firecracker.smoke-evidence/v1", ProofLevel: firecracker.ProofLevelLinuxKVME2E, Result: firecracker.EvidenceBlocked, Preflight: preflight}
	if os.Getenv("FIRECRACKER_RUNNER_CONTRACT") != runnerContract {
		record.Reason = "protected self-hosted KVM runner contract is absent"
	} else if err := preflight.Validate(); err != nil {
		record.Reason = err.Error()
	} else {
		record.Reason = "a reviewed fixture lock and enrolled M3 host-control bridge are required before launch"
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*reportPath, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "firecracker-smoke: write report: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "firecracker-smoke:", record.Reason)
	os.Exit(1)
}
