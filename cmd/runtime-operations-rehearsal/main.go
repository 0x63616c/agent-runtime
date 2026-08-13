// Command runtime-operations-rehearsal exercises the protected drill checks
// against disposable local services. It never creates an evidence artifact.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/runtimeoperations"
)

func main() {
	if os.Getenv("RUNTIME_OPERATIONS_REHEARSAL") != "local-only" {
		fmt.Fprintln(os.Stderr, "runtime-operations-rehearsal: set RUNTIME_OPERATIONS_REHEARSAL=local-only")
		os.Exit(2)
	}
	config, err := runtimeoperations.LoadRehearsalConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-rehearsal:", err)
		os.Exit(1)
	}
	certificatePath := os.Getenv("AR_RUNTIME_OPERATIONS_REHEARSAL_CA_FILE")
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-rehearsal: local audit CA file is required:", err)
		os.Exit(1)
	}
	if _, err := runtimeoperations.RunRehearsal(context.Background(), config, certificate); err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-rehearsal:", err)
		os.Exit(1)
	}
	fmt.Println("local M5 operations rehearsal passed; no evidence artifact was created")
}
