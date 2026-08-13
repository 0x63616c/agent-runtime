// Command runtime-operations-direct-lab records an explicitly authorized,
// disposable local or home-lab operations exercise. It cannot create a
// protected operational artifact.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/runtimeoperations"
)

func main() {
	report := flag.String("report", "", "required new path for a redacted direct-lab evidence report")
	validate := flag.String("validate", "", "validate one retained direct-lab evidence report")
	authorized := flag.Bool("execute-authorized-disposable-lab", false, "required explicit authorization for a mutating disposable lab")
	flag.Parse()
	if *validate != "" {
		if *report != "" || *authorized || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "runtime-operations-direct-lab: -validate cannot be combined with -report, authorization, or arguments")
			os.Exit(2)
		}
		if _, err := runtimeoperations.ReadDirectLabEvidence(*validate); err != nil {
			fmt.Fprintln(os.Stderr, "runtime-operations-direct-lab:", err)
			os.Exit(1)
		}
		return
	}
	if *report == "" || !*authorized || flag.NArg() != 0 || os.Getenv("RUNTIME_OPERATIONS_DIRECT_LAB") != "authorized-disposable-v1" {
		fmt.Fprintln(os.Stderr, "runtime-operations-direct-lab: -report, -execute-authorized-disposable-lab, and RUNTIME_OPERATIONS_DIRECT_LAB=authorized-disposable-v1 are required")
		os.Exit(2)
	}
	config, err := runtimeoperations.LoadRehearsalConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-direct-lab:", err)
		os.Exit(1)
	}
	certificate, err := os.ReadFile(os.Getenv("AR_RUNTIME_OPERATIONS_REHEARSAL_CA_FILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-direct-lab: local audit CA file is required:", err)
		os.Exit(1)
	}
	evidence, err := runtimeoperations.RunDirectLab(context.Background(), config, certificate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-direct-lab:", err)
		os.Exit(1)
	}
	if err := runtimeoperations.WriteDirectLabEvidence(*report, evidence); err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-direct-lab:", err)
		os.Exit(1)
	}
}
