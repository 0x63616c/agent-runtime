// Command runtime-operations-drill records one protected operational drill.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/runtimeoperations"
)

func main() {
	report := flag.String("report", "", "required new path for a redacted operational evidence report")
	validate := flag.String("validate", "", "validate one retained operational evidence report")
	flag.Parse()
	if *validate != "" {
		if *report != "" || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "runtime-operations-drill: -validate cannot be combined with -report or arguments")
			os.Exit(2)
		}
		if _, err := runtimeoperations.ReadEvidence(*validate); err != nil {
			fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
			os.Exit(1)
		}
		return
	}
	if *report == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill: -report is required")
		os.Exit(2)
	}
	config, err := runtimeoperations.LoadConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
		os.Exit(1)
	}
	evidence, err := runtimeoperations.Run(context.Background(), config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
		os.Exit(1)
	}
	if err := runtimeoperations.WriteEvidence(*report, evidence); err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
		os.Exit(1)
	}
}
