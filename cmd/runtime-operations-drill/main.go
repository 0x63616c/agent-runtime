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
	preflight := flag.Bool("preflight", false, "run the protected operational checks without writing evidence")
	flag.Parse()
	if *validate != "" {
		if *report != "" || *preflight || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "runtime-operations-drill: -validate cannot be combined with -report, -preflight, or arguments")
			os.Exit(2)
		}
		if _, err := runtimeoperations.ReadEvidence(*validate); err != nil {
			fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
			os.Exit(1)
		}
		return
	}
	if (*report == "" && !*preflight) || (*report != "" && *preflight) || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill: exactly one of -report or -preflight is required")
		os.Exit(2)
	}
	config, err := runtimeoperations.LoadConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
		os.Exit(1)
	}
	// A local composition may emulate the protected runner's environment names
	// to detect contract drift, but it must be preflight-only and explicitly
	// supply its ephemeral TLS CA. That path never writes Evidence.
	localRehearsal := os.Getenv("RUNTIME_OPERATIONS_REHEARSAL") == "local-only"
	if localRehearsal && !*preflight {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill: local rehearsal permits only -preflight and cannot write evidence")
		os.Exit(2)
	}
	var evidence runtimeoperations.Evidence
	if localRehearsal {
		certificatePath := os.Getenv("AR_RUNTIME_OPERATIONS_REHEARSAL_CA_FILE")
		certificate, readErr := os.ReadFile(certificatePath)
		if readErr != nil {
			fmt.Fprintln(os.Stderr, "runtime-operations-drill: local rehearsal audit CA file is required:", readErr)
			os.Exit(1)
		}
		evidence, err = runtimeoperations.RunRehearsal(context.Background(), config, certificate)
	} else {
		evidence, err = runtimeoperations.Run(context.Background(), config)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
		os.Exit(1)
	}
	if *preflight {
		fmt.Println("protected runtime operations preflight passed; no evidence artifact was created")
		return
	}
	if err := runtimeoperations.WriteEvidence(*report, evidence); err != nil {
		fmt.Fprintln(os.Stderr, "runtime-operations-drill:", err)
		os.Exit(1)
	}
}
