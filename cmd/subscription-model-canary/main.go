// Command subscription-model-canary validates a protected subscription-model
// canary contract. It does not contact a provider, read a credential, persist
// an artifact, or claim evidence: that work belongs to the approved live run.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/0x63616c/agent-runtime/internal/subscriptioncanary"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.LookupEnv); err != nil {
		fmt.Fprintln(os.Stderr, "subscription-model-canary:", err)
		os.Exit(2)
	}
}

func run(arguments []string, output io.Writer, lookup func(string) (string, bool)) error {
	flags := flag.NewFlagSet("subscription-model-canary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	preflight := flags.Bool("preflight", false, "validate the subscription model canary contract without a provider call or evidence artifact")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse subscription model canary arguments: %w", err)
	}
	if !*preflight || flags.NArg() != 0 {
		return fmt.Errorf("usage: subscription-model-canary -preflight")
	}
	if _, err := subscriptioncanary.Load(lookup); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "subscription model canary preflight passed; no provider call or evidence artifact was created")
	return err
}
