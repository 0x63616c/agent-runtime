// Command sandbox-host-bootstrap reconciles one mounted local/CI host identity
// into the sandbox-control PostgreSQL ledger.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostbootstrap"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sandbox-host-bootstrap:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("sandbox-host-bootstrap", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "absolute path to strict local/CI bootstrap configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *configPath == "" || (*configPath)[0] != '/' || flags.NArg() != 0 {
		return fmt.Errorf("--config must be one explicit absolute path")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return fmt.Errorf("open bootstrap configuration: %w", err)
	}
	config, parseErr := sandboxhostbootstrap.Parse(file)
	closeErr := file.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return fmt.Errorf("close bootstrap configuration: %w", closeErr)
	}
	return sandboxhostbootstrap.Run(context.Background(), config, os.LookupEnv)
}
