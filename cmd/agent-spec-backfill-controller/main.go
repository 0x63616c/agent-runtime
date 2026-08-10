// Command agent-spec-backfill-controller validates one explicit controller declaration.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillprocess"
)

var errNoDeclaredPorts = errors.New("no declared CR, status, archive, legacy, and content ports are linked")

func main() {
	if err := run(os.Args[1:], func(path string) (io.ReadCloser, error) { return os.Open(path) }); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "agent-spec-backfill-controller:", err)
		os.Exit(1)
	}
}

func run(arguments []string, open func(string) (io.ReadCloser, error)) error {
	flags := flag.NewFlagSet("agent-spec-backfill-controller", flag.ContinueOnError)
	configPath := flags.String("config", "", "absolute path to the strict controller configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *configPath == "" || (*configPath)[0] != '/' || flags.NArg() != 0 || open == nil {
		return errors.New("--config must be one explicit absolute path")
	}
	file, err := open(*configPath)
	if err != nil {
		return fmt.Errorf("open configuration: %w", err)
	}
	_, parseErr := agentspecbackfillprocess.ParseConfig(file)
	closeErr := file.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return fmt.Errorf("close configuration: %w", closeErr)
	}
	return errNoDeclaredPorts
}
