package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprocess"
	"github.com/cockroachdb/errors"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, sandboxhostprocess.ErrNoWork) {
		_, _ = fmt.Fprintln(os.Stderr, "sandbox-host:", err)
		os.Exit(1)
	}
}

func run() error {
	arguments := flag.NewFlagSet("sandbox-host", flag.ContinueOnError)
	configPath := arguments.String("config", "", "absolute path to the strict sandbox-host configuration")
	if err := arguments.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *configPath == "" || (*configPath)[0] != '/' || arguments.NArg() != 0 {
		return errors.New("--config must be one explicit absolute path")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return errors.Wrap(err, "open sandbox-host configuration")
	}
	config, parseErr := sandboxhostprocess.Parse(file)
	closeErr := file.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return errors.Wrap(closeErr, "close sandbox-host configuration")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return sandboxhostprocess.RunOnce(ctx, config, os.LookupEnv, wallClock{})
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }
