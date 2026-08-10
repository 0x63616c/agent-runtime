package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolprocess"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sandbox-control:", err)
		os.Exit(1)
	}
}

func run() error {
	arguments := flag.NewFlagSet("sandbox-control", flag.ContinueOnError)
	configPath := arguments.String("config", "", "absolute path to the strict sandbox-control configuration")
	if err := arguments.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *configPath == "" || (*configPath)[0] != '/' || arguments.NArg() != 0 {
		return fmt.Errorf("--config must be one explicit absolute path")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return fmt.Errorf("open configuration: %w", err)
	}
	config, err := sandboxcontrolprocess.Parse(file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return fmt.Errorf("close configuration: %w", closeErr)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return sandboxcontrolprocess.RunWithReady(ctx, config, os.LookupEnv, func(addresses sandboxcontrolprocess.BoundAddresses) {
		logReady(logger, addresses)
	})
}

func logReady(logger *slog.Logger, addresses sandboxcontrolprocess.BoundAddresses) {
	logger.Info("sandbox control ready", "role", "sandbox-control", "public_address", addresses.Public, "host_control_address", addresses.HostControl)
}
