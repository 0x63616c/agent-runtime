package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/runtimeapiprocess"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "agent-runtime-api:", err)
		os.Exit(1)
	}
}

func run() error {
	arguments := flag.NewFlagSet("agent-runtime-api", flag.ContinueOnError)
	configPath := arguments.String("config", "", "absolute path to the strict runtime API configuration")
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
	config, parseErr := runtimeapiprocess.Parse(file)
	closeErr := file.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return fmt.Errorf("close configuration: %w", closeErr)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return runtimeapiprocess.Run(ctx, config, os.LookupEnv, func(address string) {
		logger.Info("runtime API ready", "role", "agent-runtime-api", "address", address)
	})
}
