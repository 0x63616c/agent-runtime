package main

import (
	"bytes"
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
	config, check, err := loadConfig(os.Args[1:], os.LookupEnv)
	if err != nil {
		return err
	}
	if check {
		return runtimeapiprocess.Check(config, os.LookupEnv)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if config.HasOTLPExporter() {
		return runtimeapiprocess.RunWithExportingTelemetry(ctx, config, os.LookupEnv, func(address string) {
			logger.Info("runtime API ready", "role", "agent-runtime-api", "address", address)
		})
	}
	return runtimeapiprocess.Run(ctx, config, os.LookupEnv, func(address string) {
		logger.Info("runtime API ready", "role", "agent-runtime-api", "address", address)
	})
}

func loadConfig(argumentsInput []string, lookup func(string) (string, bool)) (runtimeapiprocess.Config, bool, error) {
	arguments := flag.NewFlagSet("agent-runtime-api", flag.ContinueOnError)
	configPath := arguments.String("config", "", "absolute path to the strict runtime API configuration")
	configEnvironment := arguments.String("config-env", "", "environment variable containing the strict runtime API configuration")
	check := arguments.Bool("check", false, "validate configuration without listening")
	if err := arguments.Parse(argumentsInput); err != nil {
		return runtimeapiprocess.Config{}, false, fmt.Errorf("parse runtime API command: %w", err)
	}
	if (*configPath == "" && *configEnvironment == "") || (*configPath != "" && *configEnvironment != "") || arguments.NArg() != 0 {
		return runtimeapiprocess.Config{}, false, fmt.Errorf("validate runtime API command: exactly one of --config or --config-env is required")
	}
	if *configPath != "" {
		if (*configPath)[0] != '/' {
			return runtimeapiprocess.Config{}, false, fmt.Errorf("validate runtime API command: --config must be an explicit absolute path")
		}
		file, err := os.Open(*configPath)
		if err != nil {
			return runtimeapiprocess.Config{}, false, fmt.Errorf("open runtime API configuration: %w", err)
		}
		config, parseErr := runtimeapiprocess.Parse(file)
		closeErr := file.Close()
		if parseErr != nil {
			return runtimeapiprocess.Config{}, false, parseErr
		}
		if closeErr != nil {
			return runtimeapiprocess.Config{}, false, fmt.Errorf("close runtime API configuration: %w", closeErr)
		}
		return config, *check, nil
	}
	value, found := lookup(*configEnvironment)
	if !found || value == "" {
		return runtimeapiprocess.Config{}, false, fmt.Errorf("read runtime API configuration: %s is unavailable", *configEnvironment)
	}
	config, err := runtimeapiprocess.Parse(bytes.NewReader([]byte(value)))
	if err != nil {
		return runtimeapiprocess.Config{}, false, err
	}
	return config, *check, nil
}
