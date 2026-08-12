package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
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
	configEnvironment := arguments.String("config-env", "", "environment variable containing the strict runtime API configuration")
	check := arguments.Bool("check", false, "validate configuration and required environment values then exit")
	if err := arguments.Parse(os.Args[1:]); err != nil {
		return err
	}
	config, parseErr := parseConfiguration(*configPath, *configEnvironment, arguments.NArg())
	if parseErr != nil {
		return parseErr
	}
	if *check {
		return runtimeapiprocess.Check(config, os.LookupEnv)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return runtimeapiprocess.Run(ctx, config, os.LookupEnv, func(address string) {
		logger.Info("runtime API ready", "role", "agent-runtime-api", "address", address)
	})
}

func parseConfiguration(configPath, configEnvironment string, arguments int) (runtimeapiprocess.Config, error) {
	if arguments != 0 || (configPath == "" && configEnvironment == "") || (configPath != "" && configEnvironment != "") {
		return runtimeapiprocess.Config{}, fmt.Errorf("pass exactly one of --config or --config-env")
	}
	var input io.Reader
	if configPath != "" {
		if configPath[0] != '/' {
			return runtimeapiprocess.Config{}, fmt.Errorf("--config must be an explicit absolute path")
		}
		file, err := os.Open(configPath)
		if err != nil {
			return runtimeapiprocess.Config{}, fmt.Errorf("open configuration: %w", err)
		}
		defer file.Close()
		input = file
	} else {
		value, found := os.LookupEnv(configEnvironment)
		if !found {
			return runtimeapiprocess.Config{}, fmt.Errorf("read configuration environment %q: not set", configEnvironment)
		}
		input = strings.NewReader(value)
	}
	config, err := runtimeapiprocess.Parse(input)
	if err != nil {
		return runtimeapiprocess.Config{}, err
	}
	return config, nil
}
