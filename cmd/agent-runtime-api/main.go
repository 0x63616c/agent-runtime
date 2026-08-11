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
	check := arguments.Bool("check", false, "validate configuration and exit")
	if err := arguments.Parse(os.Args[1:]); err != nil {
		return err
	}
	if arguments.NArg() != 0 || (*configPath == "" && *configEnvironment == "") || (*configPath != "" && *configEnvironment != "") {
		return fmt.Errorf("pass exactly one of --config=<absolute-path> or --config-env=<name>")
	}
	var source io.Reader
	var closeSource func() error
	if *configEnvironment != "" {
		value, found := os.LookupEnv(*configEnvironment)
		if !found || value == "" {
			return fmt.Errorf("read configuration environment %q", *configEnvironment)
		}
		source, closeSource = strings.NewReader(value), func() error { return nil }
	} else {
		if (*configPath)[0] != '/' {
			return fmt.Errorf("--config must be an explicit absolute path")
		}
		file, err := os.Open(*configPath)
		if err != nil {
			return fmt.Errorf("open configuration: %w", err)
		}
		source, closeSource = file, file.Close
	}
	config, parseErr := runtimeapiprocess.Parse(source)
	closeErr := closeSource()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return fmt.Errorf("close configuration: %w", closeErr)
	}
	if *check {
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return runtimeapiprocess.Run(ctx, config, os.LookupEnv, func(address string) {
		logger.Info("runtime API ready", "role", "agent-runtime-api", "address", address)
	})
}
