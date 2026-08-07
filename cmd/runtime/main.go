// Command runtime composes one validated Agent Runtime process role.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/roles"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.LookupEnv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, lookup func(string) (string, bool)) error {
	if len(arguments) > 0 && arguments[0] == "serve" {
		arguments = arguments[1:]
	}
	flags := flag.NewFlagSet("runtime", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "operator role configuration file")
	configEnvironment := flags.String("config-env", "", "environment variable containing operator role configuration")
	roleArgument := flags.String("role", "", "declared runtime role")
	check := flags.Bool("check", false, "validate role composition without listening")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse runtime command: %w", err)
	}
	if (*configPath == "" && *configEnvironment == "") || (*configPath != "" && *configEnvironment != "") || *roleArgument == "" {
		return fmt.Errorf("validate runtime command: exactly one of --config or --config-env, and --role, are required")
	}
	var configInput *os.File
	var inlineConfig []byte
	if *configPath != "" {
		file, err := os.Open(*configPath)
		if err != nil {
			return fmt.Errorf("open runtime role configuration: %w", err)
		}
		configInput = file
	} else {
		value, found := lookup(*configEnvironment)
		if !found || value == "" {
			return fmt.Errorf("read runtime role configuration: %s is unavailable", *configEnvironment)
		}
		inlineConfig = []byte(value)
	}
	var config roles.Config
	var err error
	if configInput != nil {
		config, err = roles.Parse(configInput)
		if closeErr := configInput.Close(); closeErr != nil && err == nil {
			return fmt.Errorf("close runtime role configuration: %w", closeErr)
		}
	} else {
		config, err = roles.Parse(bytes.NewReader(inlineConfig))
	}
	if err != nil {
		return err
	}
	if *roleArgument != string(config.Role()) {
		return fmt.Errorf("validate runtime command: --role must equal the configured trust-scoped role")
	}
	secrets, err := roles.NewEnvironmentSecretSource(lookup)
	if err != nil {
		return err
	}
	plan, err := roles.Prepare(ctx, config, secrets)
	if err != nil {
		return err
	}
	if *check {
		return nil
	}
	listener, err := net.Listen("tcp", config.ListenAddress())
	if err != nil {
		return fmt.Errorf("listen runtime role: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("role", plan.Role(), "namespace", config.Namespace())
	logger.Info("serve runtime role", "address", listener.Addr().String())
	return roles.Serve(ctx, plan, listener)
}
