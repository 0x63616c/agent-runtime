package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
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
	arguments, err := parseArguments(os.Args[1:])
	if err != nil {
		return err
	}
	file, err := os.Open(arguments.configPath)
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
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return sandboxhostprocess.Run(ctx, config, os.LookupEnv, wallClock{}, arguments.pollInterval, boundedWait, func(summary sandboxhostprocess.Summary) {
		logger.InfoContext(ctx, "sandbox host poll", "observed_at", summary.ObservedAt, "outcome", summary.Outcome, "ready", summary.Ready, "consecutive_failures", summary.ConsecutiveFailures)
	})
}

type commandArguments struct {
	configPath   string
	pollInterval time.Duration
}

func parseArguments(input []string) (commandArguments, error) {
	arguments := flag.NewFlagSet("sandbox-host", flag.ContinueOnError)
	configPath := arguments.String("config", "", "absolute path to the strict sandbox-host configuration")
	pollInterval := arguments.Duration("poll-interval", 0, "finite interval between control polls")
	if err := arguments.Parse(input); err != nil {
		return commandArguments{}, err
	}
	if *configPath == "" || (*configPath)[0] != '/' || *pollInterval <= 0 || arguments.NArg() != 0 {
		return commandArguments{}, errors.New("--config and --poll-interval must be one explicit absolute path and positive duration")
	}
	return commandArguments{configPath: *configPath, pollInterval: *pollInterval}, nil
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

func boundedWait(ctx context.Context, duration time.Duration) error {
	waitContext, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	<-waitContext.Done()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
