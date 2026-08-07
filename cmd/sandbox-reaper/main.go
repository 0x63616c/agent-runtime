package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxreaperprocess"
	"github.com/cockroachdb/errors"
)

func main() {
	if err := run(); err != nil {
		_, _ = os.Stderr.WriteString("sandbox-reaper: " + err.Error() + "\n")
		os.Exit(1)
	}
}

func run() error {
	arguments := flag.NewFlagSet("sandbox-reaper", flag.ContinueOnError)
	configPath := arguments.String("config", "", "absolute path to the strict sandbox-reaper configuration")
	if err := arguments.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *configPath == "" || (*configPath)[0] != '/' || arguments.NArg() != 0 {
		return errors.New("--config must be one explicit absolute path")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return errors.Wrap(err, "open sandbox-reaper configuration")
	}
	config, parseErr := sandboxreaperprocess.Parse(file)
	closeErr := file.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return errors.Wrap(closeErr, "close sandbox-reaper configuration")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return sandboxreaperprocess.Run(ctx, config, os.LookupEnv, wallClock{}, boundedWait, func(summary sandboxreaperprocess.Summary) {
		logger.InfoContext(ctx, "sandbox reconciliation pass",
			"observed_at", summary.ObservedAt,
			"recovered_assignments", summary.RecoveredAssignments,
			"claimed_cleanups", summary.ClaimedCleanups,
			"reaped_operations", summary.ReapedOperations)
	})
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
