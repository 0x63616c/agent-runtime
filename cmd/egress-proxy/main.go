// Command egress-proxy runs a finite allowlisted HTTP and HTTPS CONNECT proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/0x63616c/agent-runtime/internal/egressproxy"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("egress-proxy", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listenAddress := flags.String("listen", "", "explicit proxy bind address")
	allowedTargets := targetFlags{}
	flags.Var(&allowedTargets, "allowed-target", "exact allowed host:port; repeat for each target")
	check := flags.Bool("check", false, "validate proxy composition without listening")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse egress proxy command: %w", err)
	}
	if err := validateListenAddress(*listenAddress); err != nil {
		return err
	}
	proxy, err := egressproxy.New(egressproxy.Config{AllowedTargets: []egressproxy.Target(allowedTargets)})
	if err != nil {
		return err
	}
	if *check {
		return nil
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen egress proxy: %w", err)
	}
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("serve egress proxy: %w", err)
	case <-ctx.Done():
		if err := server.Shutdown(context.WithoutCancel(ctx)); err != nil {
			return fmt.Errorf("stop egress proxy: %w", err)
		}
		if err := <-result; err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("serve egress proxy: %w", err)
		}
		return nil
	}
}

type targetFlags []egressproxy.Target

func (targets *targetFlags) String() string { return "" }

func (targets *targetFlags) Set(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" || strings.Contains(host, "[") {
		return fmt.Errorf("validate egress proxy target: expected exact host:port")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("validate egress proxy target: %w", err)
	}
	*targets = append(*targets, egressproxy.Target{Host: host, Port: parsedPort})
	return nil
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" || (host != "127.0.0.1" && host != "0.0.0.0" && host != "::1" && host != "::") {
		return fmt.Errorf("validate egress proxy command: --listen must be an explicit local bind address")
	}
	return nil
}
