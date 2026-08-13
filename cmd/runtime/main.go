// Command runtime composes one validated Agent Runtime process role.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0x63616c/agent-runtime/internal/localdemoworker"
	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/tooldispatch"
	"github.com/0x63616c/agent-runtime/sandbox"
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
	if config.Role() == roles.RoleOrchestrationCodec {
		return serveCodecWorker(ctx, config, plan, listener, lookup)
	}
	if config.Role() == roles.RoleToolDispatch {
		return serveToolDispatch(ctx, config, listener, lookup)
	}
	if worker := config.LocalDemoWorker(); worker != nil && worker.Enabled {
		return serveLocalDemoWorker(ctx, config, plan, listener, lookup, logger)
	}
	return roles.Serve(ctx, plan, listener)
}

func serveToolDispatch(ctx context.Context, config roles.Config, listener net.Listener, lookup func(string) (string, bool)) error {
	declaration := config.ToolDispatch()
	controlEndpoint, controlDeclared := config.DependencyEndpoint("sandbox-control")
	if declaration == nil || !controlDeclared {
		return fmt.Errorf("compose tool-dispatch role: validated dispatch/control configuration is required")
	}
	dsn, dsnFound := lookup("TOOL_DISPATCH_STATE_DSN")
	accessKey, accessFound := lookup(declaration.ContentAccessKeyEnvironment)
	secretKey, secretFound := lookup(declaration.ContentSecretKeyEnvironment)
	controlToken, controlTokenFound := lookup(declaration.ControlCredentialEnvironment)
	triggerToken, triggerTokenFound := lookup("TOOL_BROKER_TOKEN")
	if !dsnFound || !accessFound || !secretFound || !controlTokenFound || !triggerTokenFound {
		return fmt.Errorf("compose tool-dispatch role: required private credential is unavailable")
	}
	process, err := tooldispatch.NewProcess(ctx, triggerToken, tooldispatch.ProcessConfig{
		DatabaseDSN:       dsn,
		ContentEndpoint:   declaration.ContentEndpoint,
		ContentBucket:     declaration.ContentBucket,
		ContentAccessKey:  accessKey,
		ContentSecretKey:  secretKey,
		ControlEndpoint:   controlEndpoint,
		ControlServerName: declaration.ControlServerName,
		ControlTrust:      tooldispatch.MountedTrustSource{Path: declaration.ControlTrustBundlePath, Reference: sandbox.TrustBundleRef(declaration.ControlTrustBundleRef)},
		ControlToken:      controlToken,
		Claimer:           "tool-dispatch/" + config.Namespace(),
	})
	if err != nil {
		return err
	}
	defer process.Close()
	certificate, err := tls.LoadX509KeyPair(declaration.ServerCertificatePath, declaration.ServerPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("compose tool-dispatch role: load TLS identity: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(declaration.ServerName) != nil {
		return fmt.Errorf("compose tool-dispatch role: TLS identity does not match declared server name")
	}
	server, err := tooldispatch.NewHTTPServer(process, certificate, declaration.PeerPolicy)
	if err != nil {
		return err
	}
	results := make(chan error, 1)
	go func() { results <- server.ServeTLS(listener, "", "") }()
	select {
	case err := <-results:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve tool-dispatch role: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("stop tool-dispatch role: %w", err)
		}
		err := <-results
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve tool-dispatch role: %w", err)
	}
}

func serveLocalDemoWorker(ctx context.Context, config roles.Config, plan roles.Plan, listener net.Listener, lookup func(string) (string, bool), logger *slog.Logger) error {
	roleContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- roles.Serve(roleContext, plan, listener) }()
	go func() {
		results <- localdemoworker.Run(roleContext, config, lookup, logger.With("component", "local-demo-worker"))
	}()
	err := <-results
	cancel()
	if err != nil {
		return err
	}
	return <-results
}

func serveCodecWorker(ctx context.Context, config roles.Config, plan roles.Plan, listener net.Listener, lookup func(string) (string, bool)) error {
	worker := config.Worker()
	_, stateDeclared := config.DependencyEndpoint("state")
	temporalEndpoint, temporalDeclared := config.DependencyEndpoint("temporal")
	if worker == nil || !stateDeclared || !temporalDeclared {
		return fmt.Errorf("compose orchestration-codec role: validated worker/state/temporal configuration is required")
	}
	dsn, dsnFound := lookup("STATE_DATABASE_DSN")
	token, tokenFound := lookup("TEMPORAL_AUTH_TOKEN")
	accessKey, accessFound := lookup(worker.PayloadAccessKeyEnvironment)
	secretKey, secretFound := lookup(worker.PayloadSecretKeyEnvironment)
	if !dsnFound || !tokenFound || !accessFound || !secretFound {
		return fmt.Errorf("compose orchestration-codec role: required private credential is unavailable")
	}
	auditEndpoint := ""
	auditTimeout := time.Duration(0)
	if worker.AuditSink != nil {
		auditEndpoint = worker.AuditSink.Endpoint
		auditTimeout = time.Duration(worker.AuditSink.TimeoutSeconds) * time.Second
	}
	roleContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- roles.Serve(roleContext, plan, listener) }()
	go func() {
		results <- runtimeorchestration.Run(roleContext, runtimeorchestration.ProcessConfig{
			DatabaseDSN:         dsn,
			TemporalEndpoint:    temporalEndpoint,
			TemporalToken:       token,
			Namespace:           config.Namespace(),
			TaskQueue:           worker.TaskQueue,
			PayloadBlobEndpoint: worker.PayloadBlobEndpoint,
			PayloadBlobBucket:   worker.PayloadBlobBucket,
			PayloadBlobPrefix:   worker.PayloadBlobPrefix,
			PayloadAccessKey:    accessKey,
			PayloadSecretKey:    secretKey,
			AuditSinkEndpoint:   auditEndpoint,
			AuditSinkTimeout:    auditTimeout,
		})
	}()
	err := <-results
	cancel()
	if err != nil {
		return err
	}
	return <-results
}
