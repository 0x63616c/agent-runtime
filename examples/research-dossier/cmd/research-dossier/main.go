// Command research-dossier runs the Research Dossier web or terminal example
// through Agent Runtime's public Go SDK only.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	researchdossier "github.com/0x63616c/agent-runtime/examples/research-dossier"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.LookupEnv, os.Stdin, os.Stdout); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, "research-dossier:", err); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, lookup func(string) (string, bool), input *os.File, output *os.File) error {
	flags := flag.NewFlagSet("research-dossier", flag.ContinueOnError)
	mode := flags.String("mode", "terminal", "terminal or web")
	baseURL := flags.String("runtime-url", "", "public Agent Runtime HTTPS or loopback HTTP origin")
	listen := flags.String("listen", "127.0.0.1:8092", "loopback web listen address")
	tokenEnvironment := flags.String("token-env", "AGENT_RUNTIME_DEVELOPER_TOKEN", "environment name containing the public runtime bearer")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || (*mode != "terminal" && *mode != "web") || *baseURL == "" || *tokenEnvironment == "" {
		return fmt.Errorf("usage: research-dossier --mode=terminal|web --runtime-url=<origin> [--listen=127.0.0.1:8092] [--token-env=NAME]")
	}
	token, found := lookup(*tokenEnvironment)
	if !found || token == "" {
		return fmt.Errorf("read Research Dossier runtime credential: %s is unavailable", *tokenEnvironment)
	}
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		return fmt.Errorf("configure Research Dossier runtime credential: %w", err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: *baseURL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: &requestIDs{}})
	if err != nil {
		return fmt.Errorf("configure Research Dossier public client: %w", err)
	}
	app, err := researchdossier.NewApp(client, researchdossier.RandomKeys{})
	if err != nil {
		return err
	}
	if *mode == "terminal" {
		return researchdossier.RunTerminal(ctx, app, input, output)
	}
	if err := requireLoopback(*listen); err != nil {
		return err
	}
	handler, err := researchdossier.NewWebHandler(app)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("serve Research Dossier web: %w", err)
	}
	if _, err := fmt.Fprintln(output, "Research Dossier web ready at http://"+listener.Addr().String()); err != nil {
		return fmt.Errorf("announce Research Dossier web listener: %w", err)
	}
	return http.Serve(listener, handler)
}

type requestIDs struct {
	mu   sync.Mutex
	next uint64
}

func (source *requestIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
}

func requireLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("serve Research Dossier web: listen address must be an explicit loopback address")
	}
	return nil
}
