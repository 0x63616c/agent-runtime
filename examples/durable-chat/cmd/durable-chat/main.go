// Command durable-chat runs the Durable Chat web or terminal example through
// Agent Runtime's public Go SDK only.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	durablechat "github.com/0x63616c/agent-runtime/examples/durable-chat"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.LookupEnv, os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "durable-chat:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, lookup func(string) (string, bool), input *os.File, output *os.File) error {
	flags := flag.NewFlagSet("durable-chat", flag.ContinueOnError)
	mode := flags.String("mode", "terminal", "terminal or web")
	baseURL := flags.String("runtime-url", "", "public Agent Runtime HTTPS or loopback HTTP origin")
	listen := flags.String("listen", "127.0.0.1:8090", "loopback web listen address")
	tokenEnvironment := flags.String("token-env", "AGENT_RUNTIME_DEVELOPER_TOKEN", "environment name containing the public runtime bearer")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || (*mode != "terminal" && *mode != "web") || *baseURL == "" || *tokenEnvironment == "" {
		return fmt.Errorf("usage: durable-chat --mode=terminal|web --runtime-url=<origin> [--listen=127.0.0.1:8090] [--token-env=NAME]")
	}
	token, found := lookup(*tokenEnvironment)
	if !found || token == "" {
		return fmt.Errorf("read Durable Chat runtime credential: %s is unavailable", *tokenEnvironment)
	}
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		return fmt.Errorf("configure Durable Chat runtime credential: %w", err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: *baseURL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: &requestIDs{}})
	if err != nil {
		return fmt.Errorf("configure Durable Chat public client: %w", err)
	}
	app, err := durablechat.NewApp(client, durablechat.RandomKeys{})
	if err != nil {
		return err
	}
	if *mode == "terminal" {
		return durablechat.RunTerminal(ctx, app, input, output)
	}
	if err := requireLoopback(*listen); err != nil {
		return err
	}
	handler, err := durablechat.NewWebHandler(durablechat.WebConfig{App: app})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("serve Durable Chat web: %w", err)
	}
	_, _ = fmt.Fprintln(output, "Durable Chat web ready at http://"+listener.Addr().String())
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
		return fmt.Errorf("serve Durable Chat web: listen address must be an explicit loopback address")
	}
	return nil
}
