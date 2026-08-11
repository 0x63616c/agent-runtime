// Command workspace-agent runs the public Workspace Agent approval UI.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	workspaceagent "github.com/0x63616c/agent-runtime/examples/workspace-agent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.LookupEnv, os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "workspace-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, lookup func(string) (string, bool), input *os.File, output *os.File) error {
	flags := flag.NewFlagSet("workspace-agent", flag.ContinueOnError)
	mode := flags.String("mode", "terminal", "terminal or web")
	origin := flags.String("runtime-url", "", "public runtime origin")
	listen := flags.String("listen", "127.0.0.1:8091", "loopback web listen address")
	tokenEnv := flags.String("token-env", "AGENT_RUNTIME_DEVELOPER_TOKEN", "runtime bearer environment name")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || (*mode != "terminal" && *mode != "web") || *origin == "" {
		return fmt.Errorf("usage: workspace-agent --mode=terminal|web --runtime-url=<origin> [--listen=127.0.0.1:8091] [--token-env=NAME]")
	}
	token, found := lookup(*tokenEnv)
	if !found || token == "" {
		return fmt.Errorf("read Workspace Agent runtime credential: %s is unavailable", *tokenEnv)
	}
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		return err
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: *origin, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: &requestIDs{}})
	if err != nil {
		return err
	}
	inbox, err := workspaceagent.NewInbox(client)
	if err != nil {
		return err
	}
	if *mode == "terminal" {
		return workspaceagent.RunTerminal(ctx, inbox, input, output)
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("serve Workspace Agent web: listen address must be explicit loopback")
	}
	handler, err := workspaceagent.NewWebHandler(inbox)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(output, "Workspace Agent web ready at http://"+listener.Addr().String())
	return http.Serve(listener, handler)
}

type requestIDs struct{ next uint64 }

func (source *requestIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
}
