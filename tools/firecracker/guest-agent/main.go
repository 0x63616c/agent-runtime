// Command guest-agent is the project-owned, static smoke-fixture init program.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const protocolVersion = "agent-runtime-firecracker-guest/v1"

const maximumControlLineBytes = 1024

const maximumShutdownDuration = 5 * time.Second

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: guest-agent VM-ID FIXTURE-VERSION")
		os.Exit(2)
	}
	if err := serve(os.Args[1], os.Args[2], os.Stdin, os.Stdout, systemShutdown); err != nil {
		fmt.Fprintln(os.Stderr, "guest-agent:", err)
		os.Exit(1)
	}
}

func serve(vmID, fixtureVersion string, requests io.Reader, responses io.Writer, shutdown func(context.Context) error) error {
	if vmID == "" || fixtureVersion == "" || shutdown == nil {
		return fmt.Errorf("VM ID, fixture version, and controlled shutdown are required")
	}
	if _, err := fmt.Fprintf(responses, "AGENT_RUNTIME_FC_SMOKE %s %s %s\n", vmID, fixtureVersion, protocolVersion); err != nil {
		return fmt.Errorf("write serial marker: %w", err)
	}
	request, err := bufio.NewReader(io.LimitReader(requests, maximumControlLineBytes+1)).ReadString('\n')
	if len(request) > maximumControlLineBytes {
		return fmt.Errorf("control request exceeds %d bytes", maximumControlLineBytes)
	}
	if err != nil {
		return fmt.Errorf("read bounded control request: %w", err)
	}
	fields := strings.Fields(request)
	if len(fields) != 2 || fields[0] != "PING" || fields[1] == "" {
		return fmt.Errorf("invalid control request")
	}
	if _, err := fmt.Fprintf(responses, "PONG %s %s\n", vmID, fields[1]); err != nil {
		return fmt.Errorf("write control response: %w", err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), maximumShutdownDuration)
	defer cancel()
	if err := shutdown(shutdownContext); err != nil {
		return fmt.Errorf("controlled shutdown after PONG: %w", err)
	}
	return nil
}
