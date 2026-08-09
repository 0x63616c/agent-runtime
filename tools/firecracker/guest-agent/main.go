// Command guest-agent is the project-owned, static smoke-fixture init program.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const protocolVersion = "agent-runtime-firecracker-guest/v1"

const maximumControlLineBytes = 1024

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: guest-agent VM-ID FIXTURE-VERSION")
		os.Exit(2)
	}
	if err := serve(os.Args[1], os.Args[2], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "guest-agent:", err)
		os.Exit(1)
	}
}

func serve(vmID, fixtureVersion string, requests io.Reader, responses io.Writer) error {
	if vmID == "" || fixtureVersion == "" {
		return fmt.Errorf("VM ID and fixture version are required")
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
	return nil
}
