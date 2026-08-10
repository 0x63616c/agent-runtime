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

const guestControlPort uint32 = 10777

// guestControlConnection is the one private, one-shot connection accepted by
// the static init. It deliberately has no facility for proxying arbitrary
// guest traffic.
type guestControlConnection interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
}

// guestControlListener accepts one private AF_VSOCK control connection.
type guestControlListener interface {
	Accept() (guestControlConnection, error)
	Close() error
	SetDeadline(time.Time) error
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: guest-agent VM-ID FIXTURE-VERSION")
		os.Exit(2)
	}
	if err := serveGuestControl(os.Args[1], os.Args[2], os.Stdout, newGuestControlListener, systemShutdown); err != nil {
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

// serveGuestControl keeps the serial marker as boot evidence, then accepts
// exactly one private guest-control connection before shutting down.
func serveGuestControl(vmID, fixtureVersion string, serial io.Writer, listen func() (guestControlListener, error), shutdown func(context.Context) error) error {
	if !validGuestIdentity(vmID) || !validGuestIdentity(fixtureVersion) || serial == nil || listen == nil || shutdown == nil {
		return fmt.Errorf("VM ID, fixture version, serial output, listener, and controlled shutdown are required")
	}
	listener, err := listen()
	if err != nil {
		return fmt.Errorf("bind fixed guest control port: %w", err)
	}
	defer listener.Close()
	if _, err := fmt.Fprintf(serial, "AGENT_RUNTIME_FC_SMOKE %s %s %s\n", vmID, fixtureVersion, protocolVersion); err != nil {
		return fmt.Errorf("write serial marker: %w", err)
	}
	deadline := time.Now().Add(maximumShutdownDuration)
	if err := listener.SetDeadline(deadline); err != nil {
		return fmt.Errorf("bound guest control listener deadline: %w", err)
	}
	connection, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept one guest control connection: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("bound guest control connection deadline: %w", err)
	}
	if err := serveGuestHandshake(vmID, fixtureVersion, connection); err != nil {
		return err
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), maximumShutdownDuration)
	defer cancel()
	if err := shutdown(shutdownContext); err != nil {
		return fmt.Errorf("controlled shutdown after guest control PONG: %w", err)
	}
	return nil
}

func serveGuestHandshake(vmID, fixtureVersion string, connection guestControlConnection) error {
	frames := bufio.NewReaderSize(connection, maximumControlLineBytes+1)
	connect, err := readControlFrame(frames)
	if err != nil {
		return err
	}
	if len(connect) != 3 || connect[0] != "CONNECT" || connect[1] != vmID || connect[2] != fixtureVersion {
		return fmt.Errorf("invalid guest control CONNECT frame")
	}
	if _, err := fmt.Fprintf(connection, "OK %s %s\n", vmID, fixtureVersion); err != nil {
		return fmt.Errorf("write guest control OK frame: %w", err)
	}
	ping, err := readControlFrame(frames)
	if err != nil {
		return err
	}
	if len(ping) != 2 || ping[0] != "PING" || !validControlToken(ping[1]) {
		return fmt.Errorf("invalid guest control PING frame")
	}
	if _, err := fmt.Fprintf(connection, "PONG %s %s\n", vmID, ping[1]); err != nil {
		return fmt.Errorf("write guest control PONG frame: %w", err)
	}
	return nil
}

func readControlFrame(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) == 0 || len(line) > maximumControlLineBytes || line[len(line)-1] != '\n' {
		return nil, fmt.Errorf("invalid or oversized guest control frame")
	}
	fields := strings.Split(string(line[:len(line)-1]), " ")
	if len(fields) == 0 {
		return nil, fmt.Errorf("invalid guest control frame")
	}
	for _, field := range fields {
		if !validControlToken(field) {
			return nil, fmt.Errorf("invalid guest control frame")
		}
	}
	return fields, nil
}

func validControlToken(token string) bool {
	if token == "" {
		return false
	}
	for _, character := range token {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validGuestIdentity(value string) bool {
	if len(value) == 0 || len(value) > 63 || !guestIdentityAlphaNumeric(value[0]) || !guestIdentityAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if value[index] != '-' && !guestIdentityAlphaNumeric(value[index]) {
			return false
		}
	}
	return true
}

func guestIdentityAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}
