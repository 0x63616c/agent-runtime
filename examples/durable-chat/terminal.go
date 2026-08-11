package durablechat

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// RunTerminal runs the Durable Chat terminal UI over the same App controller
// used by the web UI. It never creates a direct Temporal or provider client.
func RunTerminal(ctx context.Context, app *App, input io.Reader, output io.Writer) error {
	if app == nil || input == nil || output == nil {
		return fmt.Errorf("run Durable Chat terminal: app, input, and output are required")
	}
	_, _ = fmt.Fprintln(output, "Durable Chat terminal. Subscription status is unverified; this is not a subscription canary.")
	_, _ = fmt.Fprintln(output, "Commands: new <agent-revision>, resume <session>, send <session> <text>, events <session> [cursor], cancel <session> <turn>, quit")
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 1024), agentruntime.MaxTextPartBytes+1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "quit", "exit":
			return nil
		case "new":
			if len(fields) != 2 {
				writeTerminalError(output, "usage: new <agent-revision>")
				continue
			}
			revision, err := agentruntime.ParseAgentRevisionID(fields[1])
			if err == nil {
				var session agentruntime.Session
				session, err = app.NewSession(ctx, revision)
				if err == nil {
					_, _ = fmt.Fprintf(output, "session %s\n", session.ID)
					continue
				}
			}
			writeTerminalError(output, err)
		case "resume":
			if len(fields) != 2 {
				writeTerminalError(output, "usage: resume <session>")
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(fields[1])
			if err == nil {
				var view agentruntime.SessionView
				view, err = app.Resume(ctx, sessionID)
				if err == nil {
					_, _ = fmt.Fprintf(output, "state=%s queued=%d\n", view.Session.State, view.QueuedTurnCount)
					continue
				}
			}
			writeTerminalError(output, err)
		case "send":
			parts := strings.SplitN(scanner.Text(), " ", 3)
			if len(parts) != 3 {
				writeTerminalError(output, "usage: send <session> <text>")
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(parts[1])
			if err == nil {
				var accepted agentruntime.SendInputResult
				accepted, err = app.Send(ctx, sessionID, parts[2])
				if err == nil {
					_, _ = fmt.Fprintf(output, "queued turn %s state=%s\n", accepted.Turn.ID, accepted.Turn.State)
					continue
				}
			}
			writeTerminalError(output, err)
		case "events":
			if len(fields) < 2 || len(fields) > 3 {
				writeTerminalError(output, "usage: events <session> [cursor]")
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(fields[1])
			if err == nil {
				cursor := agentruntime.Cursor("")
				if len(fields) == 3 {
					cursor = agentruntime.Cursor(fields[2])
				}
				var page agentruntime.EventPage
				page, err = app.Reconnect(ctx, sessionID, cursor)
				if err == nil {
					_, _ = fmt.Fprintf(output, "events=%d next_cursor=%s\n", len(page.Events), page.NextCursor)
					continue
				}
			}
			writeTerminalError(output, err)
		case "cancel":
			if len(fields) != 3 {
				writeTerminalError(output, "usage: cancel <session> <turn>")
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(fields[1])
			if err == nil {
				turnID, turnErr := agentruntime.ParseTurnID(fields[2])
				if turnErr != nil {
					err = turnErr
				} else {
					turn, cancelErr := app.Cancel(ctx, sessionID, turnID)
					err = cancelErr
					if err == nil {
						_, _ = fmt.Fprintf(output, "turn %s state=%s\n", turn.ID, turn.State)
						continue
					}
				}
			}
			writeTerminalError(output, err)
		default:
			writeTerminalError(output, "unknown command")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Durable Chat terminal: %w", err)
	}
	return nil
}

func writeTerminalError(output io.Writer, err any) { _, _ = fmt.Fprintf(output, "error: %v\n", err) }
