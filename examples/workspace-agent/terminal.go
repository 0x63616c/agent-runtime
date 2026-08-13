package workspaceagent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// RunTerminal runs the public-contract Workspace Agent approval TUI.
func RunTerminal(ctx context.Context, inbox *Inbox, input io.Reader, output io.Writer) error {
	if inbox == nil || input == nil || output == nil {
		return fmt.Errorf("run Workspace Agent terminal: inbox, input, and output are required")
	}
	if err := writeTerminal(output, "Workspace Agent terminal. %s\n", SandboxStatus()); err != nil {
		return err
	}
	if err := writeTerminal(output, "Commands: list, inspect <approval>, approve <approval> <key>, deny <approval> <key>, cancel <approval> <key>, sandbox-status, quit\n"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "quit", "exit":
			return nil
		case "sandbox-status":
			if err := writeTerminal(output, "%s\n", SandboxStatus()); err != nil {
				return err
			}
		case "list":
			page, err := inbox.List(ctx)
			if err != nil {
				if err := writeTerminal(output, "error: %v\n", err); err != nil {
					return err
				}
				continue
			}
			for _, approval := range page.Approvals {
				if err := writeTerminal(output, "%s\n", Terminal(approval)); err != nil {
					return err
				}
			}
		case "inspect":
			if len(fields) != 2 {
				if err := writeTerminal(output, "error: usage: inspect <approval>\n"); err != nil {
					return err
				}
				continue
			}
			id, err := agentruntime.ParseApprovalID(fields[1])
			if err == nil {
				var approval agentruntime.Approval
				approval, err = inbox.client.InspectApproval(ctx, id)
				if err == nil {
					if err := writeTerminal(output, "%s\n", Terminal(approval)); err != nil {
						return err
					}
					continue
				}
			}
			if err := writeTerminal(output, "error: %v\n", err); err != nil {
				return err
			}
		case "approve", "deny":
			if len(fields) != 3 {
				if err := writeTerminal(output, "error: usage: approve|deny <approval> <key>\n"); err != nil {
					return err
				}
				continue
			}
			id, err := agentruntime.ParseApprovalID(fields[1])
			decision := agentruntime.ApprovalApproved
			if fields[0] == "deny" {
				decision = agentruntime.ApprovalDenied
			}
			if err == nil {
				var approval agentruntime.Approval
				approval, err = inbox.Decide(ctx, id, decision, fields[2])
				if err == nil {
					if err := writeTerminal(output, "%s\n", Terminal(approval)); err != nil {
						return err
					}
					continue
				}
			}
			if err := writeTerminal(output, "error: %v\n", err); err != nil {
				return err
			}
		case "cancel":
			if len(fields) != 3 {
				if err := writeTerminal(output, "error: usage: cancel <approval> <key>\n"); err != nil {
					return err
				}
				continue
			}
			id, err := agentruntime.ParseApprovalID(fields[1])
			if err == nil {
				var approval agentruntime.Approval
				approval, err = inbox.client.InspectApproval(ctx, id)
				if err == nil {
					_, err = inbox.Cancel(ctx, approval, fields[2])
					if err == nil {
						if err := writeTerminal(output, "cancel requested\n"); err != nil {
							return err
						}
						continue
					}
				}
			}
			if err := writeTerminal(output, "error: %v\n", err); err != nil {
				return err
			}
		default:
			if err := writeTerminal(output, "error: unknown command\n"); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Workspace Agent terminal: %w", err)
	}
	return nil
}

// RunWorkspaceTerminal runs the durable Workspace Agent work view alongside
// the approval inbox. It has no direct sandbox-control client.
func RunWorkspaceTerminal(ctx context.Context, app *App, inbox *Inbox, input io.Reader, output io.Writer) error {
	if app == nil || inbox == nil || input == nil || output == nil {
		return fmt.Errorf("run Workspace Agent terminal: app, inbox, input, and output are required")
	}
	if err := writeTerminal(output, "Workspace Agent terminal. %s\n", SandboxStatus()); err != nil {
		return err
	}
	if err := writeTerminal(output, "Commands: new <agent-revision>, request <session> <text>, resume <session>, events <session> [cursor], output <session> <turn>, cancel-turn <session> <turn>, approvals, quit\n"); err != nil {
		return err
	}
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
				_ = writeTerminal(output, "error: usage: new <agent-revision>\n")
				continue
			}
			revision, err := agentruntime.ParseAgentRevisionID(fields[1])
			if err == nil {
				var session agentruntime.Session
				session, err = app.NewSession(ctx, revision)
				if err == nil {
					_ = writeTerminal(output, "session %s\n", session.ID)
					continue
				}
			}
			_ = writeTerminal(output, "error: %v\n", err)
		case "request":
			parts := strings.SplitN(scanner.Text(), " ", 3)
			if len(parts) != 3 {
				_ = writeTerminal(output, "error: usage: request <session> <text>\n")
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(parts[1])
			if err == nil {
				var accepted agentruntime.SendInputResult
				accepted, err = app.Request(ctx, sessionID, parts[2])
				if err == nil {
					_ = writeTerminal(output, "queued turn %s state=%s\n", accepted.Turn.ID, accepted.Turn.State)
					continue
				}
			}
			_ = writeTerminal(output, "error: %v\n", err)
		case "resume", "events", "output", "cancel-turn":
			if err := runWorkspaceTerminalQuery(ctx, app, output, fields); err != nil {
				_ = writeTerminal(output, "error: %v\n", err)
			}
		case "approvals":
			page, err := inbox.List(ctx)
			if err != nil {
				_ = writeTerminal(output, "error: %v\n", err)
				continue
			}
			for _, approval := range page.Approvals {
				_ = writeTerminal(output, "%s\n", Terminal(approval))
			}
		default:
			_ = writeTerminal(output, "error: unknown command\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Workspace Agent terminal: %w", err)
	}
	return nil
}

func runWorkspaceTerminalQuery(ctx context.Context, app *App, output io.Writer, fields []string) error {
	if len(fields) < 2 || len(fields) > 3 {
		return fmt.Errorf("usage: resume <session>, events <session> [cursor], output|cancel-turn <session> <turn>")
	}
	sessionID, err := agentruntime.ParseSessionID(fields[1])
	if err != nil {
		return err
	}
	switch fields[0] {
	case "resume":
		if len(fields) != 2 {
			return fmt.Errorf("usage: resume <session>")
		}
		view, err := app.Resume(ctx, sessionID)
		if err != nil {
			return err
		}
		return writeTerminal(output, "state=%s queued=%d\n", view.Session.State, view.QueuedTurnCount)
	case "events":
		cursor := agentruntime.Cursor("")
		if len(fields) == 3 {
			cursor = agentruntime.Cursor(fields[2])
		}
		page, err := app.Reconnect(ctx, sessionID, cursor)
		if err != nil {
			return err
		}
		return writeTerminal(output, "events=%d next_cursor=%s\n", len(page.Events), page.NextCursor)
	case "output", "cancel-turn":
		if len(fields) != 3 {
			return fmt.Errorf("usage: %s <session> <turn>", fields[0])
		}
		turnID, err := agentruntime.ParseTurnID(fields[2])
		if err != nil {
			return err
		}
		if fields[0] == "output" {
			projected, err := app.ReadOutput(ctx, sessionID, turnID)
			if err != nil {
				return err
			}
			return writeTerminal(output, "%s\n", strconv.QuoteToGraphic(projected.Text))
		}
		turn, err := app.Cancel(ctx, sessionID, turnID)
		if err != nil {
			return err
		}
		return writeTerminal(output, "turn %s state=%s\n", turn.ID, turn.State)
	default:
		return fmt.Errorf("unknown command")
	}
}

func writeTerminal(output io.Writer, format string, values ...any) error {
	if _, err := fmt.Fprintf(output, format, values...); err != nil {
		return fmt.Errorf("write Workspace Agent terminal: %w", err)
	}
	return nil
}
