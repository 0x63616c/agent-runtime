package workspaceagent

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

func writeTerminal(output io.Writer, format string, values ...any) error {
	if _, err := fmt.Fprintf(output, format, values...); err != nil {
		return fmt.Errorf("write Workspace Agent terminal: %w", err)
	}
	return nil
}
