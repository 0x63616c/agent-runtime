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
	_, _ = fmt.Fprintln(output, "Workspace Agent terminal. "+SandboxStatus())
	_, _ = fmt.Fprintln(output, "Commands: list, inspect <approval>, approve <approval> <key>, deny <approval> <key>, cancel <approval> <key>, sandbox-status, quit")
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
			_, _ = fmt.Fprintln(output, SandboxStatus())
		case "list":
			page, err := inbox.List(ctx)
			if err != nil {
				fmt.Fprintf(output, "error: %v\n", err)
				continue
			}
			for _, approval := range page.Approvals {
				_, _ = fmt.Fprintln(output, Terminal(approval))
			}
		case "inspect":
			if len(fields) != 2 {
				fmt.Fprintln(output, "error: usage: inspect <approval>")
				continue
			}
			id, err := agentruntime.ParseApprovalID(fields[1])
			if err == nil {
				var approval agentruntime.Approval
				approval, err = inbox.client.InspectApproval(ctx, id)
				if err == nil {
					_, _ = fmt.Fprintln(output, Terminal(approval))
					continue
				}
			}
			fmt.Fprintf(output, "error: %v\n", err)
		case "approve", "deny":
			if len(fields) != 3 {
				fmt.Fprintln(output, "error: usage: approve|deny <approval> <key>")
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
					_, _ = fmt.Fprintln(output, Terminal(approval))
					continue
				}
			}
			fmt.Fprintf(output, "error: %v\n", err)
		case "cancel":
			if len(fields) != 3 {
				fmt.Fprintln(output, "error: usage: cancel <approval> <key>")
				continue
			}
			id, err := agentruntime.ParseApprovalID(fields[1])
			if err == nil {
				var approval agentruntime.Approval
				approval, err = inbox.client.InspectApproval(ctx, id)
				if err == nil {
					_, err = inbox.Cancel(ctx, approval, fields[2])
					if err == nil {
						fmt.Fprintln(output, "cancel requested")
						continue
					}
				}
			}
			fmt.Fprintf(output, "error: %v\n", err)
		default:
			fmt.Fprintln(output, "error: unknown command")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Workspace Agent terminal: %w", err)
	}
	return nil
}
