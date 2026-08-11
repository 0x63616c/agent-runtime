package researchdossier

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// RunTerminal runs the Research Dossier terminal UI through the same public
// App controller as the web UI. It never creates a direct worker or blob client.
func RunTerminal(ctx context.Context, app *App, input io.Reader, output io.Writer) error {
	if app == nil || input == nil || output == nil {
		return fmt.Errorf("run Research Dossier terminal: app, input, and output are required")
	}
	if err := terminalWriteLine(output, "Research Dossier terminal. Commands: start <agent-revision> <brief>, research <session> <step>, resume <session> [cursor], artifacts <session>, download <artifact>, quit"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 1024), agentruntime.MaxTextPartBytes+1024)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "quit", "exit":
			return nil
		case "start":
			parts := strings.SplitN(line, " ", 3)
			if len(parts) != 3 {
				if err := terminalError(output, "usage: start <agent-revision> <brief>"); err != nil {
					return err
				}
				continue
			}
			revision, err := agentruntime.ParseAgentRevisionID(parts[1])
			if err == nil {
				operation, cancel := terminalOperationContext(ctx)
				session, _, startErr := app.Start(operation, revision, parts[2])
				cancel()
				err = startErr
				if err == nil {
					if err := terminalWriteLine(output, "session %s", session.ID); err != nil {
						return err
					}
					continue
				}
			}
			if err := terminalError(output, "request could not be completed"); err != nil {
				return err
			}
		case "research":
			parts := strings.SplitN(line, " ", 3)
			if len(parts) != 3 {
				if err := terminalError(output, "usage: research <session> <step>"); err != nil {
					return err
				}
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(parts[1])
			if err == nil {
				operation, cancel := terminalOperationContext(ctx)
				accepted, researchErr := app.Research(operation, sessionID, parts[2])
				cancel()
				err = researchErr
				if err == nil {
					if err := terminalWriteLine(output, "queued turn %s state=%s", accepted.Turn.ID, accepted.Turn.State); err != nil {
						return err
					}
					continue
				}
			}
			if err := terminalError(output, "request could not be completed"); err != nil {
				return err
			}
		case "resume":
			if len(fields) < 2 || len(fields) > 3 {
				if err := terminalError(output, "usage: resume <session> [cursor]"); err != nil {
					return err
				}
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(fields[1])
			if err == nil {
				cursor := agentruntime.Cursor("")
				if len(fields) == 3 {
					cursor, err = agentruntime.ParseCursor(fields[2])
				}
				if err == nil {
					operation, cancel := terminalOperationContext(ctx)
					progress, resumeErr := app.Resume(operation, sessionID, cursor)
					cancel()
					err = resumeErr
					if err == nil {
						if err := terminalWriteLine(output, "state=%s events=%d next_cursor=%s", progress.Session.Session.State, len(progress.Events.Events), progress.Events.NextCursor); err != nil {
							return err
						}
						continue
					}
				}
			}
			if err := terminalError(output, "request could not be completed"); err != nil {
				return err
			}
		case "artifacts":
			if len(fields) != 2 {
				if err := terminalError(output, "usage: artifacts <session>"); err != nil {
					return err
				}
				continue
			}
			sessionID, err := agentruntime.ParseSessionID(fields[1])
			if err == nil {
				operation, cancel := terminalOperationContext(ctx)
				page, listErr := app.Artifacts(operation, sessionID)
				cancel()
				err = listErr
				if err == nil {
					for _, artifact := range page.Artifacts {
						if err := terminalWriteLine(output, "%s %s bytes=%d sha256=%s", artifact.ID, artifact.MediaType, artifact.SizeBytes, artifact.SHA256); err != nil {
							return err
						}
					}
					continue
				}
			}
			if err := terminalError(output, "request could not be completed"); err != nil {
				return err
			}
		case "download":
			if len(fields) != 2 {
				if err := terminalError(output, "usage: download <artifact>"); err != nil {
					return err
				}
				continue
			}
			artifactID, err := agentruntime.ParseArtifactID(fields[1])
			if err == nil {
				operation, cancel := terminalOperationContext(ctx)
				dossier, downloadErr := app.Download(operation, artifactID)
				cancel()
				err = downloadErr
				if err == nil {
					if _, err := output.Write(dossier.Body); err != nil {
						return fmt.Errorf("write Research Dossier terminal: %w", err)
					}
					if err := terminalWriteLine(output, ""); err != nil {
						return err
					}
					continue
				}
			}
			if err := terminalError(output, "request could not be completed"); err != nil {
				return err
			}
		default:
			if err := terminalError(output, "unknown command"); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Research Dossier terminal: %w", err)
	}
	return nil
}

func terminalOperationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 20*time.Second)
}

func terminalWriteLine(output io.Writer, format string, arguments ...any) error {
	if _, err := fmt.Fprintf(output, format+"\n", arguments...); err != nil {
		return fmt.Errorf("write Research Dossier terminal: %w", err)
	}
	return nil
}

func terminalError(output io.Writer, message string) error {
	return terminalWriteLine(output, "error: %s", message)
}
