// Command check-docs-security-audit verifies the explicitly accepted docs dependency audit exception.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/0x63616c/agent-runtime/internal/docssecurityaudit"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := os.Getwd()
	if err != nil {
		fatalf("determine repository root: %v", err)
	}
	lock, err := os.ReadFile(filepath.Join(root, "website", "package-lock.json"))
	if err != nil {
		fatalf("read documentation package lock: %v", err)
	}
	if err := docssecurityaudit.ValidateLock(lock); err != nil {
		fatalf("validate documentation package lock: %v", err)
	}

	command := exec.CommandContext(ctx, "npm", "--prefix", "website", "audit", "--omit=dev", "--json")
	command.Dir = root
	auditJSON, err := command.Output()
	if ctx.Err() != nil {
		fatalf("run documentation production audit: %v", ctx.Err())
	}
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			fatalf("run documentation production audit: %v", err)
		}
	}
	result, err := docssecurityaudit.Validate(auditJSON, time.Now().UTC())
	if err != nil {
		fatalf("validate documentation production audit: %v", err)
	}
	fmt.Printf("DOCUMENTATION SECURITY EXCEPTION ACCEPTED: issue #%d, expires %s; audit still ran and matched only the documented image-size advisories.\n", result.Issue, result.Expires.Format(time.RFC3339))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
