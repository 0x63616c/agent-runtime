// Command refresh-docs regenerates allow-listed public documentation from declared sources.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/docsrefresh"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("refresh-docs", flag.ContinueOnError)
	rootFlag := flags.String("root", ".", "repository root")
	check := flags.Bool("check", false, "compare only; never write")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	manifestPath := filepath.Join(root, "skills", "refresh-agent-runtime-docs", "source-manifest.json")
	manifestContent, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read docs source manifest: %w", err)
	}
	manifest, err := docsrefresh.LoadManifest(manifestContent)
	if err != nil {
		return err
	}
	if err := docsrefresh.ValidateGoSDKSourceList(ctx, manifest, goSDKSourceLister{root: root}); err != nil {
		return err
	}
	result, err := docsrefresh.Refresh(ctx, root, manifest, docsrefresh.OSFiles{Root: root}, docsrefresh.GitChanges{Root: root}, docsrefresh.Options{Check: *check})
	if err != nil {
		if errors.Is(err, docsrefresh.ErrStale) {
			return fmt.Errorf("%w: %s; run just docs-generate", err, strings.Join(result.Stale, ", "))
		}
		return err
	}
	if *check {
		fmt.Println("generated documentation is current")
		return nil
	}
	if len(result.Changed) == 0 {
		fmt.Println("generated documentation was already current")
	} else {
		fmt.Printf("updated generated documentation: %s\n", strings.Join(result.Changed, ", "))
	}
	if err := runCommand(ctx, root, "just", "docs-check"); err != nil {
		return fmt.Errorf("validate refreshed documentation: %w", err)
	}
	if err := showReviewDiff(ctx, root); err != nil {
		return fmt.Errorf("show exact documentation diff: %w", err)
	}
	return nil
}

type goSDKSourceLister struct {
	root string
}

const (
	goSDKDocsTargetOS   = "linux"
	goSDKDocsTargetArch = "amd64"
)

func (lister goSDKSourceLister) GoSDKFiles(ctx context.Context) ([]string, error) {
	command := exec.CommandContext(ctx, "go", "list", "-f", "{{range .GoFiles}}{{.}}{{\"\\n\"}}{{end}}", "./sdk/go")
	command.Dir = lister.root
	command.Env = goSDKListEnvironment(os.Environ())
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("run go list ./sdk/go: %w", err)
	}
	lines := strings.Fields(string(output))
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		files = append(files, filepath.ToSlash(filepath.Join("sdk", "go", line)))
	}
	return files, nil
}

// goSDKListEnvironment makes public-reference discovery independent of the host Go build target and tags.
func goSDKListEnvironment(base []string) []string {
	blocked := map[string]struct{}{
		"CGO_ENABLED": {},
		"GOARCH":      {},
		"GOFLAGS":     {},
		"GOOS":        {},
	}
	environment := make([]string, 0, len(base)+4)
	for _, value := range base {
		name, _, found := strings.Cut(value, "=")
		if !found {
			continue
		}
		if _, excluded := blocked[name]; !excluded {
			environment = append(environment, value)
		}
	}
	return append(environment,
		"GOOS="+goSDKDocsTargetOS,
		"GOARCH="+goSDKDocsTargetArch,
		"GOFLAGS=",
		"CGO_ENABLED=0",
	)
}

func showReviewDiff(ctx context.Context, root string) error {
	if err := runCommand(ctx, root, "git", docsrefresh.ReviewDiffArgs()...); err != nil {
		return err
	}
	arguments := append([]string{"ls-files", "-z", "--others", "--exclude-standard", "--"}, docsrefresh.ReviewDiffArgs()[4:]...)
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return err
	}
	paths := bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0})
	for _, pathBytes := range paths {
		if len(pathBytes) == 0 {
			continue
		}
		path := string(pathBytes)
		fmt.Printf("untracked documentation diff: %s\n", path)
		command := exec.CommandContext(ctx, "git", "diff", "--no-index", "--no-ext-diff", "--", "/dev/null", path)
		command.Dir = root
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		err := command.Run()
		var exitError *exec.ExitError
		if err != nil && (!errors.As(err, &exitError) || exitError.ExitCode() != 1) {
			return err
		}
	}
	return nil
}

func runCommand(ctx context.Context, root, name string, arguments ...string) error {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = root
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	return command.Run()
}
