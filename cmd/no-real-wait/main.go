// Command no-real-wait verifies owned Go source has no real-time wait primitive.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/nowait"
)

func main() {
	root := flag.String("root", ".", "root directory to inspect")
	flag.Parse()
	violations, err := nowait.CheckDir(context.Background(), *root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, violation := range violations {
		fmt.Fprintf(os.Stderr, "%s:%d: %s\n", violation.Path, violation.Line, violation.Rule)
	}
	if len(violations) != 0 {
		os.Exit(1)
	}
}
