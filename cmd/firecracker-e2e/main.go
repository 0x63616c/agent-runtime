// Command firecracker-e2e records whether this host can run the protected Linux/KVM lane.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

func main() {
	reportPath := flag.String("report", "", "required path for the retained redacted runner report")
	requireKVM := flag.Bool("require-kvm", false, "fail closed when the Linux/KVM runner contract is unavailable")
	flag.Parse()
	if *reportPath == "" {
		fmt.Fprintln(os.Stderr, "firecracker-e2e: -report is required")
		os.Exit(2)
	}
	report := firecracker.LocalEnvironmentReport(func(path string) error {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			_ = file.Close()
		}
		return err
	})
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*reportPath, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "firecracker-e2e: write report: %v\n", err)
		os.Exit(2)
	}
	if *requireKVM && !report.Available {
		fmt.Fprintln(os.Stderr, "firecracker-e2e: Linux/KVM unavailable; see retained report")
		os.Exit(1)
	}
}
