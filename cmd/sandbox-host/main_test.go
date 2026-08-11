package main

import (
	"testing"
	"time"
)

func TestParseArgumentsRequiresExplicitFinitePollInterval(t *testing.T) {
	t.Parallel()

	arguments, err := parseArguments([]string{"--config", "/etc/sandbox-host/host.json", "--poll-interval", "2s"})
	if err != nil || arguments.configPath != "/etc/sandbox-host/host.json" || arguments.pollInterval != 2*time.Second {
		t.Fatalf("parseArguments() = %#v, %v", arguments, err)
	}
	for _, input := range [][]string{
		{"--config", "/etc/sandbox-host/host.json"},
		{"--config", "host.json", "--poll-interval", "1s"},
		{"--config", "/etc/sandbox-host/host.json", "--poll-interval", "0s"},
		{"--config", "/etc/sandbox-host/host.json", "--poll-interval", "1s", "unexpected"},
	} {
		if _, err := parseArguments(input); err == nil {
			t.Fatalf("parseArguments(%q) accepted unsafe host daemon arguments", input)
		}
	}
}

func TestParseArgumentsSelectsTheExplicitFailClosedFirecrackerControlBridge(t *testing.T) {
	t.Parallel()

	arguments, err := parseArguments([]string{"--config", "/etc/sandbox-host/host.json", "--poll-interval", "2s", "--firecracker-control"})
	if err != nil || !arguments.firecrackerControl {
		t.Fatalf("parseArguments(Firecracker bridge) = %#v, %v", arguments, err)
	}
}
