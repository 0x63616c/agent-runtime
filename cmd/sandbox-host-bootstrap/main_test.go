package main

import "testing"

func TestRunRequiresOneAbsoluteConfiguration(t *testing.T) {
	for _, arguments := range [][]string{{}, {"--config", "relative.json"}, {"--config", "/config.json", "extra"}} {
		if err := run(arguments); err == nil {
			t.Fatalf("run(%q) error = nil", arguments)
		}
	}
}
