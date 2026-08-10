package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRunValidatesOnlyExplicitConfigurationUntilADeclaredClientIsLinked(t *testing.T) {
	t.Parallel()
	config := `{"version":1,"controller_image_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","watch_retry_millis":25}`
	err := run([]string{"--config", "/declared/controller.json"}, func(string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(config)), nil })
	if !errors.Is(err, errNoDeclaredPorts) {
		t.Fatalf("expected explicit unlinked-port refusal, got %v", err)
	}
}

func TestRunRefusesRelativeOrAmbientConfiguration(t *testing.T) {
	t.Parallel()
	if err := run([]string{"--config", "controller.json"}, nil); err == nil {
		t.Fatal("expected relative configuration to be refused")
	}
	if err := run([]string{}, nil); err == nil {
		t.Fatal("expected omitted configuration to be refused")
	}
}
