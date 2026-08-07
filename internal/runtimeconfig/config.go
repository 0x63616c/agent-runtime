// Package runtimeconfig defines explicit, validated process configuration.
package runtimeconfig

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cockroachdb/errors"
)

// NtfyTopic is the only supported milestone notification topic.
const NtfyTopic = "https://ntfy.sh/0x63616c-ai-agant"

// Input is explicit unvalidated runtime configuration from a composition root.
type Input struct {
	// Version selects the supported configuration schema.
	Version int
	// Notifier supplies explicit milestone notification configuration.
	Notifier NotifierInput
}

// NotifierInput is the explicit notifier configuration supplied at startup.
type NotifierInput struct {
	// Topic optionally repeats the one allowlisted notifier topic.
	Topic string
	// AccessToken is passed only to an explicit authorization sink.
	AccessToken string
}

// Config is validated runtime configuration.
type Config struct {
	// Version is the validated configuration schema version.
	Version int
	// Notifier is the validated fixed-topic notifier configuration.
	Notifier NotifierConfig
}

// NotifierConfig is validated fixed-topic notifier configuration.
type NotifierConfig struct {
	// Topic is the validated fixed notifier topic.
	Topic       string
	accessToken string
}

// AuthorizationSink accepts a notifier bearer token without exposing it for diagnostics.
type AuthorizationSink interface {
	// SetBearerToken applies the secret directly to a transport boundary.
	SetBearerToken(string)
}

// New validates input once at the composition boundary.
func New(input Input) (Config, error) {
	if input.Version != 1 {
		return Config{}, errors.Newf("config version must be 1, got %d", input.Version)
	}
	topic := input.Notifier.Topic
	if topic == "" {
		topic = NtfyTopic
	}
	if topic != NtfyTopic {
		return Config{}, errors.Newf("notifier topic must be %s", NtfyTopic)
	}
	return Config{
		Version: input.Version,
		Notifier: NotifierConfig{
			Topic:       topic,
			accessToken: input.Notifier.AccessToken,
		},
	}, nil
}

// Diagnostics returns configuration that is safe to expose to authorized diagnostics.
func (c Config) Diagnostics() map[string]string {
	token := "[NOT CONFIGURED]"
	if c.Notifier.accessToken != "" {
		token = "[REDACTED]"
	}
	return map[string]string{
		"version":               strconv.Itoa(c.Version),
		"notifier.topic":        c.Notifier.Topic,
		"notifier.access_token": token,
	}
}

// String returns a redacted diagnostic representation of Config.
func (c Config) String() string {
	return fmt.Sprintf("Config{Version:%d Notifier:%s}", c.Version, c.Notifier)
}

// LogValue implements slog.LogValuer with only safe configuration values.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("version", c.Version),
		slog.Any("notifier", c.Notifier),
	)
}

// String returns a redacted diagnostic representation of NotifierConfig.
func (c NotifierConfig) String() string {
	return fmt.Sprintf("NotifierConfig{Topic:%s AccessToken:%s}", c.Topic, c.redactedToken())
}

// LogValue implements slog.LogValuer with only safe notifier configuration values.
func (c NotifierConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("topic", c.Topic),
		slog.String("access_token", c.redactedToken()),
	)
}

// ApplyAuthorization supplies the token only to an explicit notifier transport sink.
func (c NotifierConfig) ApplyAuthorization(sink AuthorizationSink) {
	if sink != nil && c.accessToken != "" {
		sink.SetBearerToken(c.accessToken)
	}
}

func (c NotifierConfig) redactedToken() string {
	if c.accessToken == "" {
		return "[NOT CONFIGURED]"
	}
	return "[REDACTED]"
}
