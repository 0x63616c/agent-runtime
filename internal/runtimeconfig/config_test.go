package runtimeconfig_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimeconfig"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Runtime Configuration Suite")
}

type authorizationSink struct {
	value string
}

func (s *authorizationSink) SetBearerToken(value string) {
	s.value = value
}

var _ = Describe("Configuration", func() {
	It("accepts only explicit, fixed-topic notifier configuration and redacts diagnostics", func() {
		config, err := runtimeconfig.New(runtimeconfig.Input{
			Version:  1,
			Notifier: runtimeconfig.NotifierInput{AccessToken: "top-secret-token"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(config.Notifier.Topic).To(Equal("https://ntfy.sh/0x63616c-ai-agant"))
		Expect(config.Diagnostics()).To(Equal(map[string]string{
			"notifier.access_token": "[REDACTED]",
			"notifier.topic":        "https://ntfy.sh/0x63616c-ai-agant",
			"version":               "1",
		}))
		Expect(fmt.Sprintf("%+v", config)).NotTo(ContainSubstring("top-secret-token"))
		encoded, err := json.Marshal(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).NotTo(ContainSubstring("top-secret-token"))
		Expect(config.LogValue().Kind()).To(Equal(slog.KindGroup))
		sink := &authorizationSink{}
		config.Notifier.ApplyAuthorization(sink)
		Expect(sink.value).To(Equal("top-secret-token"))
	})

	It("rejects a missing version or custom notification URL", func() {
		_, err := runtimeconfig.New(runtimeconfig.Input{})
		Expect(err).To(MatchError(ContainSubstring("config version")))

		_, err = runtimeconfig.New(runtimeconfig.Input{
			Version:  1,
			Notifier: runtimeconfig.NotifierInput{Topic: "https://example.invalid/override", AccessToken: "token"},
		})
		Expect(err).To(MatchError(ContainSubstring("notifier topic")))
	})
})
