package runtimeconfig_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimeconfig"
	"github.com/onsi/gomega"
)

func FuzzConfigurationBoundaryNeverDisclosesToken(f *testing.F) {
	f.Add(1, "", []byte("secret"))
	f.Add(1, runtimeconfig.NtfyTopic, []byte("another secret"))
	f.Add(2, "https://example.invalid", []byte("token"))
	f.Fuzz(func(t *testing.T, version int, topic string, rawToken []byte) {
		g := gomega.NewWithT(t)
		token := "secret-" + hex.EncodeToString(rawToken)
		config, err := runtimeconfig.New(runtimeconfig.Input{Version: version, Notifier: runtimeconfig.NotifierInput{Topic: topic, AccessToken: token}})
		if err != nil {
			g.Expect(err.Error()).NotTo(gomega.ContainSubstring(token))
			return
		}
		g.Expect(version).To(gomega.Equal(1))
		g.Expect(config.Notifier.Topic).To(gomega.Equal(runtimeconfig.NtfyTopic))
		encoded, marshalErr := json.Marshal(config)
		g.Expect(marshalErr).NotTo(gomega.HaveOccurred())
		for _, diagnostic := range []string{fmt.Sprintf("%+v", config), string(encoded), fmt.Sprint(config.Diagnostics())} {
			g.Expect(diagnostic).NotTo(gomega.ContainSubstring(token))
		}
	})
}
