package stack

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type deleteCaptureRunner struct {
	arguments []string
	input     []byte
}

func (runner *deleteCaptureRunner) Run(_ context.Context, _ string, arguments []string, input []byte) (KubectlCommandResult, error) {
	runner.arguments = append([]string(nil), arguments...)
	runner.input = append([]byte(nil), input...)
	return KubectlCommandResult{}, nil
}

var _ = Describe("Kubernetes preconditioned deletion", func() {
	It("uses exact UID and resource version for a namespaced replacement race", func() {
		runner := &deleteCaptureRunner{}
		adapter := KubectlAdapter{runner: runner}
		manifest := KubernetesManifest{APIVersion: "v1", Kind: "ConfigMap", Metadata: KubernetesMetadata{Name: "owned", Namespace: "ar-feature-a"}}
		observed := observedObject{}
		observed.Metadata.UID = "old-uid"
		observed.Metadata.ResourceVersion = "41"

		err := adapter.deleteObserved(context.Background(), OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "test"}, manifest, observed)

		Expect(err).NotTo(HaveOccurred())
		Expect(runner.arguments).To(ContainElements("delete", "--raw", "/api/v1/namespaces/ar-feature-a/configmaps/owned", "-f", "-"))
		Expect(string(runner.input)).To(Equal("{\"apiVersion\":\"v1\",\"kind\":\"DeleteOptions\",\"preconditions\":{\"uid\":\"old-uid\",\"resourceVersion\":\"41\"}}\n"))
	})
})
