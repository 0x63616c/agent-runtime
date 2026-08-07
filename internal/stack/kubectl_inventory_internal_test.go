package stack

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Kubectl inventory", func() {
	Describe("verifyNamespaceEmptyForDeletion", func() {
		It("accepts the Kubernetes-owned default objects", func() {
			inventory := []byte(`{"items":[{"kind":"ServiceAccount","metadata":{"name":"default"}},{"kind":"ConfigMap","metadata":{"name":"kube-root-ca.crt"}}]}`)

			Expect(verifyNamespaceEmptyForDeletion(inventory)).To(Succeed())
		})

		It("refuses a foreign object", func() {
			inventory := []byte(`{"items":[{"kind":"ServiceAccount","metadata":{"name":"default"}},{"kind":"Secret","metadata":{"name":"foreign"}}]}`)

			Expect(verifyNamespaceEmptyForDeletion(inventory)).To(MatchError(ContainSubstring("undeclared object Secret/foreign")))
		})

		It("refuses an object without an identity", func() {
			inventory := []byte(`{"items":[{"kind":"Secret","metadata":{}}]}`)

			Expect(verifyNamespaceEmptyForDeletion(inventory)).To(MatchError(ContainSubstring("missing identity")))
		})
	})
})
