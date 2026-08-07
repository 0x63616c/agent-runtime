package stack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyNamespaceEmptyForDeletion(t *testing.T) {
	t.Parallel()

	allowed := []byte(`{"items":[{"kind":"ServiceAccount","metadata":{"name":"default"}},{"kind":"ConfigMap","metadata":{"name":"kube-root-ca.crt"}}]}`)
	require.NoError(t, verifyNamespaceEmptyForDeletion(allowed))

	foreign := []byte(`{"items":[{"kind":"ServiceAccount","metadata":{"name":"default"}},{"kind":"Secret","metadata":{"name":"foreign"}}]}`)
	require.ErrorContains(t, verifyNamespaceEmptyForDeletion(foreign), "undeclared object Secret/foreign")

	malformed := []byte(`{"items":[{"kind":"Secret","metadata":{}}]}`)
	require.ErrorContains(t, verifyNamespaceEmptyForDeletion(malformed), "missing identity")
}
