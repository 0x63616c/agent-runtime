package toolschema_test

import (
	"bytes"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/toolschema"
)

func TestCanonicalArgumentsUsesTheVersionedFailClosedCatalogSchema(t *testing.T) {
	schema := []byte(`{"additionalProperties":false,"properties":{"path":{"type":"string"},"mode":{"enum":["safe","fast"],"type":"string"}},"required":["path"],"type":"object"}`)
	version, canonical, err := toolschema.CanonicalSchema(toolschema.VersionV1, schema)
	if err != nil || version != toolschema.VersionV1 {
		t.Fatalf("canonical schema = %q %s %v", version, canonical, err)
	}
	arguments, err := toolschema.CanonicalArguments(version, canonical, []byte(`{"mode":"safe","path":"workspace/report.txt"}`))
	if err != nil || !bytes.Equal(arguments, []byte(`{"mode":"safe","path":"workspace/report.txt"}`)) {
		t.Fatalf("canonical arguments = %s, %v", arguments, err)
	}
	for _, invalid := range [][]byte{[]byte(`{"mode":"unsafe","path":"a"}`), []byte(`{"path":1}`), []byte(`{"extra":true,"path":"a"}`), []byte(`{}`)} {
		if _, err := toolschema.CanonicalArguments(version, canonical, invalid); err == nil {
			t.Fatalf("invalid arguments %s were accepted", invalid)
		}
	}
}

func TestLegacyNoInputToolOnlyAcceptsEmptyObject(t *testing.T) {
	if _, err := toolschema.CanonicalArguments("", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := toolschema.CanonicalArguments("", nil, []byte(`{"value":true}`)); err == nil {
		t.Fatal("legacy no-input tool accepted arguments")
	}
}
