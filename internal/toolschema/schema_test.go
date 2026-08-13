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

func TestCanonicalArgumentsSupportsBoundedGeneralJSONSchema(t *testing.T) {
	schema := []byte(`{"additionalProperties":false,"properties":{"destination":{"pattern":"^[a-z]+/[a-z]+\\.txt$","type":"string"},"lines":{"items":{"type":"string","maxLength":32},"maxItems":2,"type":"array"}},"required":["destination","lines"],"type":"object"}`)
	version, canonical, err := toolschema.CanonicalSchema(toolschema.VersionV2, schema)
	if err != nil || version != toolschema.VersionV2 {
		t.Fatalf("canonical general schema = %q %s %v", version, canonical, err)
	}
	arguments, err := toolschema.CanonicalArguments(version, canonical, []byte(`{"lines":["one","two"],"destination":"notes/report.txt"}`))
	if err != nil || !bytes.Equal(arguments, []byte(`{"destination":"notes/report.txt","lines":["one","two"]}`)) {
		t.Fatalf("canonical general arguments = %s, %v", arguments, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"destination":"/tmp/report.txt","lines":["one"]}`),
		[]byte(`{"destination":"notes/report.txt","lines":["one","two","three"]}`),
		[]byte(`{"destination":"notes/report.txt","lines":["one"],"extra":true}`),
	} {
		if _, err := toolschema.CanonicalArguments(version, canonical, invalid); err == nil {
			t.Fatalf("invalid general arguments %s were accepted", invalid)
		}
	}
	integerSchema := []byte(`{"properties":{"value":{"const":9007199254740992}},"required":["value"],"type":"object"}`)
	if _, err := toolschema.CanonicalArguments(toolschema.VersionV2, integerSchema, []byte(`{"value":9007199254740993}`)); err == nil {
		t.Fatal("general schema accepted a distinct integer above float precision")
	}
	if _, _, err := toolschema.CanonicalSchema(toolschema.VersionV2, []byte(`{"$ref":"https://example.test/schema"}`)); err == nil {
		t.Fatal("general schema accepted an external reference")
	}
	if _, _, err := toolschema.CanonicalSchema(toolschema.VersionV2, []byte(`{"$ref":"#"}`)); err == nil {
		t.Fatal("general schema accepted a recursive local reference")
	}
	for _, schema := range [][]byte{
		[]byte(`{"$schema":"https://example.test/draft","type":"object"}`),
		[]byte(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`),
	} {
		if _, _, err := toolschema.CanonicalSchema(toolschema.VersionV2, schema); err == nil {
			t.Fatalf("general schema accepted a caller-selected dialect: %s", schema)
		}
	}
}
