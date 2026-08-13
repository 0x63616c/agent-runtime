// Package toolschema owns the deliberately small, versioned JSON Schema
// profile used by model-visible tool catalogs. It is intentionally
// fail-closed: richer JSON Schema composition is not silently interpreted at
// the authority boundary.
package toolschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// VersionV1 identifies the supported bounded object-schema profile.
const VersionV1 = "agent-runtime.tool-input/v1"

// VersionV2 identifies the general JSON Schema draft 2020-12 profile used for
// registered model-visible tool inputs. Schemas are reference-free so
// registration and invocation cannot fetch data, select a caller-provided
// dialect, or recurse through a mutable schema graph.
const VersionV2 = "agent-runtime.tool-input/v2"

// CanonicalSchema validates and canonicalizes one catalog schema. An omitted
// schema is the backwards-compatible no-input tool: it accepts only {}.
func CanonicalSchema(version string, raw []byte) (string, []byte, error) {
	if version == "" && len(raw) == 0 {
		return VersionV1, []byte(`{"additionalProperties":false,"type":"object"}`), nil
	}
	if len(raw) == 0 || len(raw) > 48<<10 {
		return "", nil, errors.New("unsupported tool input schema")
	}
	if version == VersionV2 {
		canonical, err := canonicalGeneralSchema(raw)
		if err != nil {
			return "", nil, err
		}
		return VersionV2, canonical, nil
	}
	if version != VersionV1 {
		return "", nil, errors.New("unsupported tool input schema")
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(raw, &schema); err != nil || schema == nil {
		return "", nil, errors.New("invalid tool input schema")
	}
	if err := validateObjectSchema(schema, 0); err != nil {
		return "", nil, err
	}
	canonical, err := json.Marshal(schema)
	if err != nil || len(canonical) > 48<<10 {
		return "", nil, errors.New("invalid tool input schema")
	}
	return VersionV1, canonical, nil
}

// CanonicalArguments validates a single model request against its catalog
// schema and returns the exact canonical bytes committed into its capability.
func CanonicalArguments(version string, schemaRaw, argumentsRaw []byte) ([]byte, error) {
	canonicalVersion, schemaRaw, err := CanonicalSchema(version, schemaRaw)
	if err != nil {
		return nil, err
	}
	if len(argumentsRaw) == 0 {
		argumentsRaw = []byte(`{}`)
	}
	if len(argumentsRaw) > 48<<10 {
		return nil, errors.New("tool arguments are oversized")
	}
	var arguments map[string]json.RawMessage
	if err := json.Unmarshal(argumentsRaw, &arguments); err != nil || arguments == nil {
		return nil, errors.New("tool arguments must be an object")
	}
	if canonicalVersion == VersionV2 {
		schema, err := compileGeneralSchema(schemaRaw)
		if err != nil {
			return nil, err
		}
		var generalArguments any
		argumentsDecoder := json.NewDecoder(bytes.NewReader(argumentsRaw))
		argumentsDecoder.UseNumber()
		if err := argumentsDecoder.Decode(&generalArguments); err != nil || argumentsDecoder.More() {
			return nil, errors.New("tool arguments must be an object")
		}
		if err := schema.Validate(generalArguments); err != nil {
			return nil, errors.New("tool arguments do not match input schema")
		}
		canonical, err := json.Marshal(arguments)
		if err != nil {
			return nil, errors.New("canonicalize tool arguments")
		}
		return canonical, nil
	}
	var schema map[string]json.RawMessage
	if json.Unmarshal(schemaRaw, &schema) != nil {
		return nil, errors.New("invalid tool input schema")
	}
	if err := validateObject(schema, arguments, 0); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(arguments)
	if err != nil {
		return nil, errors.New("canonicalize tool arguments")
	}
	return canonical, nil
}

func canonicalGeneralSchema(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var schema any
	if err := decoder.Decode(&schema); err != nil || decoder.More() || schema == nil {
		return nil, errors.New("invalid tool input schema")
	}
	if _, ok := schema.(map[string]any); !ok || hasExternalReference(schema) {
		return nil, errors.New("unsupported tool input schema")
	}
	canonical, err := json.Marshal(schema)
	if err != nil || len(canonical) > 48<<10 {
		return nil, errors.New("invalid tool input schema")
	}
	if _, err := compileGeneralSchema(canonical); err != nil {
		return nil, errors.New("invalid tool input schema")
	}
	return canonical, nil
}

func compileGeneralSchema(raw []byte) (*jsonschema.Schema, error) {
	var document any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil || decoder.More() {
		return nil, errors.New("invalid tool input schema")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("urn:agent-runtime:tool-input", document); err != nil {
		return nil, errors.New("invalid tool input schema")
	}
	schema, err := compiler.Compile("urn:agent-runtime:tool-input")
	if err != nil {
		return nil, errors.New("invalid tool input schema")
	}
	return schema, nil
}

func hasExternalReference(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if key == "$schema" {
				return true
			}
			if key == "$ref" || key == "$dynamicRef" {
				return true
			}
			if hasExternalReference(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if hasExternalReference(nested) {
				return true
			}
		}
	}
	return false
}

func validateObjectSchema(schema map[string]json.RawMessage, depth int) error {
	if depth > 16 || schemaType(schema) != "object" {
		return errors.New("unsupported tool input schema")
	}
	allowed := map[string]bool{"type": true, "properties": true, "required": true, "additionalProperties": true}
	for key := range schema {
		if !allowed[key] {
			return errors.New("unsupported tool input schema")
		}
	}
	if raw, ok := schema["properties"]; ok {
		var properties map[string]json.RawMessage
		if json.Unmarshal(raw, &properties) != nil {
			return errors.New("unsupported tool input schema")
		}
		for name, property := range properties {
			if name == "" || len(name) > 128 {
				return errors.New("unsupported tool input schema")
			}
			var child map[string]json.RawMessage
			if json.Unmarshal(property, &child) != nil || child == nil || validateValueSchema(child, depth+1) != nil {
				return errors.New("unsupported tool input schema")
			}
		}
	}
	if raw, ok := schema["required"]; ok {
		var required []string
		if json.Unmarshal(raw, &required) != nil {
			return errors.New("unsupported tool input schema")
		}
	}
	if raw, ok := schema["additionalProperties"]; ok {
		var value bool
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("unsupported tool input schema")
		}
	}
	return nil
}

func validateValueSchema(schema map[string]json.RawMessage, depth int) error {
	if depth > 16 {
		return errors.New("unsupported tool input schema")
	}
	typeName := schemaType(schema)
	if typeName != "string" && typeName != "boolean" && typeName != "number" && typeName != "integer" && typeName != "object" && typeName != "array" {
		return errors.New("unsupported tool input schema")
	}
	allowed := map[string]bool{"type": true, "enum": true, "properties": true, "required": true, "additionalProperties": true, "items": true}
	for key := range schema {
		if !allowed[key] {
			return errors.New("unsupported tool input schema")
		}
	}
	if raw, ok := schema["enum"]; ok {
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
			return errors.New("unsupported tool input schema")
		}
	}
	if typeName == "object" {
		return validateObjectSchema(schema, depth)
	}
	if typeName == "array" {
		raw, ok := schema["items"]
		if !ok {
			return errors.New("unsupported tool input schema")
		}
		var item map[string]json.RawMessage
		if json.Unmarshal(raw, &item) != nil || item == nil {
			return errors.New("unsupported tool input schema")
		}
		return validateValueSchema(item, depth+1)
	}
	return nil
}

func validateObject(schema map[string]json.RawMessage, value map[string]json.RawMessage, depth int) error {
	if depth > 16 || schemaType(schema) != "object" {
		return errors.New("unsupported tool input schema")
	}
	properties := map[string]json.RawMessage{}
	if raw, found := schema["properties"]; found && json.Unmarshal(raw, &properties) != nil {
		return errors.New("unsupported tool input schema")
	}
	if raw, found := schema["required"]; found {
		var required []string
		if json.Unmarshal(raw, &required) != nil {
			return errors.New("unsupported tool input schema")
		}
		for _, name := range required {
			if _, found := value[name]; !found {
				return errors.New("required tool argument is missing")
			}
		}
	}
	additional := true
	if raw, found := schema["additionalProperties"]; found && json.Unmarshal(raw, &additional) != nil {
		return errors.New("unsupported tool input schema")
	}
	for name, raw := range value {
		property, found := properties[name]
		if !found {
			if !additional {
				return errors.New("tool argument is not permitted")
			}
			continue
		}
		var child map[string]json.RawMessage
		if json.Unmarshal(property, &child) != nil || child == nil {
			return errors.New("unsupported tool input schema")
		}
		if err := validateValue(child, raw, depth+1); err != nil {
			return fmt.Errorf("tool argument %q: %w", name, err)
		}
	}
	return nil
}

func validateValue(schema map[string]json.RawMessage, raw json.RawMessage, depth int) error {
	if depth > 16 {
		return errors.New("tool argument nesting exceeds bound")
	}
	if choices, found := schema["enum"]; found {
		var values []json.RawMessage
		if json.Unmarshal(choices, &values) != nil {
			return errors.New("unsupported tool input schema")
		}
		matched := false
		for _, choice := range values {
			if bytes.Equal(compact(choice), compact(raw)) {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("tool argument is not an allowed enum value")
		}
	}
	switch schemaType(schema) {
	case "string":
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return errors.New("tool argument is not a string")
		}
	case "boolean":
		var v bool
		if json.Unmarshal(raw, &v) != nil {
			return errors.New("tool argument is not a boolean")
		}
	case "number":
		var v json.Number
		if json.Unmarshal(raw, &v) != nil {
			return errors.New("tool argument is not a number")
		}
	case "integer":
		var v json.Number
		if json.Unmarshal(raw, &v) != nil {
			return errors.New("tool argument is not an integer")
		}
		if _, err := v.Int64(); err != nil {
			return errors.New("tool argument is not an integer")
		}
	case "object":
		var v map[string]json.RawMessage
		if json.Unmarshal(raw, &v) != nil || v == nil {
			return errors.New("tool argument is not an object")
		}
		return validateObject(schema, v, depth+1)
	case "array":
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return errors.New("tool argument is not an array")
		}
		var item map[string]json.RawMessage
		if json.Unmarshal(schema["items"], &item) != nil || item == nil {
			return errors.New("unsupported tool input schema")
		}
		for _, value := range values {
			if err := validateValue(item, value, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported tool input schema")
	}
	return nil
}

func schemaType(schema map[string]json.RawMessage) string {
	var value string
	if raw, found := schema["type"]; !found || json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value
}
func compact(raw []byte) []byte {
	var out bytes.Buffer
	if json.Compact(&out, raw) != nil {
		return nil
	}
	return out.Bytes()
}
