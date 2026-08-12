package mcptool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// validateArguments applies the intentionally small, fail-closed JSON Schema
// profile accepted for MCP tool descriptors. Full schema composition is not
// silently guessed: unsupported constructs refuse admission at the adapter
// boundary before an external call can occur.
func validateArguments(schemaRaw, argumentsRaw []byte) error {
	var schema map[string]json.RawMessage
	if json.Unmarshal(schemaRaw, &schema) != nil || schema == nil {
		return errors.New("validate MCP tool: invalid pinned input schema")
	}
	var arguments map[string]json.RawMessage
	if json.Unmarshal(argumentsRaw, &arguments) != nil || arguments == nil {
		return errors.New("validate MCP tool: arguments must be an object")
	}
	return validateObject(schema, arguments, 0)
}

func validateObject(schema map[string]json.RawMessage, value map[string]json.RawMessage, depth int) error {
	if depth > 16 || schemaType(schema) != "object" {
		return errors.New("validate MCP tool: unsupported input schema")
	}
	properties := map[string]json.RawMessage{}
	if raw, found := schema["properties"]; found && json.Unmarshal(raw, &properties) != nil {
		return errors.New("validate MCP tool: unsupported input schema")
	}
	if raw, found := schema["required"]; found {
		var required []string
		if json.Unmarshal(raw, &required) != nil {
			return errors.New("validate MCP tool: unsupported input schema")
		}
		for _, name := range required {
			if _, found := value[name]; !found {
				return errors.New("validate MCP tool: required argument is missing")
			}
		}
	}
	additional := true
	if raw, found := schema["additionalProperties"]; found && json.Unmarshal(raw, &additional) != nil {
		return errors.New("validate MCP tool: unsupported input schema")
	}
	for name, raw := range value {
		property, found := properties[name]
		if !found {
			if !additional {
				return errors.New("validate MCP tool: argument is not permitted")
			}
			continue
		}
		var propertySchema map[string]json.RawMessage
		if json.Unmarshal(property, &propertySchema) != nil || propertySchema == nil {
			return errors.New("validate MCP tool: unsupported input schema")
		}
		if err := validateValue(propertySchema, raw, depth+1); err != nil {
			return fmt.Errorf("validate MCP tool argument %q: %w", name, err)
		}
	}
	return nil
}

func validateValue(schema map[string]json.RawMessage, raw json.RawMessage, depth int) error {
	if depth > 16 {
		return errors.New("value nesting exceeds bound")
	}
	if rawEnum, found := schema["enum"]; found {
		var choices []json.RawMessage
		if json.Unmarshal(rawEnum, &choices) != nil {
			return errors.New("unsupported schema enum")
		}
		matched := false
		for _, choice := range choices {
			if bytes.Equal(compactJSON(choice), compactJSON(raw)) {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("value is not in allowed enum")
		}
	}
	switch schemaType(schema) {
	case "string":
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("value is not a string")
		}
	case "boolean":
		var value bool
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("value is not a boolean")
		}
	case "number":
		var value json.Number
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("value is not a number")
		}
	case "integer":
		var value json.Number
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("value is not an integer")
		}
		if _, err := value.Int64(); err != nil {
			return errors.New("value is not an integer")
		}
	case "object":
		var value map[string]json.RawMessage
		if json.Unmarshal(raw, &value) != nil || value == nil {
			return errors.New("value is not an object")
		}
		return validateObject(schema, value, depth+1)
	case "array":
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return errors.New("value is not an array")
		}
		rawItems, found := schema["items"]
		if !found {
			return errors.New("array items schema is required")
		}
		var itemSchema map[string]json.RawMessage
		if json.Unmarshal(rawItems, &itemSchema) != nil || itemSchema == nil {
			return errors.New("unsupported array items schema")
		}
		for _, value := range values {
			if err := validateValue(itemSchema, value, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported input schema type")
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

func compactJSON(raw []byte) []byte {
	var buffer bytes.Buffer
	if json.Compact(&buffer, raw) != nil {
		return nil
	}
	return buffer.Bytes()
}
