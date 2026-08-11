package openapicontract_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestV1CompatibilityBaselineRetainsPublicVocabulary(t *testing.T) {
	t.Parallel()

	baseline := readJSON(t, filepath.Join("..", "..", "api", "openapi", "compatibility-v1.json"))
	contract := readJSON(t, filepath.Join("..", "..", "api", "openapi", "openapi.yaml"))
	assertCompatibleVocabulary(t, baseline, contract)
}

func TestApprovalContractGoldenSchemaCarriesTheSafeRequestProjection(t *testing.T) {
	contract := readJSON(t, filepath.Join("..", "..", "api", "openapi", "openapi.yaml"))
	schemas := object(t, object(t, contract, "components"), "schemas")

	approval := object(t, schemas, "Approval")
	if additional, ok := approval["additionalProperties"].(bool); !ok || additional {
		t.Fatal("Approval contract must reject undocumented fields")
	}
	for _, field := range []string{"id", "session_id", "turn_id", "tool_call_id", "requester", "policy_revision", "state", "action", "scope", "expires_at"} {
		if !contains(array(t, approval, "required"), field) {
			t.Fatalf("Approval contract must retain required %q", field)
		}
	}
	properties := object(t, approval, "properties")
	for _, field := range []string{"id", "session_id", "turn_id", "tool_call_id", "requester", "policy_revision", "action", "scope", "expires_at", "decided_at"} {
		if _, exists := properties[field]; !exists {
			t.Fatalf("Approval contract must expose safe %q", field)
		}
	}
	for _, state := range []any{"pending", "approved", "denied", "expired", "cancelled"} {
		if !contains(array(t, properties["state"].(map[string]any), "enum"), state) {
			t.Fatalf("Approval contract must retain state %q", state)
		}
	}
	action := object(t, schemas, "ApprovalAction")
	if additional, ok := action["additionalProperties"].(bool); !ok || additional || !contains(array(t, action, "required"), "verb") || !contains(array(t, action, "required"), "target") {
		t.Fatalf("Approval action must be a closed required safe summary: %#v", action)
	}
	actionProperties := object(t, action, "properties")
	if !contains(array(t, actionProperties["verb"].(map[string]any), "enum"), "write") || !contains(array(t, actionProperties["target"].(map[string]any), "enum"), "workspace-service") {
		t.Fatalf("Approval action must retain bounded vocabulary: %#v", actionProperties)
	}
	scope := object(t, schemas, "ApprovalScope")
	if additional, ok := scope["additionalProperties"].(bool); !ok || additional || !contains(array(t, scope, "required"), "maximum_uses") {
		t.Fatalf("Approval scope must be a closed required bounded projection: %#v", scope)
	}
	maximumUses := object(t, scope, "properties")["maximum_uses"].(map[string]any)
	if minimum, ok := maximumUses["minimum"].(float64); !ok || minimum != 1 || maximumUses["maximum"] != float64(32) {
		t.Fatalf("Approval scope maximum_uses bounds = %#v, want 1..32", maximumUses)
	}
	turn := object(t, schemas, "Turn")
	states := array(t, object(t, turn, "properties")["state"].(map[string]any), "enum")
	if !contains(states, "waiting_for_approval") {
		t.Fatal("Turn contract must retain waiting_for_approval as a public non-terminal phase")
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value map[string]any
	if err := json.Unmarshal(contents, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func assertCompatibleVocabulary(t *testing.T, baseline, contract map[string]any) {
	t.Helper()
	if contract["openapi"] != baseline["openapi"] {
		t.Fatalf("OpenAPI version = %#v, want retained %#v", contract["openapi"], baseline["openapi"])
	}
	paths := object(t, contract, "paths")
	for _, operation := range array(t, baseline, "operations") {
		value := operation.(map[string]any)
		path, method, id, status := value["path"].(string), value["method"].(string), value["id"].(string), value["status"].(string)
		actual := object(t, paths, path)[method].(map[string]any)
		if actual["operationId"] != id {
			t.Fatalf("%s %s operation = %#v, want %q", method, path, actual["operationId"], id)
		}
		if _, found := object(t, actual, "responses")[status]; !found {
			t.Fatalf("%s %s lost %s response", method, path, status)
		}
	}
	schemas := object(t, object(t, contract, "components"), "schemas")
	for name, expected := range object(t, baseline, "schemas") {
		actual := object(t, schemas, name)
		for _, field := range array(t, expected.(map[string]any), "required") {
			if !contains(array(t, actual, "required"), field) {
				t.Fatalf("schema %s lost required field %q", name, field)
			}
		}
		enums, _ := expected.(map[string]any)["enums"].(map[string]any)
		for field, values := range enums {
			actualEnum := array(t, object(t, actual, "properties")[field].(map[string]any), "enum")
			for _, value := range values.([]any) {
				if !contains(actualEnum, value) {
					t.Fatalf("schema %s.%s lost enum %q", name, field, value)
				}
			}
		}
	}
}

func object(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	result, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object: %s", key, fmt.Sprintf("%#v", value[key]))
	}
	return result
}
func array(t *testing.T, value map[string]any, key string) []any {
	t.Helper()
	result, ok := value[key].([]any)
	if !ok {
		t.Fatalf("%s is not an array", key)
	}
	return result
}
func contains(values []any, wanted any) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
