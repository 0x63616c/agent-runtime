package sandboxcontrol

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/cockroachdb/errors"
)

// validateDispatchBody keeps durable dispatch metadata secret-free. It does
// not claim that arbitrary command output or bytes are secret-free.
func validateDispatchBody(body string) error {
	if body == "" {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return errors.New("accept sandbox operation: dispatch body must be JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("accept sandbox operation: dispatch body must contain one value")
	}
	if containsSecretMaterial(value, false) {
		return errors.New("accept sandbox operation: dispatch body contains direct secret material")
	}
	return nil
}

func containsSecretMaterial(value any, environment bool) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if environment && secretShapedKey(key) {
				return true
			}
			if secretShapedKey(key) && key != "secret_bindings" && key != "secret_binding" && key != "secret_reference" && key != "secret_references" {
				return true
			}
			if containsSecretMaterial(nested, environment || key == "environment") {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsSecretMaterial(nested, environment) {
				return true
			}
		}
	case string:
		return looksLikeSecret(typed)
	}
	return false
}

func secretShapedKey(key string) bool {
	key = strings.ToUpper(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return '_'
	}, key))
	for _, marker := range []string{"SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL", "AUTHORIZATION"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func looksLikeSecret(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "-----BEGIN ") || strings.HasPrefix(value, "Bearer ") || strings.HasPrefix(value, "sk-") || strings.HasPrefix(value, "AKIA") || bytes.Contains([]byte(value), []byte("aws_secret_access_key"))
}
