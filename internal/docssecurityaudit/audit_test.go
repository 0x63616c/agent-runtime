package docssecurityaudit

import (
	"strings"
	"testing"
	"time"
)

const acceptedAudit = `{
  "metadata":{"vulnerabilities":{"high":2,"critical":0}},
  "vulnerabilities":{
    "@docusaurus/mdx-loader":{"severity":"high","via":["image-size"]},
    "image-size":{"severity":"high","via":[
      {"url":"https://github.com/advisories/GHSA-w3rx-r6r6-pgpr"},
      {"url":"https://github.com/advisories/GHSA-5p2g-fcmc-qvqq"}
    ]}
  }
}`

func TestValidateAcceptsOnlyTheDocumentedImageSizeException(t *testing.T) {
	result, err := Validate([]byte(acceptedAudit), time.Date(2026, time.August, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Issue != 36 {
		t.Fatalf("result issue = %d, want 36", result.Issue)
	}
}

func TestValidateRefusesAnUnexpectedHighAdvisory(t *testing.T) {
	audit := strings.Replace(acceptedAudit, `"image-size":{"severity":"high"`, `"unapproved":{"severity":"high","via":[{"url":"https://github.com/advisories/GHSA-unapproved"}]},"image-size":{"severity":"high"`, 1)
	_, err := Validate([]byte(audit), time.Date(2026, time.August, 10, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("Validate() error = %v, want unapproved advisory refusal", err)
	}
}

func TestValidateRefusesTheExpiredException(t *testing.T) {
	_, err := Validate([]byte(acceptedAudit), time.Date(2026, time.November, 9, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Validate() error = %v, want expiry refusal", err)
	}
}

func TestValidateRefusesAResolvedAuditUntilTheExceptionIsRemoved(t *testing.T) {
	resolved := `{"metadata":{"vulnerabilities":{"high":0,"critical":0}},"vulnerabilities":{}}`
	_, err := Validate([]byte(resolved), time.Date(2026, time.August, 10, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "remove") {
		t.Fatalf("Validate() error = %v, want stale exception refusal", err)
	}
}

func TestValidateLockRequiresTheAcceptedImageSizeVersion(t *testing.T) {
	lock := []byte(`{"packages":{"node_modules/image-size":{"version":"2.0.2"}}}`)
	if err := ValidateLock(lock); err != nil {
		t.Fatalf("ValidateLock() error = %v", err)
	}
	if err := ValidateLock([]byte(`{"packages":{"node_modules/image-size":{"version":"2.0.3"}}}`)); err == nil {
		t.Fatal("ValidateLock() accepted an unreviewed image-size version")
	}
}
