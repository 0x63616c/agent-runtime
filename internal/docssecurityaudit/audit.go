// Package docssecurityaudit validates the narrowly accepted documentation audit exception.
package docssecurityaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	exceptionIssue      = 36
	acceptedImageSize   = "2.0.2"
	exceptionExpiryText = "2026-11-08T00:00:00Z"
)

var acceptedAdvisories = map[string]struct{}{
	"https://github.com/advisories/GHSA-w3rx-r6r6-pgpr": {},
	"https://github.com/advisories/GHSA-5p2g-fcmc-qvqq": {},
}

// Result identifies the sole accepted dependency-audit exception.
type Result struct {
	Issue   int
	Expires time.Time
}

type auditDocument struct {
	Metadata struct {
		Vulnerabilities struct {
			High     int `json:"high"`
			Critical int `json:"critical"`
		} `json:"vulnerabilities"`
	} `json:"metadata"`
	Vulnerabilities map[string]auditVulnerability `json:"vulnerabilities"`
}

type auditVulnerability struct {
	Severity string            `json:"severity"`
	Via      []json.RawMessage `json:"via"`
}

type packageLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

// Validate accepts only the documented production audit exception before its expiry.
func Validate(auditJSON []byte, now time.Time) (Result, error) {
	expires, err := time.Parse(time.RFC3339, exceptionExpiryText)
	if err != nil {
		return Result{}, fmt.Errorf("parse documentation audit exception expiry: %w", err)
	}
	if !now.UTC().Before(expires) {
		return Result{}, fmt.Errorf("documentation audit exception expired at %s; renew or remove it", expires.Format(time.RFC3339))
	}

	var audit auditDocument
	if err := json.Unmarshal(auditJSON, &audit); err != nil {
		return Result{}, fmt.Errorf("parse npm audit JSON: %w", err)
	}
	if audit.Metadata.Vulnerabilities.Critical != 0 {
		return Result{}, fmt.Errorf("documentation audit has %d critical production finding(s), none approved", audit.Metadata.Vulnerabilities.Critical)
	}
	if audit.Metadata.Vulnerabilities.High == 0 {
		return Result{}, fmt.Errorf("documentation audit no longer has high production findings; remove the resolved exception")
	}

	found := make(map[string]struct{})
	for name, vulnerability := range audit.Vulnerabilities {
		if vulnerability.Severity != "high" {
			continue
		}
		urls, err := highAdvisoryURLs(name, audit.Vulnerabilities, map[string]bool{})
		if err != nil {
			return Result{}, err
		}
		if len(urls) == 0 {
			return Result{}, fmt.Errorf("high production finding %q has no approved advisory path", name)
		}
		for url := range urls {
			if _, ok := acceptedAdvisories[url]; !ok {
				return Result{}, fmt.Errorf("high production advisory %q is not approved by documentation exception #%d", url, exceptionIssue)
			}
			found[url] = struct{}{}
		}
	}
	if !sameAdvisories(found, acceptedAdvisories) {
		return Result{}, fmt.Errorf("documentation audit advisories do not exactly match exception #%d: got %s", exceptionIssue, advisoryList(found))
	}
	return Result{Issue: exceptionIssue, Expires: expires}, nil
}

// ValidateLock refuses dependency drift while the documentation audit exception exists.
func ValidateLock(lockJSON []byte) error {
	var lock packageLock
	if err := json.Unmarshal(lockJSON, &lock); err != nil {
		return fmt.Errorf("parse documentation package lock: %w", err)
	}
	installed, ok := lock.Packages["node_modules/image-size"]
	if !ok {
		return fmt.Errorf("documentation package lock has no image-size package; remove or re-evaluate exception #%d", exceptionIssue)
	}
	if installed.Version != acceptedImageSize {
		return fmt.Errorf("documentation package lock resolves image-size %q, not accepted exception version %q", installed.Version, acceptedImageSize)
	}
	return nil
}

func highAdvisoryURLs(name string, vulnerabilities map[string]auditVulnerability, visiting map[string]bool) (map[string]struct{}, error) {
	if visiting[name] {
		return nil, fmt.Errorf("documentation audit has a high-severity dependency cycle at %q", name)
	}
	vulnerability, ok := vulnerabilities[name]
	if !ok {
		return nil, fmt.Errorf("documentation audit high dependency %q is missing from the report", name)
	}
	if vulnerability.Severity != "high" {
		return nil, nil
	}
	visiting[name] = true
	defer delete(visiting, name)

	urls := make(map[string]struct{})
	for _, raw := range vulnerability.Via {
		var dependency string
		if err := json.Unmarshal(raw, &dependency); err == nil {
			child, ok := vulnerabilities[dependency]
			if !ok || child.Severity != "high" {
				continue
			}
			childURLs, err := highAdvisoryURLs(dependency, vulnerabilities, visiting)
			if err != nil {
				return nil, err
			}
			for url := range childURLs {
				urls[url] = struct{}{}
			}
			continue
		}
		var advisory struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(raw, &advisory); err != nil || advisory.URL == "" {
			return nil, fmt.Errorf("documentation audit has an unparseable high advisory for %q", name)
		}
		urls[advisory.URL] = struct{}{}
	}
	return urls, nil
}

func sameAdvisories(got, want map[string]struct{}) bool {
	if len(got) != len(want) {
		return false
	}
	for url := range want {
		if _, ok := got[url]; !ok {
			return false
		}
	}
	return true
}

func advisoryList(advisories map[string]struct{}) string {
	urls := make([]string, 0, len(advisories))
	for url := range advisories {
		urls = append(urls, url)
	}
	sort.Strings(urls)
	return strings.Join(urls, ", ")
}
