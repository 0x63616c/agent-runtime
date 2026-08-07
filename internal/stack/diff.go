package stack

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"

	"github.com/cockroachdb/errors"
)

// ChangeKind classifies desired-state catalog drift.
type ChangeKind string

const (
	// ChangeAdded means observed desired state declares a new resource.
	ChangeAdded ChangeKind = "added"
	// ChangeModified means the canonical resource declaration changed.
	ChangeModified ChangeKind = "modified"
	// ChangeRemoved means observed desired state omitted an expected resource.
	ChangeRemoved ChangeKind = "removed"
)

// Change is one bounded resource-level desired-state difference.
type Change struct {
	// Resource is the affected stable resource identity.
	Resource ResourceID `json:"resource"`
	// Kind classifies the difference.
	Kind ChangeKind `json:"kind"`
}

// Difference contains deterministic ResourceID-ordered drift.
type Difference struct {
	// Changes is empty only when desired states match.
	Changes []Change `json:"changes"`
}

// Check verifies candidate provenance and exact desired-state identity.
func Check(expected Rendered, candidate io.Reader) error {
	document, err := parseRendered(candidate)
	if err != nil {
		return err
	}
	if document.Digest != expected.Digest() {
		return errors.Newf("check rendered stack: digest drift: expected %s, got %s", expected.Digest(), document.Digest)
	}
	return nil
}

// Diff verifies candidate provenance and returns resource-level desired-state drift.
func Diff(expected Rendered, candidate io.Reader) (Difference, error) {
	document, err := parseRendered(candidate)
	if err != nil {
		return Difference{}, err
	}
	expectedDocument, err := parseRenderedBytes(expected.JSON())
	if err != nil {
		return Difference{}, errors.Wrap(err, "diff expected rendered stack")
	}
	if document.Stack != expectedDocument.Stack || document.Profile != expectedDocument.Profile || document.Namespace != expectedDocument.Namespace {
		return Difference{}, errors.New("diff rendered stack: stack, profile, and namespace identity must match")
	}
	expectedCatalog := catalogDigests(expectedDocument.Catalog)
	actualCatalog := catalogDigests(document.Catalog)
	changes := make([]Change, 0)
	for id, expectedDigest := range expectedCatalog {
		actualDigest, exists := actualCatalog[id]
		switch {
		case !exists:
			changes = append(changes, Change{Resource: id, Kind: ChangeRemoved})
		case actualDigest != expectedDigest:
			changes = append(changes, Change{Resource: id, Kind: ChangeModified})
		}
	}
	for id := range actualCatalog {
		if _, exists := expectedCatalog[id]; !exists {
			changes = append(changes, Change{Resource: id, Kind: ChangeAdded})
		}
	}
	sort.Slice(changes, func(left, right int) bool { return changes[left].Resource < changes[right].Resource })
	return Difference{Changes: changes}, nil
}

func parseRendered(input io.Reader) (renderedDocument, error) {
	if input == nil {
		return renderedDocument{}, errors.New("parse rendered stack: input is required")
	}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var document renderedDocument
	if err := decoder.Decode(&document); err != nil {
		return renderedDocument{}, errors.Wrap(err, "parse rendered stack")
	}
	if err := requireEnd(decoder); err != nil {
		return renderedDocument{}, err
	}
	claimed := document.Digest
	if !sha256Pattern.MatchString(claimed) {
		return renderedDocument{}, errors.New("parse rendered stack: valid digest is required")
	}
	document.Digest = ""
	unsigned, err := json.Marshal(document)
	if err != nil {
		return renderedDocument{}, errors.Wrap(err, "verify rendered stack digest")
	}
	if digest(unsigned) != claimed {
		return renderedDocument{}, errors.New("parse rendered stack: digest does not match canonical desired state")
	}
	document.Digest = claimed
	return document, nil
}

func parseRenderedBytes(input []byte) (renderedDocument, error) {
	return parseRendered(bytes.NewReader(input))
}

func catalogDigests(catalog []CatalogEntry) map[ResourceID]string {
	digests := make(map[ResourceID]string, len(catalog))
	for _, entry := range catalog {
		digests[entry.ID] = entry.Digest
	}
	return digests
}
