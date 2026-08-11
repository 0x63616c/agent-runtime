package sandboxtransfer

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"
)

func TestValidateArchiveAcceptsOnlyBoundedCanonicalRegularWorkspaceEntries(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "results", Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "results/value.txt", Mode: 0o600, Size: 5, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := ValidateArchive(context.Background(), bytes.NewReader(buffer.Bytes()), 16)
	if err != nil || len(entries) != 2 || entries[1].Path != "results/value.txt" {
		t.Fatalf("ValidateArchive()=(%#v,%v)", entries, err)
	}
}
func TestValidateArchiveRefusesPathEscapeAndLinks(t *testing.T) {
	for _, header := range []*tar.Header{{Name: "../escape", Size: 1, Typeflag: tar.TypeReg}, {Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}} {
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			_, _ = writer.Write([]byte("x"))
		}
		_ = writer.Close()
		if _, err := ValidateArchive(context.Background(), bytes.NewReader(buffer.Bytes()), 16); err == nil {
			t.Fatalf("ValidateArchive accepted %#v", header)
		}
	}
}
