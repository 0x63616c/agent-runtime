package docsrefresh_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDocsRefresh(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Documentation Refresh Suite")
}
