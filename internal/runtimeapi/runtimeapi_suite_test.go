package runtimeapi_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRuntimeAPI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Runtime API Suite")
}
