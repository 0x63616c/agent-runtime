//go:build !linux

package main

import (
	"context"
	"fmt"
)

func systemShutdown(context.Context) error {
	return fmt.Errorf("controlled guest shutdown is only available on linux")
}
