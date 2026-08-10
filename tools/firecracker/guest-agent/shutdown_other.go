//go:build !linux

package main

import (
	"context"
	"fmt"
)

func systemShutdown(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("controlled guest shutdown is only available on linux")
}
