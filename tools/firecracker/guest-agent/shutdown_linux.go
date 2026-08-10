//go:build linux

package main

import (
	"context"
	"syscall"
)

func systemShutdown(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}
