//go:build linux

package main

import (
	"context"
	"syscall"
)

func systemShutdown(context.Context) error {
	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}
