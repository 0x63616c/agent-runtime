//go:build !linux

package main

import "fmt"

func newGuestControlListener() (guestControlListener, error) {
	return nil, fmt.Errorf("AF_VSOCK guest control is only available on linux")
}
