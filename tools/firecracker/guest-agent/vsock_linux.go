//go:build linux

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

func newGuestControlListener() (guestControlListener, error) {
	fileDescriptor, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open AF_VSOCK socket: %w", err)
	}
	if err := unix.Bind(fileDescriptor, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: guestControlPort}); err != nil {
		unix.Close(fileDescriptor)
		return nil, fmt.Errorf("bind AF_VSOCK port: %w", err)
	}
	if err := unix.Listen(fileDescriptor, 1); err != nil {
		unix.Close(fileDescriptor)
		return nil, fmt.Errorf("listen on AF_VSOCK port: %w", err)
	}
	return &linuxGuestControlListener{fileDescriptor: fileDescriptor}, nil
}

type linuxGuestControlListener struct {
	fileDescriptor int
	deadline       time.Time
}

func (listener *linuxGuestControlListener) Accept() (guestControlConnection, error) {
	return acceptGuestControlConnection(
		func() error {
			return waitForGuestControlFD(listener.fileDescriptor, guestControlPollIn, listener.deadline)
		},
		func() (guestControlConnection, uint32, error) {
			fileDescriptor, address, err := unix.Accept4(listener.fileDescriptor, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
			if err != nil {
				return nil, 0, err
			}
			peer, ok := address.(*unix.SockaddrVM)
			if !ok {
				return &linuxGuestControlConnection{fileDescriptor: fileDescriptor, deadline: listener.deadline}, 0, nil
			}
			return &linuxGuestControlConnection{fileDescriptor: fileDescriptor, deadline: listener.deadline}, peer.CID, nil
		},
	)
}

func (listener *linuxGuestControlListener) Close() error {
	if err := unix.Close(listener.fileDescriptor); err != nil {
		return fmt.Errorf("close AF_VSOCK listener: %w", err)
	}
	return nil
}

func (listener *linuxGuestControlListener) SetDeadline(deadline time.Time) error {
	listener.deadline = deadline
	return nil
}

type linuxGuestControlConnection struct {
	fileDescriptor int
	deadline       time.Time
}

func (connection *linuxGuestControlConnection) Read(buffer []byte) (int, error) {
	for {
		if err := waitForGuestControlFD(connection.fileDescriptor, guestControlPollIn, connection.deadline); err != nil {
			return 0, err
		}
		count, err := unix.Read(connection.fileDescriptor, buffer)
		if retryableGuestControlError(err) {
			continue
		}
		return count, err
	}
}

func (connection *linuxGuestControlConnection) Write(buffer []byte) (int, error) {
	return writeAllGuestControl(buffer, func(remaining []byte) (int, error) {
		for {
			if err := waitForGuestControlFD(connection.fileDescriptor, unix.POLLOUT, connection.deadline); err != nil {
				return 0, err
			}
			count, err := unix.Write(connection.fileDescriptor, remaining)
			if retryableGuestControlError(err) {
				continue
			}
			return count, err
		}
	})
}

func (connection *linuxGuestControlConnection) Close() error {
	if err := unix.Close(connection.fileDescriptor); err != nil {
		return fmt.Errorf("close AF_VSOCK connection: %w", err)
	}
	return nil
}

func (connection *linuxGuestControlConnection) SetDeadline(deadline time.Time) error {
	connection.deadline = deadline
	return nil
}

func waitForGuestControlFD(fileDescriptor int, events int16, deadline time.Time) error {
	return waitForGuestControlPoll(func(descriptor int32, requestedEvents int16, milliseconds int) (int, int16, error) {
		pollFDs := []unix.PollFd{{Fd: descriptor, Events: requestedEvents}}
		ready, err := unix.Poll(pollFDs, milliseconds)
		return ready, pollFDs[0].Revents, err
	}, int32(fileDescriptor), events, deadline)
}
