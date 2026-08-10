package main

import (
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"
)

const (
	guestControlPollIn      int16  = 0x0001
	guestControlPollError   int16  = 0x0008
	guestControlPollHangup  int16  = 0x0010
	guestControlPollInvalid int16  = 0x0020
	guestControlHostCID     uint32 = 2
)

type guestControlPoll func(fileDescriptor int32, events int16, milliseconds int) (ready int, revents int16, err error)

func waitForGuestControlPoll(poll guestControlPoll, fileDescriptor int32, events int16, deadline time.Time) error {
	if poll == nil {
		return fmt.Errorf("guest control poll is required")
	}
	for {
		milliseconds := -1
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return fmt.Errorf("guest control deadline elapsed")
			}
			milliseconds = int((remaining + time.Millisecond - 1) / time.Millisecond)
		}
		ready, revents, err := poll(fileDescriptor, events, milliseconds)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			return fmt.Errorf("guest control deadline elapsed")
		}
		if revents&(guestControlPollError|guestControlPollHangup|guestControlPollInvalid) != 0 {
			return fmt.Errorf("guest control poll returned a terminal event")
		}
		if revents&events == 0 {
			return fmt.Errorf("guest control poll returned no requested event")
		}
		return nil
	}
}

func acceptGuestControlConnection(wait func() error, accept func() (guestControlConnection, uint32, error)) (guestControlConnection, error) {
	if wait == nil || accept == nil {
		return nil, fmt.Errorf("guest control wait and accept are required")
	}
	for {
		if err := wait(); err != nil {
			return nil, err
		}
		connection, peerCID, err := accept()
		if retryableGuestControlError(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("accept guest control connection: %w", err)
		}
		if connection == nil {
			return nil, fmt.Errorf("accepted guest control connection is required")
		}
		if peerCID != guestControlHostCID {
			if closeErr := connection.Close(); closeErr != nil {
				return nil, fmt.Errorf("refuse non-host guest control peer: %w", closeErr)
			}
			return nil, fmt.Errorf("refuse non-host guest control peer")
		}
		return connection, nil
	}
}

func writeAllGuestControl(buffer []byte, write func([]byte) (int, error)) (int, error) {
	if write == nil {
		return 0, fmt.Errorf("guest control writer is required")
	}
	for written := 0; written < len(buffer); {
		count, err := write(buffer[written:])
		if count < 0 || count > len(buffer)-written {
			return written, fmt.Errorf("guest control writer returned an invalid byte count")
		}
		written += count
		if err != nil {
			return written, err
		}
		if count == 0 {
			return written, io.ErrShortWrite
		}
	}
	return len(buffer), nil
}

func retryableGuestControlError(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR)
}
