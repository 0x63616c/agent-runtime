// Package firecrackerbootprobejournal owns the host-instance-exclusive durable
// launch-intent record required before an M4 Jailer may start.
package firecrackerbootprobejournal

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/cockroachdb/errors"
)

var ErrLocked = errors.New("Firecracker boot-probe host-instance journal is already locked")

type document struct {
	Version string                         `json:"version"`
	Session firecrackerbootprobev2.Session `json:"session"`
}

// Journal exclusively owns one absolute host-instance journal path.
type Journal struct {
	path    string
	lock    *os.File
	session *firecrackerbootprobev2.Session
}

// Open recovers the sole canonical journal record and refuses a second host process.
func Open(path string) (*Journal, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("open Firecracker boot-probe journal: absolute path is required")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.Wrap(ErrLocked, "open Firecracker boot-probe journal")
	}
	j := &Journal{path: path, lock: lock}
	wire, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		_ = j.Close()
		return nil, err
	}
	var d document
	dec := json.NewDecoder(bytes.NewReader(wire))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF || d.Version != "firecracker-boot-probe-host-journal/v2" || d.Session.Validate() != nil {
		_ = j.Close()
		return nil, errors.New("open Firecracker boot-probe journal: invalid canonical record")
	}
	canonical, _ := json.Marshal(d)
	if !bytes.Equal(wire, canonical) {
		_ = j.Close()
		return nil, errors.New("open Firecracker boot-probe journal: non-canonical record")
	}
	j.session = &d.Session
	return j, nil
}

// StageLaunchIntent fsyncs exactly the authorized current delivery before launch.
func (j *Journal) StageLaunchIntent(session firecrackerbootprobev2.Session) error {
	if j == nil || j.lock == nil || session.Validate() != nil || session.Lifecycle.Phase != firecrackerbootprobev2.LifecycleLaunchAuthorized {
		return errors.New("stage Firecracker boot-probe launch intent: exact authorized session is required")
	}
	if j.session != nil {
		current, currentErr := firecrackerbootprobev2.EncodeSession(*j.session)
		candidate, candidateErr := firecrackerbootprobev2.EncodeSession(session)
		if currentErr == nil && candidateErr == nil && bytes.Equal(current, candidate) {
			return nil
		}
		return errors.New("stage Firecracker boot-probe launch intent: altered session refused")
	}
	wire, err := json.Marshal(document{Version: "firecracker-boot-probe-host-journal/v2", Session: session})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(j.path+".tmp", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(wire); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(j.path+".tmp", j.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(j.path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	j.session = &session
	return nil
}

// LaunchIntent returns the recovered immutable intent, if one was fsynced.
func (j *Journal) LaunchIntent() (firecrackerbootprobev2.Session, bool) {
	if j == nil || j.session == nil {
		return firecrackerbootprobev2.Session{}, false
	}
	return *j.session, true
}

// Close releases exclusive host-instance ownership.
func (j *Journal) Close() error {
	if j == nil || j.lock == nil {
		return nil
	}
	l := j.lock
	j.lock = nil
	_ = syscall.Flock(int(l.Fd()), syscall.LOCK_UN)
	return l.Close()
}
