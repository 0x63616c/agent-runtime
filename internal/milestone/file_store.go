package milestone

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cockroachdb/errors"
)

// FileStore persists one retained milestone record per opaque milestone identifier.
type FileStore struct {
	directory string
	mu        sync.Mutex
}

// NewFileStore creates a private directory-backed EvidenceStore.
func NewFileStore(directory string) (*FileStore, error) {
	if directory == "" {
		return nil, errors.New("create milestone file store: directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.Wrap(err, "create milestone file store directory")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, errors.Wrap(err, "inspect milestone file store directory")
	}
	if !info.IsDir() {
		return nil, errors.New("create milestone file store: path is not a directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, errors.Wrap(err, "harden milestone file store directory")
	}
	return &FileStore{directory: directory}, nil
}

// Retain stores a pending record before delivery without overwriting prior evidence.
func (store *FileStore) Retain(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "retain file milestone evidence")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, err := os.Stat(store.path(record.Report.Milestone)); err == nil {
		return errors.New("retain file milestone evidence: record already exists")
	} else if !os.IsNotExist(err) {
		return errors.Wrap(err, "inspect retained milestone evidence")
	}
	return store.write(record, false)
}

// Lookup returns a previously retained record.
func (store *FileStore) Lookup(ctx context.Context, milestone MilestoneID) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, errors.Wrap(err, "lookup file milestone evidence")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.read(milestone)
}

// MarkFailed retains the latest classified failed delivery result.
func (store *FileStore) MarkFailed(ctx context.Context, milestone MilestoneID, code FailureCode) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, errors.Wrap(err, "mark file milestone delivery failed")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.read(milestone)
	if err != nil {
		return Record{}, err
	}
	record.Delivery = DeliveryFailed
	record.Failure = code
	record.Attempts++
	if err := store.write(record, true); err != nil {
		return Record{}, err
	}
	return record, nil
}

// MarkSent retains the successful delivery result.
func (store *FileStore) MarkSent(ctx context.Context, milestone MilestoneID) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, errors.Wrap(err, "mark file milestone delivery sent")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.read(milestone)
	if err != nil {
		return Record{}, err
	}
	record.Delivery = DeliverySent
	record.Failure = ""
	record.Attempts++
	if err := store.write(record, true); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (store *FileStore) read(milestone MilestoneID) (Record, error) {
	encoded, err := os.ReadFile(store.path(milestone))
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, errors.New("lookup file milestone evidence: record not found")
		}
		return Record{}, errors.Wrap(err, "read retained milestone evidence")
	}
	var record Record
	if err := decodeOne(bytes.NewReader(encoded), &record); err != nil {
		return Record{}, errors.Wrap(err, "decode retained milestone evidence")
	}
	if record.Report.Milestone != milestone {
		return Record{}, errors.New("decode retained milestone evidence: milestone mismatch")
	}
	return record, nil
}

func (store *FileStore) write(record Record, replace bool) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.Wrap(err, "encode retained milestone evidence")
	}
	temporary, err := os.CreateTemp(store.directory, ".milestone-*.json")
	if err != nil {
		return errors.Wrap(err, "create retained milestone evidence")
	}
	temporaryPath := temporary.Name()
	defer removeTemporary(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		return closeTemporary(temporary, errors.Wrap(err, "harden retained milestone evidence"))
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		return closeTemporary(temporary, errors.Wrap(err, "write retained milestone evidence"))
	}
	if err := temporary.Sync(); err != nil {
		return closeTemporary(temporary, errors.Wrap(err, "sync retained milestone evidence"))
	}
	if err := temporary.Close(); err != nil {
		return errors.Wrap(err, "close retained milestone evidence")
	}
	if replace {
		if err := os.Rename(temporaryPath, store.path(record.Report.Milestone)); err != nil {
			return errors.Wrap(err, "replace retained milestone evidence")
		}
		return store.syncDirectory()
	}
	if err := os.Link(temporaryPath, store.path(record.Report.Milestone)); err != nil {
		if os.IsExist(err) {
			return errors.New("retain file milestone evidence: record already exists")
		}
		return errors.Wrap(err, "retain milestone evidence")
	}
	return store.syncDirectory()
}

func (store *FileStore) syncDirectory() (resultErr error) {
	directory, err := os.Open(store.directory)
	if err != nil {
		return errors.Wrap(err, "open milestone evidence directory for sync")
	}
	defer func() {
		if err := directory.Close(); err != nil {
			resultErr = stderrors.Join(resultErr, errors.Wrap(err, "close milestone evidence directory after sync"))
		}
	}()
	if err := directory.Sync(); err != nil {
		return errors.Wrap(err, "sync milestone evidence directory")
	}
	return nil
}

func closeTemporary(temporary *os.File, failure error) error {
	if err := temporary.Close(); err != nil {
		return stderrors.Join(failure, errors.Wrap(err, "close retained milestone evidence"))
	}
	return failure
}

func removeTemporary(path string) {
	// A leftover temporary file cannot replace retained evidence; removal is hygiene only.
	_ = os.Remove(path)
}

func (store *FileStore) path(milestone MilestoneID) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(milestone))
	return filepath.Join(store.directory, "milestone-"+encoded+".json")
}

func (store *FileStore) claimDelivery(ctx context.Context, milestone MilestoneID) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "claim file milestone delivery")
	}
	claim, err := os.OpenFile(store.path(milestone)+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.Wrap(err, "open file milestone delivery claim")
	}
	if err := claim.Chmod(0o600); err != nil {
		return nil, closeClaim(claim, errors.Wrap(err, "harden file milestone delivery claim"))
	}
	if err := syscall.Flock(int(claim.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return nil, closeClaim(claim, errors.New("file milestone delivery is already claimed"))
		}
		return nil, closeClaim(claim, errors.Wrap(err, "lock file milestone delivery claim"))
	}
	return func() error {
		unlockErr := syscall.Flock(int(claim.Fd()), syscall.LOCK_UN)
		closeErr := claim.Close()
		if unlockErr != nil {
			return errors.Wrap(unlockErr, "unlock file milestone delivery claim")
		}
		if closeErr != nil {
			return errors.Wrap(closeErr, "close file milestone delivery claim")
		}
		return nil
	}, nil
}

func closeClaim(claim *os.File, failure error) error {
	if err := claim.Close(); err != nil {
		return stderrors.Join(failure, errors.Wrap(err, "close file milestone delivery claim"))
	}
	return failure
}
