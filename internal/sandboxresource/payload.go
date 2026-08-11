package sandboxresource

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const snapshotEnvelopeVersion byte = 1

func encryptSnapshot(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encrypt snapshot payload: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encrypt snapshot payload: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("encrypt snapshot payload: random nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte{snapshotEnvelopeVersion})
	return append(append([]byte{snapshotEnvelopeVersion}, nonce...), ciphertext...), nil
}

func decryptSnapshot(key, envelope []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt snapshot payload: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("decrypt snapshot payload: %w", err)
	}
	if len(envelope) < 1+gcm.NonceSize()+gcm.Overhead() || envelope[0] != snapshotEnvelopeVersion {
		return nil, ErrIntegrity
	}
	plain, err := gcm.Open(nil, envelope[1:1+gcm.NonceSize()], envelope[1+gcm.NonceSize():], []byte{snapshotEnvelopeVersion})
	if err != nil {
		return nil, ErrIntegrity
	}
	return plain, nil
}
