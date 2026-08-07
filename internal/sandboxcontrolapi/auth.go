package sandboxcontrolapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/cockroachdb/errors"
)

// StaticAuthenticator binds one already-injected authorization value to one
// explicit identity. It retains only the credential digest and is intended for
// isolated development or a single service identity, not multi-user issuance.
type StaticAuthenticator struct {
	digest   [sha256.Size]byte
	identity Identity
}

// NewStaticAuthenticator constructs a fixed-identity adapter without retaining
// the authorization value.
func NewStaticAuthenticator(authorization string, identity Identity) (*StaticAuthenticator, error) {
	if !bounded(authorization, 4096) || !validIdentity(identity) {
		return nil, errors.New("construct static sandbox authenticator: bounded authorization and identity are required")
	}
	return &StaticAuthenticator{digest: sha256.Sum256([]byte(authorization)), identity: identity}, nil
}

// Authenticate performs a constant-time digest comparison and returns no
// credential material in either success or failure values.
func (authenticator *StaticAuthenticator) Authenticate(ctx context.Context, authorization string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, errors.Wrap(err, "authenticate sandbox control request")
	}
	if authenticator == nil || !bounded(authorization, 4096) {
		return Identity{}, errors.New("authenticate sandbox control request: denied")
	}
	digest := sha256.Sum256([]byte(authorization))
	if subtle.ConstantTimeCompare(digest[:], authenticator.digest[:]) != 1 {
		return Identity{}, errors.New("authenticate sandbox control request: denied")
	}
	return authenticator.identity, nil
}

var _ Authenticator = (*StaticAuthenticator)(nil)
