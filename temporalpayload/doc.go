// Package temporalpayload provides the local, size-aware Temporal payload codec chain.
//
// A Codec always starts with Temporal's normal serialization. It retains that
// representation unless a zstd wrapper is strictly smaller, then retains that
// representation unless an immutable content-addressed blob reference is
// strictly smaller. Runtime clients and workers use Codec.DataConverter
// locally. NewUIHandler exposes the identical codec only for an authorized
// Temporal UI inspection endpoint; it is never on a worker's normal path.
//
// The package provides integrity and compatibility, not encryption. Callers
// provide the BlobStore implementation appropriate to their object store and
// must declare its endpoint, credentials, prefix, lifecycle, and retention in
// their deployment configuration.
package temporalpayload
