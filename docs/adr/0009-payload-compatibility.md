---
status: accepted
---

# Temporal payload compatibility

Every owned Temporal client and worker uses one versioned payload converter
chain. Serialization is followed by compression and then size-aware immutable
blob offload; decoding reverses that order. Metadata is runtime-owned and
versioned. The Temporal UI codec is an inspection adapter using the same chain,
not a runtime dependency.

## Considered options

- Let each worker choose converters independently.
- Reuse Software Factory metadata unchanged or make the UI codec authoritative.

## Consequences

Converter changes require golden legacy-decode, startup round-trip, replay, and
two-consumer compatibility evidence. Missing or corrupt content fails visibly;
no silent default change can reinterpret retained history.
