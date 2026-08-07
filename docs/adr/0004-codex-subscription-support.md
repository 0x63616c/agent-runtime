---
status: accepted
---

# Codex subscription support policy

Codex subscription support is a binding first-release user requirement. Before
the Codex adapter is implemented, the project must retain current official
OpenAI documentation, product-terms, protocol and credential-lifecycle
verification. When supportable, the adapter uses an operator-configured,
redacted credential source with model-role-only access, refresh locking and a
protected live Durable Chat canary. If it is not supportable, the release is
visibly blocked; an API-key adapter is not a substitute.

## Consequences

No credential value appears in the repository, a Kubernetes Secret value,
Temporal payload, sandbox, event, log, artifact or fixture. Credentialed tests
are excluded from untrusted forks and retain only secret-safe evidence.
