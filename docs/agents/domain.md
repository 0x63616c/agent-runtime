# Domain documentation

Agent Runtime uses a single domain-documentation context. Before exploring or
changing a capability, read the relevant current sources in this order:

1. `CONTEXT.md` for the implementation-free ubiquitous language.
2. Relevant accepted numbered records in `docs/adr/` for hard-to-reverse
   decisions and their consequences.
3. `docs/architecture/system.md`, the master requirements, acceptance ledger,
   and seams/invariants for binding architecture, scope and test evidence.
4. Relevant planning design, risk, reuse, environment, or documentation files;
   proposed/external drafts cannot override the binding sources above.

`CONTEXT.md` and `docs/adr/` are established, accepted sources. Update the
glossary only when domain language crystallizes; update an ADR only for a
hard-to-reverse decision. Do not invent a second vocabulary or let a proposed
or copied/external draft silently override an accepted term or decision.

When defined, use the canonical terms exactly in code, issue titles, tests,
documentation, and alerts. The initial required vocabulary includes Agent
specification, Agent revision, Session, Input, Turn, Model invocation, Tool
call, Tool execution, Capability grant, Sandbox, Process, Operation, Approval,
Artifact, Product event, Cursor, Gap, Audit record, Outbox record, Tenant,
Principal, Policy, Capability profile, Effective specification, Host assignment
and Status estimate. Do not substitute a synonym when a canonical term exists.

If a proposed change conflicts with an ADR, call it out explicitly rather than
silently overriding it. A conflict needs a superseding ADR and updates to the
master requirements and acceptance ledger before implementation proceeds.

The intended structure is:

```text
/
├── CONTEXT.md                 # accepted implementation-free language
└── docs/
    └── adr/                   # accepted numbered, hard-to-reverse decisions
```

The repository remains one domain context and one root Go module. A
contributor-only `go.work` is not permission to fork domain terminology or
create another public module boundary.
