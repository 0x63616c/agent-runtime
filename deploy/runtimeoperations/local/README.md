# M5 local operations rehearsal

Run this only against local disposable Docker/OrbStack resources:

```sh
./deploy/runtimeoperations/local/run-rehearsal.sh
```

To retain a redacted, explicitly labeled direct-lab record, choose a new path
outside this checkout and pass both authorizations:

```sh
./deploy/runtimeoperations/local/run-rehearsal.sh \
  --direct-lab-report /absolute/new/direct-lab-evidence.json \
  --execute-authorized-disposable-lab
```

The script starts two ephemeral PostgreSQL instances: a source with WAL
archiving enabled and a separately named restore target. It applies the runtime
migrations, seeds an authorized completed retention record and tenant snapshot,
restores a PostgreSQL custom dump into the isolated target, and starts a local
TLS audit-sink simulator. It then invokes the same `runtimeoperations.Run`
checks used by the protected command.

It always removes containers, credentials, certificate, backup, and logs on
exit. It never invokes GitHub. Direct-lab mode creates only a new
`agent-runtime.direct-lab-evidence/v1` artifact at the explicit path; it has a
different proof level and is rejected by the protected evidence reader.

This is a rehearsal only. It does **not** prove a protected Linux x64 GitHub
Environment run, operator-owned source/restore isolation, real WAL archive
retention or physical point-in-time recovery, deployed audit-sink access
control, or retained protected-run evidence. Those are still required to close
M5 formally.
