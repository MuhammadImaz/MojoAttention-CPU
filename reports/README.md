# Reports

Generated runs are ignored. Curated release evidence must be added explicitly.

## Integrity-bound validation runs

A producer exclusively creates `<run-id>.staging`, durably writes `staging.json`,
and owns the run in one process. No run can be resumed or adopted. Only after the
attachment closure and canonical root are flushed and reverified does one atomic
no-replace rename publish `<run-id>.complete`.

Only canonical, schema-valid, hash-closed `.complete` directories are evidence.
JSON is authoritative and `report.md` is its deterministic display projection.
Completed output is append-forbidden by the API but tamper-detectable rather than
filesystem-immutable; SHA-256 proves consistency, not author identity.

An authenticated human may quarantine abandoned staging only after confirming its
producer is gone. Never promote, resume, merge, or silently hide it. Transient
generation cannot overwrite the separately curated, protected `reports/release/`.
