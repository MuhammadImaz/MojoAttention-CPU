# Schemas

Trust-boundary schemas use JSON Schema Draft 2020-12, require `schema_version`, and reject unknown fields.

- `agent-authority.schema.json` defines provider-neutral role authority.
- `acceptance-contract.schema.json` dispatches exact v1/v2 task contracts. V2 requires a distinct `suite_manifest_digest`; v1 forbids it and retains its original meaning.
- `protected-change-authorization.schema.json` defines the version 2 independent human-approval envelope, including exact base/candidate commit and tree IDs, trusted policy identity, complete change-set digest, and provenance digest.
- `protected-assets.schema.json` defines the complete trusted category, path-scope, remediation, and trigger-to-generated-output policy.
- `validation-evidence.schema.json` dispatches strict v1/v2/v3 canonical run envelopes. V2 binds `suite_manifest_digest`; v3 additionally binds governance and immutable CI run identity. Completed older evidence remains valid and inspectable.
- `required-checks.schema.json`, `repository-governance.schema.json`, and `governance-observation.schema.json` separate stable configured intent from authenticated hosted observations.
- `foundation-validation-suite.schema.json` fixes the non-recursive Foundation evidence inventory.
- `ci-tier-policy.schema.json` fixes ordered path/event applicability, prerequisite, artifact, and command declarations for all eight CI tiers.
- `validation-suite.schema.json` defines Fast v1's immutable ordered inventory, single-case/single-shard cardinality, bounded runner configuration, expected verdict classes, and reproduction argv.
- `kernel-contract.schema.json` defines the strict v1 attention semantic,
  supported-domain, memory/ABI, stable-error, and golden-example interface.

The Fast v1 manifest schema fixes 14 ordered `FAST-NNN` checks, one case and `required_count=1` per ID, seed `1601`, and one complete shard. `FAST-014` reserves the externally bootstrapped Agent Loop policy canary. Its three-minute value is a recorded reference-machine target; it never authorizes deselection, skipping, or incomplete execution.

Protected authorization bytes are supplied by a protected caller with an independent approval-anchor identity, and the canonical provenance digest is recomputed. A path in the candidate checkout is never an authorization source.
