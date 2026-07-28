# Schemas

Trust-boundary schemas use JSON Schema Draft 2020-12, require `schema_version`, and reject unknown fields.

- `agent-authority.schema.json` defines provider-neutral role authority.
- `acceptance-contract.schema.json` defines task identity, scope, evidence cardinality, referenced digests, retry state, and authorization references.
- `protected-change-authorization.schema.json` defines the version 2 independent human-approval envelope, including exact base/candidate commit and tree IDs, trusted policy identity, complete change-set digest, and provenance digest.
- `protected-assets.schema.json` defines the complete trusted category, path-scope, remediation, and trigger-to-generated-output policy.
- `validation-evidence.schema.json` defines the strict canonical run envelope, result, typed-error, metric, attachment-closure, lifecycle, and verdict contract.

Protected authorization bytes are supplied by a protected caller with an independent approval-anchor identity, and the canonical provenance digest is recomputed. A path in the candidate checkout is never an authorization source.
