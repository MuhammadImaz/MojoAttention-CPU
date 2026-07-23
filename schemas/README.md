# Schemas

Trust-boundary schemas use JSON Schema Draft 2020-12, require `schema_version`, and reject unknown fields.

- `agent-authority.schema.json` defines provider-neutral role authority.
- `acceptance-contract.schema.json` defines task identity, scope, evidence cardinality, referenced digests, retry state, and authorization references.
- `protected-change-authorization.schema.json` defines the independent human-approval envelope. Its structure and exact bindings are validated here; trusted provenance is enforced in Story 1.4.
