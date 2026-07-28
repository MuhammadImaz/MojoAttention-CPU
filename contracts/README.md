# Contracts

`acceptance/` contains strict versioned task contracts. Every bound field participates in `contract_digest`, calculated as lowercase SHA-256 over UTF-8 canonical JSON with sorted keys and compact separators after removing only the top-level digest field.

Validation never rewrites a contract. Maintainer tooling may deliberately issue a new digest through `mojoattention.validation.acceptance.issue_contract`; there is intentionally no mutation-capable issuance CLI.

Protected-path approval is a separate envelope. The contract stores only its `authorization_id`; validation requires an externally anchored, human authorization bound to the exact contract digest, source revision, trusted base, and protected paths. Story 1.3 validates those bindings but does not claim that branch-local code proves provenance. Trusted-state acquisition and candidate-diff enforcement belong to Story 1.4.

`protected-assets.json` is the canonical protected inventory. A protected caller supplies policy/schema bytes, the policy's Git blob OID and SHA-256 digest, and the schema's SHA-256 digest; enforcement rejects trust inputs inside the candidate checkout. The evaluator resolves the explicit base and candidate commits, computes a canonical tree-to-tree effect digest, and rejects protected effects without a caller-supplied version 2 human authorization and trusted authorization schema.

The `evidence-producer` role may only generate contracted output indirectly below
`reports/runs`; it has no direct write, approval, rename, copy, or merge authority.

The version 2 envelope binds the exact base/candidate commit and tree IDs, trusted policy blob and digest, complete change-set digest, contract digest, exact protected paths, and independently supplied human approval anchor. Its provenance digest is SHA-256 over canonical compact sorted JSON with only `provenance_digest` omitted.

Bootstrapping the first protected policy and approval store is a one-time human governance action outside this validator. Branch-local execution is deterministic feedback; only protected CI or equivalent administrator-controlled orchestration can establish that the supplied bytes and identities are authoritative.
