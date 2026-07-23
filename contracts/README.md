# Contracts

`acceptance/` contains strict versioned task contracts. Every bound field participates in `contract_digest`, calculated as lowercase SHA-256 over UTF-8 canonical JSON with sorted keys and compact separators after removing only the top-level digest field.

Validation never rewrites a contract. Maintainer tooling may deliberately issue a new digest through `mojoattention.validation.acceptance.issue_contract`; there is intentionally no mutation-capable issuance CLI.

Protected-path approval is a separate envelope. The contract stores only its `authorization_id`; validation requires an externally anchored, human authorization bound to the exact contract digest, source revision, trusted base, and protected paths. Story 1.3 validates those bindings but does not claim that branch-local code proves provenance. Trusted-state acquisition and candidate-diff enforcement belong to Story 1.4.
