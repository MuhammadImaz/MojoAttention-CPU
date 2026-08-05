# Contracts

`acceptance/` contains strict versioned task contracts. Every bound field participates in `contract_digest`, calculated as lowercase SHA-256 over UTF-8 canonical JSON with sorted keys and compact separators after removing only the top-level digest field.

Acceptance Contract v2 adds required `suite_manifest_digest` binding without changing `config_digest` or `protocol_digest` semantics. V1 forbids the new field; evidence dispatch follows the same rule so historical v1 runs remain inspectable while Fast emits v2.

Validation never rewrites a contract. Maintainer tooling may deliberately issue a new digest through `mojoattention.validation.acceptance.issue_contract`; there is intentionally no mutation-capable issuance CLI.

Protected-path approval is a separate envelope. The contract stores only its `authorization_id`; validation requires an externally anchored, human authorization bound to the exact contract digest, source revision, trusted base, and protected paths. Story 1.3 validates those bindings but does not claim that branch-local code proves provenance. Trusted-state acquisition and candidate-diff enforcement belong to Story 1.4.

`protected-assets.json` is the canonical protected inventory. A protected caller supplies policy/schema bytes, the policy's Git blob OID and SHA-256 digest, and the schema's SHA-256 digest; enforcement rejects trust inputs inside the candidate checkout. The evaluator resolves the explicit base and candidate commits, computes a canonical tree-to-tree effect digest, and rejects protected effects without a caller-supplied version 2 human authorization and trusted authorization schema.

`validation-suites/fast.json` is the canonical Fast v1 authority. `config_digest` binds its bounded runner configuration; `manifest_digest` is SHA-256 over canonical compact sorted JSON with only `manifest_digest` omitted. The manifest and schema are protected bootstrap assets: the branch that introduces them cannot treat its own candidate-local bytes as trusted Fast authority. They become a usable trusted base only after external review, exact protected-change authorization, and merge.

The `evidence-producer` role may only generate contracted output indirectly below
`reports/runs`; it has no direct write, approval, rename, copy, or merge authority.
The separate `agent-loop-producer` role has the same deny-by-default shape for
`reports/agent-loops`; the two writer scopes do not overlap.

`FAST-014` is reserved as the required Agent Loop policy canary. Its protected
manifest/schema inventory must be externally authorized and merged before its
production mutation/control evaluator can become trusted authority.

`acceptance/1-7-agent-loop.example.json` is the schema-valid Acceptance
Contract v2 template referenced by `FAST-014`. It binds all 14 ordered checks
and the exact manifest, runner-config, and Fast protocol digests. Its example
source revision is deliberately non-authoritative: a protected caller must
externally issue the contract for the exact candidate commit and separately
supply human authorization. The tracked template cannot authorize itself.

The version 2 envelope binds the exact base/candidate commit and tree IDs, trusted policy blob and digest, complete change-set digest, contract digest, exact protected paths, and independently supplied human approval anchor. Its provenance digest is SHA-256 over canonical compact sorted JSON with only `provenance_digest` omitted.

Bootstrapping the first protected policy and approval store is a one-time human governance action outside this validator. Branch-local execution is deterministic feedback; only protected CI or equivalent administrator-controlled orchestration can establish that the supplied bytes and identities are authoritative.

`required-checks.json` reserves eight stable check identities and activates only
`foundation-quality`; reserved entries are not synthetic jobs. The Foundation
manifest binds canonical JSON, deterministic Markdown, attachment closure,
governance, and GitHub run identity. `repository-governance.json` is configured
intent only. See `docs/governance.md` for authenticated observation and human
activation procedures.
