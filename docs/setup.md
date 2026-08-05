# Setup and preflight

## Foundation Quality

After exact local bootstrap, run `scripts/quality.sh --local`. GitHub Actions runs the same policy, lock, deterministic tests, lint, formatting, typing, and shell checks through `scripts/quality.sh --ci` from a clean checkout.

The public `contracts/agent-authority.json` is provider-neutral enforcement data. Personal BMAD, Codex, agent prompts, and orchestration state stay ignored and are not required by validation. The privacy check inspects tracked path names only; it does not read ignored files or claim to detect arbitrary secrets stored under an otherwise allowed name.

The standard Ubuntu 24.04 runner is valid only when it satisfies the protected
capacity and toolchain prerequisites. The workflow now evaluates trusted policy
before candidate execution and audits an authenticated hosted observation, but
it does not activate branch protection, CODEOWNERS review, bypass restrictions,
rulesets, or dependency automation. Those remain explicit GitHub-administrator
actions documented in `docs/governance.md`.

The proven host is Ubuntu 26.04 LTS on x86-64. Verify that `python3 --version` is exactly `3.14.4` before bootstrap. Other compatible Linux distributions can pass with an `unproven-distribution` warning; Ubuntu 24.04 CI remains provisional until clean conformance.

## Clean setup

Install the project-owned uv executable, synchronize the exact lock, and then verify the completed environment:

```bash
scripts/install-uv.sh
scripts/bootstrap.sh --sync
scripts/bootstrap.sh --check
```

`install-uv.sh` downloads the official PyPI Linux x86-64 wheel for uv 0.11.29 over TLS and verifies SHA-256 `eec03a8b63d55915694db3af4e91324b39ced49e2aeac7af37851c7eb3f470ea` before installing it under ignored `.tools/uv/`. Bootstrap clears ambient uv project/index overrides, uses `--no-config`, checks the committed lock, and installs only into `.venv`. It runs broad resource preflight before synchronization and exact environment identity afterward.

## Verification

Use the project runner so MAX, Mojo, XDG, Python, and compiler caches remain inside the checkout:

```bash
scripts/run.sh mojoattention environment --json -
scripts/run.sh mojoattention preflight --mode baseline --json -
scripts/run.sh mojoattention preflight --mode broad --json reports/preflight.json
scripts/run.sh max --version
scripts/run.sh mojo --version
```

Validate the canonical Acceptance Contract with explicit trusted context:

```bash
scripts/run.sh mojoattention contract validate \
  --contract contracts/acceptance/1-3.example.json \
  --source-revision 1111111111111111111111111111111111111111 \
  --trusted-base-revision 2222222222222222222222222222222222222222 \
  --json -
```

The example returns `pass`. A deterministic digest failure can be demonstrated safely by copying the example outside the repository, changing any bound field without reissuing its digest, and validating the copy with the same command. It returns exit 3 with `ACPT-003`. Missing, unreadable, or malformed input returns `ACPT-009`; invalid contract shape returns `ACPT-001`.

Contracts that name protected paths additionally require both `--authorization <file>` and an independently obtained `--approval-anchor-revision <sha>`. The authorization file must be outside the proposed repository and bind that human approval anchor, the exact contract digest, source/trusted-base revisions, and exact protected paths. This is contract feedback, not proof that the supplied approval came from trusted state; Story 1.4 owns that enforcement.

Evaluate committed candidate changes using policy/schema bytes acquired by a protected caller:

```bash
scripts/run.sh mojoattention protected validate \
  --trusted-base-revision <40-hex-base-commit> \
  --candidate-revision <40-hex-candidate-commit> \
  --contract-digest <sha256:...> \
  --trusted-policy <protected-policy-file> \
  --trusted-policy-schema <protected-schema-file> \
  --trusted-policy-identity <40-hex-recorded-policy-oid> \
  --trusted-policy-digest <sha256:policy-bytes> \
  --trusted-policy-schema-digest <sha256:schema-bytes> \
  --json -
```

The command compares the exact trees using config-isolated, NUL-delimited Git plumbing. An unauthorized protected effect returns `PROT-003` and exit `3`. For authorized work, add `--authorization <protected-caller-file>`, `--trusted-authorization-schema <protected-schema-file>`, and `--approval-anchor-revision <40-hex-independent-anchor>`. The version 2 envelope binds the exact identities, policy bytes, effect digest, contract, protected paths, and anchor; its provenance digest and strict schema are checked before use.

Candidate-checkout policy or authorization paths are never trust sources. A human must bootstrap the first policy and protected approval channel outside the proposal. This deterministic local command is feedback, not proof that hosted branch rules, caller inputs, or approval provenance are authoritative. Complete trusted-policy-first CI ordering and administrator governance auditing remain Story 1.8 work.

Baseline requires Linux x86-64, glibc 2.34+, effective x86-64-v3, 8 GiB total RAM, and four logical CPUs. Broad mode additionally requires 4 GiB available RAM, 15 GiB free disk, no active/unsealed run, and project Modular cache below 80% of its 5,000,000,000-byte budget. It warns at 70%. Filesystem capacity and project-cache budget are independent gates.

Exit 0 is pass (warnings included), 2 is `infrastructure-invalid`, 3 is `contract-invalid`, and 64 is invalid CLI usage. JSON goes only to `--json`; diagnostics go to stderr. A successful live broad check reports `pass`. Deterministic warning/failure examples can be exercised safely without filling the disk:

```bash
scripts/run.sh pytest -q tests/foundation/test_preflight.py -k 'cache_budget or broad_resource'
```

The tests prove the 70% warning exits successfully and the 80% stop, low-RAM, and low-disk cases exit as `infrastructure-invalid`.

## Safe cache cleanup

Preflight never deletes data. When PF-302 warns or stops:

1. Confirm no active, staging, or unsealed run exists under `reports/runs/`.
2. Close every MAX/Mojo process using this checkout.
3. Move `.cache/modular` to a timestamped quarantine directory under `.cache/quarantine/`; do not delete it in place.
4. Recreate empty `.cache/modular`, run broad preflight, and only remove quarantined data later after confirming no required evidence or active specialization depends on it.

The real PyTorch-to-Mojo custom-operation round trip and routing proof belong to Milestone 1B (Stories 2.4 and 2.6). GitHub repository rules and administrator controls remain external human actions.

## Validation evidence

Evidence is staged below `reports/runs/` and published only after durable closure
verification. Use `scripts/run.sh mojoattention evidence verify --run PATH` for
read-only inspection. Its stable exits are pass `0`, product failure `1`,
infrastructure-invalid `2`, contract-invalid `3`, and invalid usage `64`.
Branch-local generation is feedback; later CI and Agent Loop stories own trusted
retention and governance.

## Fast foundation validation

Fast has one public execution surface:

```bash
scripts/run.sh mojoattention validate \
  --suite fast \
  --contract /path/outside/checkout/issued-fast-contract.json \
  --trusted-base /path/outside/checkout/trusted-base-anchor.json \
  --trusted-policy /path/outside/checkout/protected-assets.json \
  --trusted-policy-schema /path/outside/checkout/protected-assets.schema.json \
  --authorization /path/outside/checkout/authorization.json \
  --trusted-authorization-schema /path/outside/checkout/protected-change-authorization.schema.json \
  --approval-anchor-revision <40-hex-independent-anchor> \
  --output reports/runs
```

All six trust inputs and the contract must be acquired outside the candidate
checkout. The trusted-base anchor binds the exact base revision/tree and
trusted-policy Git identity/digests; the human authorization binds that base,
the candidate revision/tree, contract digest, change-set digest, protected
paths, and independent approval anchor. The contract must be an externally issued Acceptance Contract v2 bound to the
current candidate commit, its trusted base, and the exact
`suite_manifest_digest`, `config_digest`, `protocol_digest`, ordered
`FAST-001`–`FAST-014` inventory, counts, cases, seed, and complete shard in the
trusted `contracts/validation-suites/fast.json`. The contract path must be
outside the candidate checkout. `reports/runs` is the only accepted output
argument. The producer chooses a unique child identity; callers cannot select,
resume, or name a run.

The tracked `contracts/acceptance/1-7-agent-loop.example.json` demonstrates the
exact v2 inventory/digest shape used by `FAST-014`; copy and externally issue it
for the real candidate identity. It is not an approval envelope or a valid
substitute for the outside-checkout contract and human authorization inputs.

Canonical JSON is written to stdout and diagnostics to stderr. Exits are `0`
pass, `1` product failure, `2` infrastructure invalid, `3` contract invalid,
and `64` invalid CLI usage. A completed JSON response names a relative
`reports/runs/<generated-id>.complete` directory containing authoritative
`manifest.json`, deterministic `report.md`, and the hash-closure files. Inspect
it independently:

```bash
scripts/run.sh mojoattention evidence inspect \
  --run reports/runs/<generated-id>.complete \
  --json -
```

Every record includes its stable validation ID, typed error when failed, exact
reproduction argv, structural collection counts, seed/shard identity, and
integer `run-elapsed` in nanoseconds. `reference-target` is the three-minute
reference-machine target, not a portable deadline and never permission to
remove checks.

To demonstrate false-green rejection without changing the checkout, run one
isolated mutation/control test, then Fast and independent inspection:

```bash
scripts/run.sh pytest -q \
  tests/foundation/test_fast_canaries.py \
  -k workflow_omission_tricks
scripts/run.sh mojoattention validate \
  --suite fast \
  --contract /path/outside/checkout/issued-fast-contract.json \
  --trusted-base /path/outside/checkout/trusted-base-anchor.json \
  --trusted-policy /path/outside/checkout/protected-assets.json \
  --trusted-policy-schema /path/outside/checkout/protected-assets.schema.json \
  --authorization /path/outside/checkout/authorization.json \
  --trusted-authorization-schema /path/outside/checkout/protected-change-authorization.schema.json \
  --approval-anchor-revision <40-hex-independent-anchor> \
  --output reports/runs
scripts/run.sh mojoattention evidence inspect \
  --run reports/runs/<generated-id>.complete \
  --json -
```

The first command proves disabled/conditional checks, swallowed exits, empty
selection, deselection, skips, xfails, and placeholders are rejected for
`FAST-009`, followed by an unchanged passing control. The valid Fast run then
publishes one independently inspectable closure. Incomplete staging, raw
successful commands, partial shards, or unverified/tampered output are not
evidence.

Fast is foundation feedback only: contracts, schemas, static analysis, imports,
provider-neutral authority discovery, path policy, report rendering, and
false-green canaries. It is not kernel correctness, backend routing, model,
training, benchmark, hosted-governance, or release evidence. Later stories add
those tiers through protected versioned changes; they do not silently change
Fast's public identity. Candidate-local edits cannot self-approve the manifest,
schemas, policy, runner, tests, or workflow because trust-bearing controls are
read from authenticated Git state and protected-change authorization is
evaluated separately.

## Bounded Agent Loop

The Agent Loop consumes an externally issued Acceptance Contract and completed,
independently verified evidence. It never executes a shell command, infers a
decision from prose, approves a protected change, or authorizes a merge. All
trust-bearing inputs shown below must be supplied by a protected caller from
outside the candidate checkout:

```bash
LOOP_TRUST_ARGS=(
  --contract /outside/issued-contract.json
  --trusted-base /outside/trusted-base-anchor.json
  --trusted-policy /outside/protected-assets.json
  --trusted-policy-schema /outside/protected-assets.schema.json
  --authorization /outside/protected-change-authorization.json
  --trusted-authorization-schema /outside/protected-change-authorization.schema.json
  --approval-anchor-revision <40-hex-independent-human-approval>
  --trusted-loop-schema /outside/agent-loop-state.schema.json
  --role implementation-agent
)
```

Start a loop with an explicit RFC 3339 UTC timestamp:

```bash
scripts/run.sh mojoattention agent-loop start \
  "${LOOP_TRUST_ARGS[@]}" \
  --timestamp 2026-07-30T12:00:00Z
```

The canonical JSON response contains the internally generated `loop_id`,
`attempt: 1`, `retries_consumed: 0`, status `awaiting-validation`, and next
action `record-validation`. The caller cannot choose the loop ID or journal
path. The immutable layout is:

```text
reports/agent-loops/<generated-loop-id>/
├── header.json
└── events/
    ├── 00000001.json
    ├── 00000002.json
    └── ...
```

Each sealed event commits its exact sequence, attempt, transition, prior-event
digest, immutable control binding, evidence bindings, typed diagnosis and
improvement proof where applicable, stop reason, actor kind, and timestamp.
The initial attempt is `1`. A retry authorization increments the attempt and
consumes exactly one retry; a budget of five therefore permits attempts 1–5,
never attempt 6.

Record a completed validation result by passing a structured event file and
one independently verified `.complete` evidence directory:

```bash
scripts/run.sh mojoattention agent-loop evaluate \
  "${LOOP_TRUST_ARGS[@]}" \
  --loop-id <generated-loop-id> \
  --event /outside/validation-event.json \
  --evidence reports/runs/<generated-run-id>.complete
```

A valid pass moves to terminal `awaiting-human-review`; it does not mean
approved or mergeable. A product failure moves to `validation-failed`.
Infrastructure-invalid or contract-invalid evidence stops for human escalation.
Exits remain `0` pass, `1` product failure, `2` infrastructure-invalid, `3`
contract-invalid, and `64` invalid usage.

After a product failure, a retry event must include `repair_request` with:

- a diagnosis bound to the failed validation, stable error/failure signature,
  evidence digest, affected canonical paths, and exact reproduction argv;
- comparable previous/current observations and a strict metric improvement or
  a required failure-to-pass change with no new regression;
- repair paths inside both the contract and effective role authority; and
- `requests_approval: false`, with no protected, generated-output, gate,
  tolerance, baseline, schema, workflow, lock, reference, or self-approval
  conflict.

For example, reducing the same validation/case/config failure-count metric from
`2` to `1` can authorize one bounded repair. Causality, nonfinite,
unsupported-input, unexpected-fallback, missing-routing, nondeterminism,
scope-expansion, protected-conflict, and validation-weakening failures stop
without retry. An equal or worse metric, incomparable identity, repeated
failure signature, new required failure, absent diagnosis, or exhausted budget
is rejected as non-improving or budget-exhausted before a retry event can be
appended.

Inspect and verify the complete chain without modifying it:

```bash
scripts/run.sh mojoattention agent-loop inspect \
  --loop-id <generated-loop-id> \
  --trusted-loop-schema /outside/agent-loop-state.schema.json
```

Inspection rejects a changed header/event digest, broken genesis or prior-event
binding, missing/duplicate/reordered/truncated event, unknown schema version,
mixed evidence identity, or any event after a terminal state. It never repairs,
normalizes, truncates, or completes history. After interruption, rerun
`inspect`; only fully sealed records are replayed. An unsealed or orphan
temporary tail is not evidence and cannot be inferred as progress.

Append-only hash chaining detects and rejects corruption; it does not make the
local filesystem, ignored journal, logs, or agent prose a security boundary.
Trusted controls, external commit-bound human authorization, protected CI, and
human review remain required. A terminal loop is never reopened: human repair
or a newly approved contract starts a new loop. Story 1.8 owns hosted
governance auditing, required-check ordering, retention policy, and complete CI
enforcement.
