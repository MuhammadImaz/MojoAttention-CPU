# Repository Governance Operations

The files in this repository declare governance intent. They do not prove that
GitHub enforces it. Only an authenticated, schema-valid observation evaluated by
`mojoattention governance audit` can report observed activation.

The required `foundation-quality` validation remains fully automatic. A missing
hosted-governance observation does not preempt code, contract, policy, static,
typing, or test validation. When `GOVERNANCE_OBSERVATION` is configured, the
same workflow additionally audits and publishes hosted-governance evidence;
observed drift then fails closed. Protected-change findings remain visible for
review but do not require a separately generated authorization token merely to
run CI.

## Trusted CI order

`foundation-quality` resolves immutable event identity, checks out the trusted
base separately, acquires the protected policy and required-check registry,
validates candidate scope against trusted-base policy, checks runner capacity, and only then checks
out and executes candidate code. Exact lock synchronization uses the indexes in
the workflow. The job publishes a canonical `.complete` directory only after
schema, identity, validation inventory, Markdown projection, and attachment
closure verification.

The active stable check is `foundation-quality`. `correctness`, `model`,
`training-smoke`, `benchmark-smoke`, `nightly`, `stable-benchmark`, and
`release` are reserved identities, not implemented or passing suites. Runner
capacity or toolchain mismatch is `infrastructure-invalid`; the inventory must
not be reduced to fit a runner.

## Product-validation applicability

`contracts/ci-tier-policy.json` is the protected bridge between future product
paths and CI. The planner evaluates the authenticated base/head change set,
including rename/copy source and destination paths, and closes prerequisites:

| Changed area or event | Required product validation |
| --- | --- |
| Kernel contract, domain, backend, conformance, correctness | Correctness |
| Model, generation, model fixtures/tests | Correctness + Model |
| Data or training | Correctness + Model + Training Smoke |
| Benchmark implementation/protocol | Correctness + Benchmark Smoke |
| Schedule/manual nightly | Correctness + Model + Training Smoke + Nightly |
| Release | Correctness + Model + Training Smoke + Benchmark Smoke + Release |

A future story activates its tier in `contracts/required-checks.json` and adds
both the canonical suite manifest and runner in the same change. If governed
production paths appear while that tier remains reserved, has a missing
inventory, or lacks its runner, planning returns `contract-invalid`; CI does not
emit a product pass. After bootstrap, applicability comes from the trusted base,
so candidate code cannot remove its own required tier. Runner capacity is
checked for every execution and returns `infrastructure-invalid` rather than
shrinking work.

```bash
scripts/run.sh mojoattention ci plan \
  --base BASE_SHA --head HEAD_SHA --event pull-request --json -
```

The canonical output lists required and non-applicable tiers, exact argv, and
typed findings. “Not applicable” is not a passing product-validation claim.

## Offline audit

Export an authenticated observation matching
`schemas/governance-observation.schema.json`. Do not include tokens, response
headers, or unrelated API data. The export must identify the repository,
default branch, base/head commits, observation time, source (`github-rest-api`
or `authenticated-export`), and API version `2026-03-10`.

Run:

```bash
scripts/run.sh mojoattention governance audit \
  --intent contracts/repository-governance.json \
  --intent-schema schemas/repository-governance.schema.json \
  --observation /secure/path/governance-observation.json \
  --observation-schema schemas/governance-observation.schema.json \
  --required-checks contracts/required-checks.json \
  --required-checks-schema schemas/required-checks.schema.json \
  --repository MuhammadImaz/MojoAttention-CPU \
  --default-branch main \
  --head-sha HEAD_SHA --base-sha BASE_SHA \
  --evaluation-time 2026-08-05T12:00:00Z \
  --maximum-age-seconds 3600 --api-version 2026-03-10
```

Exit codes are `0` pass, `1` product/configuration failure, `2`
infrastructure-invalid observation, `3` contract-invalid input, and `64` CLI
usage. Re-run after every administrator change and retain the exact authenticated
snapshot with the emitted canonical JSON. Diagnostic logs are not authority.

## Administrator activation checklist

A repository or organization administrator must perform and independently
verify these hosted operations:

1. Apply a ruleset or classic branch protection to `main` with strict
   `foundation-quality` from GitHub Actions.
2. Require at least one human approval, CODEOWNERS review, stale-review
   dismissal, and approval after the last push.
3. Enforce controls for administrators and remove all bypass actors.
4. Require Actions to be pinned to full commit SHAs and retain read-only default
   permissions.
5. Enable Dependabot for `.github/dependabot.yml` and assign immutable Action
   updates to the listed owner.
6. Configure the non-secret `GOVERNANCE_OBSERVATION` and its independently
   recorded `GOVERNANCE_OBSERVATION_SHA256` from a current authenticated export.
   CI validation itself requires no separate authorization envelope; human
   GitHub review and merge remain the promotion boundary.
7. Register any larger/self-hosted runner only after calibration against the
   protected runner prerequisites.

The audit reports committed intent, observed active state, mismatches,
unavailable controls, and human actions separately. AI review is advisory;
human approval and final merge remain external. Hosted performance is
diagnostic until a runner is calibrated. Completion of this governance gate
does not open Milestone 1B: Epic 2 must still prove clean CPU tensor round-trip
and independent routing.

## Artifact retrieval

The workflow artifact name binds GitHub run ID, attempt, and the full source
SHA. Download the single `.complete` directory and verify it with the same
`schemas/validation-evidence.schema.json` and expected CI identity. The
protected registry currently retains Foundation evidence for 14 days. Upload
configuration is transport policy; the evidence digest and transitive hash
closure are the proof.
