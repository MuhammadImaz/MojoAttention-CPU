# Repository Governance Operations

The files in this repository declare governance intent. They do not prove that
GitHub enforces it. Only an authenticated, schema-valid observation evaluated by
`mojoattention governance audit` can report observed activation.

## Trusted CI order

`foundation-quality` resolves immutable event identity, checks out the trusted
base separately, acquires the protected policy and required-check registry,
validates candidate authorization, checks runner capacity, and only then checks
out and executes candidate code. Exact lock synchronization uses the indexes in
the workflow. The job publishes a canonical `.complete` directory only after
schema, identity, validation inventory, Markdown projection, and attachment
closure verification.

The active stable check is `foundation-quality`. `correctness`, `model`,
`training-smoke`, `benchmark-smoke`, `nightly`, `stable-benchmark`, and
`release` are reserved identities, not implemented or passing suites. Runner
capacity or toolchain mismatch is `infrastructure-invalid`; the inventory must
not be reduced to fit a runner.

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
6. Configure the non-secret `GOVERNANCE_OBSERVATION` repository variable from a
   current authenticated export. Configure `PROTECTED_CHANGE_AUTHORIZATION`
   only from a separately reviewed, commit-bound human approval envelope.
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
