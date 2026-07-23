# Setup and preflight

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
