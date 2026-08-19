# Reproducible kernel cases

`contracts/kernel/kernel-case-matrix.json` is the protected, canonical 90-entry inventory: three cases for each of the 30 Kernel Contract shapes. The cases are `fixed-zero`, `boundary-alternating`, and `seeded-interior` in that order.

Generator v1 is repository-owned and network-free. It domain-separates Q, K, and V, emits contiguous BHSD little-endian float32 bytes, and records SHA-256 digests. `seeded-interior` uses SHA-256 counter blocks and exact binary fractions strictly inside `[-20,20]`; it does not depend on ambient Python, NumPy, or PyTorch RNG state.

Validate the protected matrix:

```bash
scripts/run.sh mojoattention kernel-cases validate \
  --matrix contracts/kernel/kernel-case-matrix.json \
  --schema schemas/kernel-case-matrix.schema.json \
  --contract contracts/kernel/kernel-contract.json \
  --json -
```

Reproduce one case from tracked inputs only:

```bash
scripts/run.sh mojoattention kernel-cases generate \
  --contract contracts/kernel/kernel-contract.json \
  --case-id v1-b1-h2-s16-d16-seeded-interior-seed0 \
  --seed 42 \
  --json -
```

The JSON response binds generator version, Kernel Contract digest, shape, bounds, seed, serialization, tensor byte counts/digests, and exact reproduction arguments. Local output is validation feedback, not hosted CI or merge authorization.
