# MojoAttention Kernel Contract

Contract: `mojoattention-causal-attention` v1
Digest: `sha256:f18088ab796566ff25f1bf140d8080ad58ea16901b47fec7462226048b603fef`

## Semantics

- Score: `score[b,h,i,j]=sum_d(Q[b,h,i,d]*K[b,h,j,d])/sqrt(D)`
- Causal mask rejects `j>i`.
- Softmax axis: `key-j`.
- Output: `O[b,h,i,d]=sum_j<=i(prob[b,h,i,j]*V[b,h,j,d])`.
- Q is unscaled on entry; scaling occurs exactly once; arithmetic and accumulation are float32.

## Supported domain

- Device: CPU
- Dtype: float32
- Layout: contiguous BHSD row-major
- B: 1
- H: 2, 4
- S: 1, 16, 32, 64, 128
- D: 16, 32, 64
- Inputs: finite and `abs(x) <= 20`
- Shape specializations: 30

| B | H | S | D |
|---:|---:|---:|---:|
| 1 | 2 | 1 | 16 |
| 1 | 2 | 1 | 32 |
| 1 | 2 | 1 | 64 |
| 1 | 2 | 16 | 16 |
| 1 | 2 | 16 | 32 |
| 1 | 2 | 16 | 64 |
| 1 | 2 | 32 | 16 |
| 1 | 2 | 32 | 32 |
| 1 | 2 | 32 | 64 |
| 1 | 2 | 64 | 16 |
| 1 | 2 | 64 | 32 |
| 1 | 2 | 64 | 64 |
| 1 | 2 | 128 | 16 |
| 1 | 2 | 128 | 32 |
| 1 | 2 | 128 | 64 |
| 1 | 4 | 1 | 16 |
| 1 | 4 | 1 | 32 |
| 1 | 4 | 1 | 64 |
| 1 | 4 | 16 | 16 |
| 1 | 4 | 16 | 32 |
| 1 | 4 | 16 | 64 |
| 1 | 4 | 32 | 16 |
| 1 | 4 | 32 | 32 |
| 1 | 4 | 32 | 64 |
| 1 | 4 | 64 | 16 |
| 1 | 4 | 64 | 32 |
| 1 | 4 | 64 | 64 |
| 1 | 4 | 128 | 16 |
| 1 | 4 | 128 | 32 |
| 1 | 4 | 128 | 64 |

## Memory and ABI

- Q, K, V, and output are pairwise non-overlapping.
- PyTorch allocates output; native code completely writes it synchronously without hidden copies.
- Argument order: `q, k, v, out, B, H, S, D`; dimensions are signed int64; minimum alignment is 4 bytes.

## Stable errors

| Precedence | Code | Message | Context keys |
|---:|---|---|---|
| 1 | `KERNEL-DEVICE` | tensor device is unsupported | tensor, detected_device, supported_device |
| 2 | `KERNEL-DTYPE` | tensor dtype is unsupported | tensor, detected_dtype, supported_dtype |
| 3 | `KERNEL-RANK` | tensor rank is unsupported | tensor, detected_rank, required_rank |
| 4 | `KERNEL-SHAPE` | Q K and V shapes must match | q_shape, k_shape, v_shape |
| 5 | `KERNEL-BATCH` | batch size is unsupported | detected_batch, supported_batches |
| 6 | `KERNEL-HEADS` | head count is unsupported | detected_heads, supported_heads |
| 7 | `KERNEL-SEQUENCE` | sequence length is unsupported | detected_sequence, supported_sequences |
| 8 | `KERNEL-DIMENSION` | head dimension is unsupported | detected_dimension, supported_dimensions |
| 9 | `KERNEL-LAYOUT` | tensor layout is unsupported | tensor, detected_strides, required_layout |
| 10 | `KERNEL-NONFINITE` | tensor contains a nonfinite element | tensor, index |
| 11 | `KERNEL-MAGNITUDE` | tensor magnitude exceeds the supported bound | tensor, index, maximum_absolute_value |
| 12 | `KERNEL-INPUT-OVERLAP` | input storage ranges overlap | first_tensor, second_tensor |
| 13 | `KERNEL-OUTPUT-SHAPE` | output shape must equal Q shape | detected_shape, required_shape |
| 14 | `KERNEL-OUTPUT-LAYOUT` | output layout must equal Q layout | detected_strides, required_strides |
| 15 | `KERNEL-OUTPUT-OVERLAP` | output storage overlaps an input | input_tensor |
| 16 | `KERNEL-OWNERSHIP` | tensor ownership is unsupported | tensor, required_owner |
| 17 | `KERNEL-LIFETIME` | tensor lifetime is unsupported | tensor, required_lifetime |
| 18 | `KERNEL-INCOMPLETE-WRITE` | native operation did not completely write output | first_unwritten_index |

## Golden examples

### `sequence-one`

S=1 proves output equals V

- Shape: `{"B":1,"D":16,"H":2,"S":1}`
- Q definition: `{"kind":"constant","value":1}`
- K definition: `{"kind":"constant","value":2}`
- V definition: `{"kind":"constant","value":3}`
- Expected output SHA-256 (little-endian float32 BHSD): `sha256:11f2667fd090884e4fccbadb71c96435bfb589537a858b53070f4b8aab365543`
- Output observations: `[{"index":[0,0,0,0],"value":3}]`

### `causal-boundaries`

uniform scores make each query equal the mean of current and prior value positions

- Shape: `{"B":1,"D":16,"H":2,"S":16}`
- Q definition: `{"kind":"constant","value":0}`
- K definition: `{"kind":"constant","value":0}`
- V definition: `{"kind":"sequence-index","offset":0,"scale":1}`
- Expected output SHA-256 (little-endian float32 BHSD): `sha256:03e8c05698c1774fbcd114dbe95496f59985e6e809ce6842384eaae94eaf580c`
- Output observations: `[{"index":[0,0,0,0],"value":0},{"index":[0,0,15,0],"value":7.5}]`

### `scale-sensitive-d16`

D=16 distinguishes exactly-once square-root scaling

- Shape: `{"B":1,"D":16,"H":2,"S":16}`
- Q definition: `{"kind":"constant","value":1}`
- K definition: `{"kind":"sequence-index","offset":0,"scale":1}`
- V definition: `{"kind":"sequence-index","offset":0,"scale":1}`
- Expected output SHA-256 (little-endian float32 BHSD): `sha256:0f18920ee3907b7e0559576f00e012f5844476de9968d114402b61899773f0a2`
- Output observations: `[{"index":[0,0,0,0],"value":0},{"index":[0,0,15,0],"value":14.981342315673828}]`

## Versioning and validation

Any semantic or domain change changes the canonical digest and requires complete downstream regeneration and revalidation.

```bash
scripts/run.sh mojoattention kernel-contract validate --contract contracts/kernel/kernel-contract.json --schema schemas/kernel-contract.schema.json --json -
scripts/run.sh mojoattention kernel-contract show --contract contracts/kernel/kernel-contract.json --schema schemas/kernel-contract.schema.json
```
