# Backend Selection and Fallback Policy

Story 2.5 defines the framework-independent policy boundary for choosing an attention backend. It does not implement causal attention or prove that a native Mojo kernel executed; later stories compose real adapters and independently validate routing through this boundary.

## Configuration surface

Create one immutable `BackendRequest` at the workflow boundary:

- `mode`: `training` or `inference`.
- `backend`: `pytorch`, `mojo`, or omitted only for training.
- `fallback`: `forbid` by default, or the explicit `allow-mojo-to-pytorch` policy.

Training without an override selects PyTorch. Training with Mojo is rejected because Mojo is inference-only in the MVP. Inference always requires an explicit backend; there is no environment-derived or implicit inference default.

## Adapter composition

Workflows construct a `BackendRegistry` from exactly one PyTorch implementation and one Mojo implementation of the framework-independent `AttentionBackend` protocol. Domain code and the selection policy do not import PyTorch, MAX, validation, CLI, or concrete adapter modules.

The registry is a composition seam, not a simulated backend. Story 2.7 supplies the protected PyTorch semantic reference and Story 3.1 supplies scalar Mojo attention. Adapters retain responsibility for tensor validation and execution; the selection layer forwards Q, K, V, and caller-owned output objects unchanged.

## Required Mojo and fallback

The default `forbid` policy makes an explicit Mojo request required. A typed Mojo `unavailable`, `invalid`, or `execution` failure becomes a stable `BACKEND-MOJO-*` error and PyTorch is not called.

Fallback is possible only when all of these are true:

1. mode is inference;
2. the requested backend is Mojo;
3. policy is explicitly `allow-mojo-to-pytorch`; and
4. the Mojo adapter raises a typed `BackendFailure`.

Arbitrary programming exceptions are not converted into fallback permission. A failing PyTorch fallback is reported and is not retried.

## Selection evidence

Every execution attempt receives one non-empty invocation identity. A successful execution returns immutable policy evidence containing:

- `invocation_id`;
- `requested_backend` (or no override for defaulted training);
- `executed_backend`;
- `policy`;
- `fallback_reason`, which is null without fallback and a stable Mojo failure code after permitted fallback.

This record makes policy behavior observable but is not trusted proof of native execution. Story 2.6 owns independent wrapper/native correlation, call-count validation, source revision binding, and Milestone 1B closure.

## Example

```python
from mojoattention.backend_selection import BackendRegistry, execute_attention
from mojoattention.domain.backends import BackendName, BackendRequest, ExecutionMode, FallbackPolicy

registry = BackendRegistry((pytorch_adapter, mojo_adapter))
request = BackendRequest(
    mode=ExecutionMode.INFERENCE,
    backend=BackendName.MOJO,
    fallback=FallbackPolicy.FORBID,
)
result = execute_attention(registry, request, q, k, v, out)
```

Use `FallbackPolicy.ALLOW_MOJO_TO_PYTORCH` only when the caller has explicitly accepted fallback and will retain the resulting evidence.
