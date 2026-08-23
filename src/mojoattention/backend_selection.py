from __future__ import annotations

from collections.abc import Callable, Iterable
from uuid import uuid4

from mojoattention.domain.backends import (
    AttentionBackend,
    BackendExecutionResult,
    BackendFailure,
    BackendName,
    BackendRequest,
    BackendSelectionError,
    BackendSelectionEvidence,
    ExecutionMode,
    FallbackPolicy,
)


class BackendRegistry[TensorT]:
    def __init__(self, backends: Iterable[AttentionBackend[TensorT]]) -> None:
        registered: dict[BackendName, AttentionBackend[TensorT]] = {}
        for backend in backends:
            name = backend.name
            if not isinstance(name, BackendName):
                raise BackendSelectionError(
                    "BACKEND-REGISTRY-NAME",
                    "backend registry contains an invalid adapter name",
                    {"name": str(name)},
                )
            if name in registered:
                raise BackendSelectionError(
                    "BACKEND-REGISTRY-DUPLICATE",
                    "backend registry contains a duplicate",
                    {"backend": name.value},
                )
            registered[name] = backend
        missing = [backend.value for backend in BackendName if backend not in registered]
        if missing:
            raise BackendSelectionError(
                "BACKEND-REGISTRY-MISSING",
                "backend registry is incomplete",
                {"missing": missing},
            )
        self._backends = registered

    def get(self, name: BackendName) -> AttentionBackend[TensorT]:
        return self._backends[name]


def _default_invocation_id() -> str:
    return str(uuid4())


def _selected_backend(request: BackendRequest) -> BackendName:
    if request.mode is ExecutionMode.INFERENCE and request.backend is None:
        raise BackendSelectionError(
            "BACKEND-INFERENCE-REQUIRES-SELECTION",
            "inference requires an explicit backend",
            {"mode": request.mode.value},
        )
    selected = request.backend or BackendName.PYTORCH
    if request.mode is ExecutionMode.TRAINING and selected is BackendName.MOJO:
        raise BackendSelectionError(
            "BACKEND-MOJO-INFERENCE-ONLY",
            "Mojo backend is inference-only",
            {"backend": selected.value, "mode": request.mode.value},
        )
    return selected


def _require_invocation_id(factory: Callable[[], str]) -> str:
    try:
        invocation_id = factory()
    except Exception as error:
        raise BackendSelectionError(
            "BACKEND-INVOCATION-ID",
            "invocation identity could not be created",
            {"error_type": type(error).__name__},
        ) from error
    if not isinstance(invocation_id, str) or not invocation_id.strip():
        raise BackendSelectionError(
            "BACKEND-INVOCATION-ID",
            "invocation identity must be a non-empty string",
            {},
        )
    return invocation_id


def _selection_error(
    failure: BackendFailure,
    backend: BackendName,
    request: BackendRequest,
    invocation_id: str,
) -> BackendSelectionError:
    return BackendSelectionError(
        failure.code(backend),
        failure.message,
        {
            "failure_context": failure.context,
            "invocation_id": invocation_id,
            "policy": request.fallback.value,
            "requested_backend": backend.value,
        },
    )


def _fallback_error(
    mojo_failure: BackendFailure,
    fallback_failure: BackendFailure,
    request: BackendRequest,
    invocation_id: str,
) -> BackendSelectionError:
    return BackendSelectionError(
        fallback_failure.code(BackendName.PYTORCH),
        fallback_failure.message,
        {
            "executed_backend": BackendName.PYTORCH.value,
            "failure_context": fallback_failure.context,
            "fallback_reason": mojo_failure.code(BackendName.MOJO),
            "invocation_id": invocation_id,
            "policy": request.fallback.value,
            "requested_backend": BackendName.MOJO.value,
        },
    )


def execute_attention[TensorT](
    registry: BackendRegistry[TensorT],
    request: BackendRequest,
    q: TensorT,
    k: TensorT,
    v: TensorT,
    out: TensorT,
    *,
    invocation_id_factory: Callable[[], str] = _default_invocation_id,
) -> BackendExecutionResult:
    selected = _selected_backend(request)
    invocation_id = _require_invocation_id(invocation_id_factory)
    try:
        registry.get(selected)(q, k, v, out)
    except BackendFailure as failure:
        may_fallback = (
            selected is BackendName.MOJO
            and request.mode is ExecutionMode.INFERENCE
            and request.fallback is FallbackPolicy.ALLOW_MOJO_TO_PYTORCH
        )
        if not may_fallback:
            raise _selection_error(failure, selected, request, invocation_id) from failure
        try:
            registry.get(BackendName.PYTORCH)(q, k, v, out)
        except BackendFailure as fallback_failure:
            raise _fallback_error(failure, fallback_failure, request, invocation_id) from fallback_failure
        return BackendExecutionResult(
            BackendSelectionEvidence(
                invocation_id=invocation_id,
                requested_backend=selected,
                executed_backend=BackendName.PYTORCH,
                policy=request.fallback,
                fallback_reason=failure.code(selected),
            )
        )
    return BackendExecutionResult(
        BackendSelectionEvidence(
            invocation_id=invocation_id,
            requested_backend=request.backend,
            executed_backend=selected,
            policy=request.fallback,
            fallback_reason=None,
        )
    )
