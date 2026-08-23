from __future__ import annotations

import ast
from dataclasses import asdict
from pathlib import Path

import pytest

from mojoattention.backend_selection import BackendRegistry, execute_attention
from mojoattention.domain.backends import (
    BackendFailure,
    BackendFailureKind,
    BackendName,
    BackendRequest,
    BackendSelectionError,
    ExecutionMode,
    FallbackPolicy,
)


class FakeBackend:
    def __init__(self, name: BackendName, failure: BackendFailure | None = None) -> None:
        self.name = name
        self.failure = failure
        self.calls: list[tuple[object, object, object, object]] = []

    def __call__(self, q: object, k: object, v: object, out: object) -> None:
        self.calls.append((q, k, v, out))
        if self.failure is not None:
            raise self.failure


def request(
    mode: ExecutionMode,
    backend: BackendName | None,
    fallback: FallbackPolicy = FallbackPolicy.FORBID,
) -> BackendRequest:
    return BackendRequest(mode=mode, backend=backend, fallback=fallback)


def registry(*, mojo_failure: BackendFailure | None = None) -> tuple[BackendRegistry[object], FakeBackend, FakeBackend]:
    pytorch = FakeBackend(BackendName.PYTORCH)
    mojo = FakeBackend(BackendName.MOJO, mojo_failure)
    return BackendRegistry((pytorch, mojo)), pytorch, mojo


@pytest.mark.parametrize(
    ("backend_request", "executed"),
    [
        (request(ExecutionMode.TRAINING, None), BackendName.PYTORCH),
        (request(ExecutionMode.TRAINING, BackendName.PYTORCH), BackendName.PYTORCH),
        (request(ExecutionMode.INFERENCE, BackendName.PYTORCH), BackendName.PYTORCH),
        (request(ExecutionMode.INFERENCE, BackendName.MOJO), BackendName.MOJO),
    ],
)
def test_selection_success_is_explicit_and_preserves_arguments(
    backend_request: BackendRequest, executed: BackendName
) -> None:
    backends, pytorch, mojo = registry()
    values = (object(), object(), object(), object())

    result = execute_attention(backends, backend_request, *values, invocation_id_factory=lambda: "invocation-7")

    assert asdict(result.evidence) == {
        "invocation_id": "invocation-7",
        "requested_backend": backend_request.backend,
        "executed_backend": executed,
        "policy": backend_request.fallback,
        "fallback_reason": None,
    }
    assert pytorch.calls == ([values] if executed is BackendName.PYTORCH else [])
    assert mojo.calls == ([values] if executed is BackendName.MOJO else [])


def test_inference_requires_explicit_backend_before_any_call() -> None:
    backends, pytorch, mojo = registry()

    with pytest.raises(BackendSelectionError) as raised:
        execute_attention(
            backends,
            request(ExecutionMode.INFERENCE, None),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=lambda: "unused",
        )

    assert raised.value.as_dict() == {
        "code": "BACKEND-INFERENCE-REQUIRES-SELECTION",
        "message": "inference requires an explicit backend",
        "context": {"mode": "inference"},
    }
    assert pytorch.calls == mojo.calls == []


def test_mojo_is_inference_only() -> None:
    backends, pytorch, mojo = registry()

    with pytest.raises(BackendSelectionError) as raised:
        execute_attention(
            backends,
            request(ExecutionMode.TRAINING, BackendName.MOJO),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=lambda: "unused",
        )

    assert raised.value.code == "BACKEND-MOJO-INFERENCE-ONLY"
    assert raised.value.context == {"backend": "mojo", "mode": "training"}
    assert pytorch.calls == mojo.calls == []


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        (BackendFailureKind.UNAVAILABLE, "BACKEND-MOJO-UNAVAILABLE"),
        (BackendFailureKind.INVALID, "BACKEND-MOJO-INVALID"),
        (BackendFailureKind.EXECUTION, "BACKEND-MOJO-EXECUTION"),
    ],
)
def test_required_mojo_failure_is_stable_and_never_falls_back(kind: BackendFailureKind, code: str) -> None:
    failure = BackendFailure(kind, {"detail": "bounded"})
    backends, pytorch, mojo = registry(mojo_failure=failure)

    with pytest.raises(BackendSelectionError) as raised:
        execute_attention(
            backends,
            request(ExecutionMode.INFERENCE, BackendName.MOJO),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=lambda: "invocation-required",
        )

    assert raised.value.as_dict() == {
        "code": code,
        "message": failure.message,
        "context": {
            "failure_context": {"detail": "bounded"},
            "invocation_id": "invocation-required",
            "policy": "forbid",
            "requested_backend": "mojo",
        },
    }
    assert len(mojo.calls) == 1
    assert pytorch.calls == []


@pytest.mark.parametrize("kind", list(BackendFailureKind))
def test_explicit_fallback_records_complete_evidence(kind: BackendFailureKind) -> None:
    failure = BackendFailure(kind, {"detail": "bounded"})
    backends, pytorch, mojo = registry(mojo_failure=failure)
    values = (object(), object(), object(), object())

    result = execute_attention(
        backends,
        request(ExecutionMode.INFERENCE, BackendName.MOJO, FallbackPolicy.ALLOW_MOJO_TO_PYTORCH),
        *values,
        invocation_id_factory=lambda: "invocation-fallback",
    )

    assert asdict(result.evidence) == {
        "invocation_id": "invocation-fallback",
        "requested_backend": BackendName.MOJO,
        "executed_backend": BackendName.PYTORCH,
        "policy": FallbackPolicy.ALLOW_MOJO_TO_PYTORCH,
        "fallback_reason": failure.code(BackendName.MOJO),
    }
    assert mojo.calls == [values]
    assert pytorch.calls == [values]


def test_untyped_adapter_exception_is_not_reinterpreted_as_fallback() -> None:
    class BrokenBackend(FakeBackend):
        def __call__(self, q: object, k: object, v: object, out: object) -> None:
            super().__call__(q, k, v, out)
            raise ValueError("programming error")

    pytorch = FakeBackend(BackendName.PYTORCH)
    mojo = BrokenBackend(BackendName.MOJO)
    backends = BackendRegistry((pytorch, mojo))

    with pytest.raises(ValueError, match="programming error"):
        execute_attention(
            backends,
            request(ExecutionMode.INFERENCE, BackendName.MOJO, FallbackPolicy.ALLOW_MOJO_TO_PYTORCH),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=lambda: "invocation-error",
        )

    assert len(mojo.calls) == 1
    assert pytorch.calls == []


def test_registry_rejects_missing_and_duplicate_adapters() -> None:
    pytorch = FakeBackend(BackendName.PYTORCH)
    mojo = FakeBackend(BackendName.MOJO)

    with pytest.raises(BackendSelectionError) as missing:
        BackendRegistry((pytorch,))
    assert missing.value.as_dict() == {
        "code": "BACKEND-REGISTRY-MISSING",
        "message": "backend registry is incomplete",
        "context": {"missing": ["mojo"]},
    }

    with pytest.raises(BackendSelectionError) as duplicate:
        BackendRegistry((pytorch, mojo, FakeBackend(BackendName.MOJO)))
    assert duplicate.value.as_dict() == {
        "code": "BACKEND-REGISTRY-DUPLICATE",
        "message": "backend registry contains a duplicate",
        "context": {"backend": "mojo"},
    }


def test_registry_rejects_unknown_and_unstable_adapter_names() -> None:
    class UnknownBackend:
        name = "other"

        def __call__(self, q: object, k: object, v: object, out: object) -> None:
            del q, k, v, out

    class UnstableBackend(FakeBackend):
        reads = 0

        @property
        def name(self) -> BackendName:  # type: ignore[override]
            self.reads += 1
            return BackendName.PYTORCH if self.reads == 1 else BackendName.MOJO

        @name.setter
        def name(self, value: BackendName) -> None:
            del value

    with pytest.raises(BackendSelectionError) as unknown:
        BackendRegistry((FakeBackend(BackendName.PYTORCH), FakeBackend(BackendName.MOJO), UnknownBackend()))  # type: ignore[arg-type]
    assert unknown.value.code == "BACKEND-REGISTRY-NAME"

    unstable = UnstableBackend(BackendName.PYTORCH)
    registered = BackendRegistry((unstable, FakeBackend(BackendName.MOJO)))
    assert registered.get(BackendName.PYTORCH) is unstable
    assert unstable.reads == 1


@pytest.mark.parametrize("invocation_id", ["", "   "])
def test_invalid_invocation_identity_stops_before_adapter_call(invocation_id: str) -> None:
    backends, pytorch, mojo = registry()

    with pytest.raises(BackendSelectionError) as raised:
        execute_attention(
            backends,
            request(ExecutionMode.INFERENCE, BackendName.PYTORCH),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=lambda: invocation_id,
        )

    assert raised.value.code == "BACKEND-INVOCATION-ID"
    assert pytorch.calls == mojo.calls == []


def test_invocation_identity_factory_failure_is_stable() -> None:
    backends, pytorch, mojo = registry()

    def fail() -> str:
        raise RuntimeError("identity service failed")

    with pytest.raises(BackendSelectionError) as raised:
        execute_attention(
            backends,
            request(ExecutionMode.INFERENCE, BackendName.PYTORCH),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=fail,
        )

    assert raised.value.as_dict() == {
        "code": "BACKEND-INVOCATION-ID",
        "message": "invocation identity could not be created",
        "context": {"error_type": "RuntimeError"},
    }
    assert pytorch.calls == mojo.calls == []


def test_domain_backend_port_has_no_framework_or_adapter_imports() -> None:
    path = Path(__file__).parents[2] / "src/mojoattention/domain/backends.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)

    forbidden = ("torch", "max", "mojoattention.backends", "mojoattention.cli", "mojoattention.validation")
    assert not any(module == prefix or module.startswith(prefix + ".") for module in imported for prefix in forbidden)


def test_backend_request_rejects_runtime_values_outside_typed_surface() -> None:
    with pytest.raises(BackendSelectionError) as raised:
        BackendRequest(mode="inference", backend=BackendName.MOJO, fallback=FallbackPolicy.FORBID)  # type: ignore[arg-type]
    assert raised.value.code == "BACKEND-CONFIG"


@pytest.mark.parametrize(
    ("mode", "backend"),
    [
        (ExecutionMode.TRAINING, None),
        (ExecutionMode.TRAINING, BackendName.PYTORCH),
        (ExecutionMode.INFERENCE, BackendName.PYTORCH),
    ],
)
def test_fallback_policy_is_valid_only_for_mojo_inference(mode: ExecutionMode, backend: BackendName | None) -> None:
    with pytest.raises(BackendSelectionError) as raised:
        BackendRequest(
            mode=mode,
            backend=backend,
            fallback=FallbackPolicy.ALLOW_MOJO_TO_PYTORCH,
        )
    assert raised.value.code == "BACKEND-FALLBACK-POLICY"

    with pytest.raises(BackendSelectionError) as raised:
        BackendRequest(mode=ExecutionMode.INFERENCE, backend="mojo", fallback=FallbackPolicy.FORBID)  # type: ignore[arg-type]
    assert raised.value.code == "BACKEND-CONFIG"


def test_pytorch_failure_does_not_trigger_retry_or_fallback() -> None:
    failure = BackendFailure(BackendFailureKind.EXECUTION, {"detail": "pytorch failed"})
    pytorch = FakeBackend(BackendName.PYTORCH, failure)
    mojo = FakeBackend(BackendName.MOJO)

    with pytest.raises(BackendSelectionError) as raised:
        execute_attention(
            BackendRegistry((pytorch, mojo)),
            request(ExecutionMode.INFERENCE, BackendName.PYTORCH),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=lambda: "invocation-pytorch",
        )

    assert raised.value.code == "BACKEND-PYTORCH-EXECUTION"
    assert len(pytorch.calls) == 1
    assert mojo.calls == []


def test_failed_pytorch_fallback_preserves_mojo_reason_and_request_identity() -> None:
    mojo_failure = BackendFailure(BackendFailureKind.UNAVAILABLE, {"stage": "load"})
    pytorch_failure = BackendFailure(BackendFailureKind.EXECUTION, {"stage": "fallback"})
    pytorch = FakeBackend(BackendName.PYTORCH, pytorch_failure)
    mojo = FakeBackend(BackendName.MOJO, mojo_failure)

    with pytest.raises(BackendSelectionError) as raised:
        execute_attention(
            BackendRegistry((pytorch, mojo)),
            request(ExecutionMode.INFERENCE, BackendName.MOJO, FallbackPolicy.ALLOW_MOJO_TO_PYTORCH),
            object(),
            object(),
            object(),
            object(),
            invocation_id_factory=lambda: "invocation-fallback-failed",
        )

    assert raised.value.as_dict() == {
        "code": "BACKEND-PYTORCH-EXECUTION",
        "message": "requested backend execution failed",
        "context": {
            "executed_backend": "pytorch",
            "failure_context": {"stage": "fallback"},
            "fallback_reason": "BACKEND-MOJO-UNAVAILABLE",
            "invocation_id": "invocation-fallback-failed",
            "policy": "allow-mojo-to-pytorch",
            "requested_backend": "mojo",
        },
    }
    assert len(mojo.calls) == len(pytorch.calls) == 1


def test_error_contexts_are_snapshotted_and_serialized_defensively() -> None:
    source = {"nested": {"value": 1}}
    failure = BackendFailure(BackendFailureKind.INVALID, source)
    source["nested"]["value"] = 2  # type: ignore[index]
    assert failure.context == {"nested": {"value": 1}}

    context = {"nested": {"value": 1}}
    error = BackendSelectionError("CODE", "message", context)
    context["nested"]["value"] = 2  # type: ignore[index]
    rendered = error.as_dict()
    rendered_context = rendered["context"]
    assert isinstance(rendered_context, dict)
    rendered_context["nested"] = {"value": 3}
    assert error.context == {"nested": {"value": 1}}
