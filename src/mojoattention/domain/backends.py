from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class BackendName(StrEnum):
    PYTORCH = "pytorch"
    MOJO = "mojo"


class ExecutionMode(StrEnum):
    TRAINING = "training"
    INFERENCE = "inference"


class FallbackPolicy(StrEnum):
    FORBID = "forbid"
    ALLOW_MOJO_TO_PYTORCH = "allow-mojo-to-pytorch"


class BackendFailureKind(StrEnum):
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"
    EXECUTION = "execution"


_FAILURE_MESSAGES = {
    BackendFailureKind.UNAVAILABLE: "requested backend is unavailable",
    BackendFailureKind.INVALID: "requested backend is invalid",
    BackendFailureKind.EXECUTION: "requested backend execution failed",
}


class BackendSelectionError(RuntimeError):
    def __init__(self, code: str, message: str, context: dict[str, object]) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self._context = deepcopy(context)

    @property
    def context(self) -> dict[str, object]:
        return deepcopy(self._context)

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "message": self.message, "context": deepcopy(self._context)}


class BackendFailure(RuntimeError):
    """Typed adapter failure that may participate in explicit fallback policy."""

    def __init__(self, kind: BackendFailureKind, context: dict[str, object]) -> None:
        if not isinstance(kind, BackendFailureKind):
            raise BackendSelectionError("BACKEND-FAILURE", "backend failure kind is invalid", {"kind": str(kind)})
        self.kind = kind
        self.message = _FAILURE_MESSAGES[kind]
        self._context = deepcopy(context)
        super().__init__(self.message)

    @property
    def context(self) -> dict[str, object]:
        return deepcopy(self._context)

    def code(self, backend: BackendName) -> str:
        return f"BACKEND-{backend.value.upper()}-{self.kind.value.upper()}"


@dataclass(frozen=True, slots=True)
class BackendRequest:
    mode: ExecutionMode
    backend: BackendName | None
    fallback: FallbackPolicy = FallbackPolicy.FORBID

    def __post_init__(self) -> None:
        valid = (
            isinstance(self.mode, ExecutionMode)
            and (self.backend is None or isinstance(self.backend, BackendName))
            and isinstance(self.fallback, FallbackPolicy)
        )
        if not valid:
            raise BackendSelectionError(
                "BACKEND-CONFIG",
                "backend request contains an invalid typed value",
                {
                    "backend": str(self.backend),
                    "fallback": str(self.fallback),
                    "mode": str(self.mode),
                },
            )
        if self.fallback is FallbackPolicy.ALLOW_MOJO_TO_PYTORCH and not (
            self.mode is ExecutionMode.INFERENCE and self.backend is BackendName.MOJO
        ):
            raise BackendSelectionError(
                "BACKEND-FALLBACK-POLICY",
                "fallback is valid only for explicit Mojo inference",
                {
                    "backend": self.backend.value if self.backend is not None else None,
                    "fallback": self.fallback.value,
                    "mode": self.mode.value,
                },
            )


@dataclass(frozen=True, slots=True)
class BackendSelectionEvidence:
    invocation_id: str
    requested_backend: BackendName | None
    executed_backend: BackendName
    policy: FallbackPolicy
    fallback_reason: str | None


@dataclass(frozen=True, slots=True)
class BackendExecutionResult:
    evidence: BackendSelectionEvidence


class AttentionBackend[TensorT](Protocol):
    @property
    def name(self) -> BackendName: ...

    def __call__(self, q: TensorT, k: TensorT, v: TensorT, out: TensorT) -> None: ...
