from __future__ import annotations

from typing import Protocol, TypeVar

TensorT = TypeVar("TensorT", contravariant=True)


class AttentionDispatch(Protocol[TensorT]):
    def __call__(self, q: TensorT, k: TensorT, v: TensorT, out: TensorT) -> None: ...
