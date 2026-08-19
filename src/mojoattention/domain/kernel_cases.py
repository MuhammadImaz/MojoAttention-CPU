from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from mojoattention.domain.kernel_contract import KernelContract, KernelShape

GENERATOR_ID = "mojoattention-counter-sha256"
GENERATOR_VERSION = 1
CASE_KINDS = ("fixed-zero", "boundary-alternating", "seeded-interior")
TENSOR_LABELS = ("q", "k", "v")


@dataclass(frozen=True, slots=True)
class CaseMatrixEntry:
    case_id: str
    shape: KernelShape
    kind: str
    seed: int


@dataclass(frozen=True, slots=True)
class GeneratedCase:
    case_id: str
    shape: KernelShape
    kind: str
    seed: int
    q: bytes
    k: bytes
    v: bytes
    q_sha256: str
    k_sha256: str
    v_sha256: str


def _identity(shape: KernelShape, kind: str, seed: int) -> str:
    return f"v1-b{shape.batch}-h{shape.heads}-s{shape.sequence}-d{shape.head_dimension}-{kind}-seed{seed}"


def matrix_entries(contract: KernelContract) -> tuple[CaseMatrixEntry, ...]:
    return tuple(
        CaseMatrixEntry(_identity(shape, kind, 0), shape, kind, 0) for shape in contract.shapes for kind in CASE_KINDS
    )


def _element_count(shape: KernelShape) -> int:
    values = (shape.batch, shape.heads, shape.sequence, shape.head_dimension)
    if any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in values):
        raise ValueError("kernel case shape dimensions must be positive integers")
    return shape.batch * shape.heads * shape.sequence * shape.head_dimension


def _seeded_bytes(shape: KernelShape, kind: str, seed: int, label: str) -> bytes:
    if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= (1 << 63) - 1:
        raise ValueError("kernel case seed must be an integer in [0, 2^63-1]")
    if kind not in CASE_KINDS or label not in TENSOR_LABELS:
        raise ValueError("kernel case kind or tensor label is unsupported")
    count = _element_count(shape)
    if kind == "fixed-zero":
        return bytes(count * 4)
    if kind == "boundary-alternating":
        phase = TENSOR_LABELS.index(label)
        return b"".join(struct.pack("<f", -20.0 if (index + phase) % 2 == 0 else 20.0) for index in range(count))
    prefix = f"{GENERATOR_ID}\0{GENERATOR_VERSION}\0{_identity(shape, kind, seed)}\0{label}\0".encode("ascii")
    output = bytearray()
    for counter in range(count):
        word = int.from_bytes(hashlib.sha256(prefix + counter.to_bytes(8, "little")).digest()[:4], "little")
        signed = (word % 40959) - 20479
        output.extend(struct.pack("<f", signed / 1024.0))
    return bytes(output)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def generate_case(shape: KernelShape, kind: str, seed: int) -> GeneratedCase:
    q, k, v = (_seeded_bytes(shape, kind, seed, label) for label in TENSOR_LABELS)
    return GeneratedCase(_identity(shape, kind, seed), shape, kind, seed, q, k, v, _digest(q), _digest(k), _digest(v))
