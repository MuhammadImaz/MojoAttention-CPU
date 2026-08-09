from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def canonical_kernel_contract_bytes(contract: dict[str, object]) -> bytes:
    payload = deepcopy(contract)
    payload.pop("contract_digest", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def compute_kernel_contract_digest(contract: dict[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_kernel_contract_bytes(contract)).hexdigest()


@dataclass(frozen=True, slots=True)
class KernelShape:
    batch: int
    heads: int
    sequence: int
    head_dimension: int


@dataclass(frozen=True, slots=True)
class KernelContract:
    schema_version: str
    contract_id: str
    contract_version: int
    contract_digest: str
    shapes: tuple[KernelShape, ...]
    raw: dict[str, object]


def load_kernel_contract(contract_path: Path, schema_path: Path) -> KernelContract:
    from mojoattention.validation.kernel_contract import validate_kernel_contract

    record: Any = json.loads(contract_path.read_bytes())
    errors = validate_kernel_contract(record, schema_path)
    if errors or not isinstance(record, dict):
        raise ValueError("kernel contract is invalid")
    domain = record["supported_domain"]
    assert isinstance(domain, dict)
    raw_shapes = domain["shapes"]
    assert isinstance(raw_shapes, list)
    shapes = tuple(
        KernelShape(item["B"], item["H"], item["S"], item["D"]) for item in raw_shapes if isinstance(item, dict)
    )
    return KernelContract(
        schema_version=str(record["schema_version"]),
        contract_id=str(record["contract_id"]),
        contract_version=int(record["contract_version"]),
        contract_digest=str(record["contract_digest"]),
        shapes=shapes,
        raw=deepcopy(record),
    )
