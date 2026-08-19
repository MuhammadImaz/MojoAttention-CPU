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


def load_kernel_contract(contract_path: Path) -> KernelContract:
    record: Any = json.loads(contract_path.read_bytes())
    if not isinstance(record, dict):
        raise ValueError("kernel contract is not an object")
    try:
        domain = record["supported_domain"]
        if not isinstance(domain, dict) or not isinstance(domain["shapes"], list):
            raise TypeError("kernel contract domain is not structured")
        shapes = tuple(
            KernelShape(int(item["B"]), int(item["H"]), int(item["S"]), int(item["D"]))
            for item in domain["shapes"]
            if isinstance(item, dict)
        )
        if len(shapes) != len(domain["shapes"]):
            raise TypeError("kernel contract shape is not structured")
        return KernelContract(
            schema_version=str(record["schema_version"]),
            contract_id=str(record["contract_id"]),
            contract_version=int(record["contract_version"]),
            contract_digest=str(record["contract_digest"]),
            shapes=shapes,
            raw=deepcopy(record),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("kernel contract cannot be loaded") from error
