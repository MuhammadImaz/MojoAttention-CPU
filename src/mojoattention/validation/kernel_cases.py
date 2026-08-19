from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from mojoattention.domain.kernel_cases import CASE_KINDS, GENERATOR_ID, GENERATOR_VERSION, matrix_entries
from mojoattention.domain.kernel_contract import KernelContract


@dataclass(frozen=True, slots=True)
class KernelCaseError:
    code: str
    message: str
    context: dict[str, object]


def canonical_matrix_bytes(record: dict[str, object]) -> bytes:
    unsigned = dict(record)
    unsigned.pop("matrix_digest", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def compute_matrix_digest(record: dict[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_matrix_bytes(record)).hexdigest()


def expected_matrix(contract: KernelContract) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": "1.0.0",
        "matrix_id": "mojoattention-kernel-cases",
        "matrix_version": 1,
        "matrix_digest": "",
        "generator": {"id": GENERATOR_ID, "version": GENERATOR_VERSION},
        "kernel_contract": {
            "id": contract.contract_id,
            "version": contract.contract_version,
            "digest": contract.contract_digest,
        },
        "bounds": {"minimum": -20.0, "maximum": 20.0},
        "serialization": "little-endian-float32-contiguous-BHSD",
        "case_kinds": list(CASE_KINDS),
        "required_shapes": 30,
        "required_entries": 90,
        "entries": [
            {
                "case_id": item.case_id,
                "shape": {
                    "B": item.shape.batch,
                    "H": item.shape.heads,
                    "S": item.shape.sequence,
                    "D": item.shape.head_dimension,
                },
                "kind": item.kind,
                "seed": item.seed,
            }
            for item in matrix_entries(contract)
        ],
    }
    record["matrix_digest"] = compute_matrix_digest(record)
    return record


def validate_matrix(record: object, schema_path: Path, contract: KernelContract) -> tuple[KernelCaseError, ...]:
    try:
        schema = json.loads(schema_path.read_bytes())
        Draft202012Validator.check_schema(schema)
        issues = sorted(Draft202012Validator(schema).iter_errors(record), key=lambda item: list(item.absolute_path))
    except (OSError, ValueError, SchemaError) as error:
        return (KernelCaseError("KCASE-001", "kernel case matrix or schema is invalid", {"error": str(error)[:256]}),)
    if issues or not isinstance(record, dict):
        return tuple(
            KernelCaseError(
                "KCASE-001", "kernel case matrix schema validation failed", {"path": list(item.absolute_path)}
            )
            for item in issues
        )
    if record != expected_matrix(contract):
        return (
            KernelCaseError("KCASE-002", "kernel case matrix differs from canonical contract-derived inventory", {}),
        )
    return ()


def matrix_json(contract: KernelContract) -> str:
    return (
        json.dumps(
            expected_matrix(contract), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        + "\n"
    )
