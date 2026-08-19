from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from itertools import product
from pathlib import Path

from mojoattention.domain.kernel_cases import CASE_KINDS, generate_case, matrix_entries
from mojoattention.domain.kernel_contract import KernelShape, load_kernel_contract
from mojoattention.validation.kernel_cases import expected_matrix, validate_matrix


def expected_shapes() -> tuple[KernelShape, ...]:
    return tuple(KernelShape(b, h, s, d) for b, h, s, d in product([1], [2, 4], [1, 16, 32, 64, 128], [16, 32, 64]))


def test_matrix_is_complete_ordered_and_contract_derived() -> None:
    contract = load_kernel_contract(ROOT / "contracts/kernel/kernel-contract.json")
    assert contract.shapes == expected_shapes()
    entries = matrix_entries(contract)
    assert CASE_KINDS == ("fixed-zero", "boundary-alternating", "seeded-interior")
    assert len(entries) == 90
    assert tuple((entry.shape, entry.kind) for entry in entries) == tuple(
        (shape, kind) for shape in expected_shapes() for kind in CASE_KINDS
    )
    assert len({entry.case_id for entry in entries}) == 90


def test_generation_is_byte_exact_bounded_and_domain_separated() -> None:
    shape = KernelShape(1, 2, 16, 16)
    first = generate_case(shape, "seeded-interior", 42)
    second = generate_case(shape, "seeded-interior", 42)
    assert first == second
    assert len({first.q_sha256, first.k_sha256, first.v_sha256}) == 3
    expected_bytes = shape.batch * shape.heads * shape.sequence * shape.head_dimension * 4
    for payload, digest in ((first.q, first.q_sha256), (first.k, first.k_sha256), (first.v, first.v_sha256)):
        assert len(payload) == expected_bytes
        assert digest == "sha256:" + hashlib.sha256(payload).hexdigest()
        values = struct.unpack(f"<{expected_bytes // 4}f", payload)
        assert all(-20.0 < value < 20.0 for value in values)


def test_fixed_and_boundary_cases_have_exact_v1_semantics() -> None:
    shape = KernelShape(1, 2, 1, 16)
    fixed = generate_case(shape, "fixed-zero", 0)
    assert fixed.q == fixed.k == fixed.v == bytes(2 * 16 * 4)
    boundary = generate_case(shape, "boundary-alternating", 0)
    for payload in (boundary.q, boundary.k, boundary.v):
        assert set(struct.unpack("<32f", payload)) == {-20.0, 20.0}


def test_strict_matrix_validation_rejects_inventory_mutations() -> None:
    contract = load_kernel_contract(ROOT / "contracts/kernel/kernel-contract.json")
    schema = ROOT / "schemas/kernel-case-matrix.schema.json"
    record = expected_matrix(contract)
    assert validate_matrix(record, schema, contract) == ()
    for mutation in (
        lambda item: item["entries"].pop(),
        lambda item: item["entries"].append(dict(item["entries"][0])),
        lambda item: item["entries"].reverse(),
        lambda item: item.update({"matrix_digest": "sha256:" + "0" * 64}),
        lambda item: item.update({"unknown": True}),
    ):
        changed = json.loads(json.dumps(record))
        mutation(changed)
        assert validate_matrix(changed, schema, contract)


def test_tracked_matrix_and_cli_validate_and_reproduce() -> None:
    contract = load_kernel_contract(ROOT / "contracts/kernel/kernel-contract.json")
    matrix_path = ROOT / "contracts/kernel/kernel-case-matrix.json"
    schema_path = ROOT / "schemas/kernel-case-matrix.schema.json"
    record = json.loads(matrix_path.read_bytes())
    assert record == expected_matrix(contract)
    assert validate_matrix(record, schema_path, contract) == ()
    base = [sys.executable, "-m", "mojoattention.cli.main", "kernel-cases"]
    validated = subprocess.run(
        [
            *base,
            "validate",
            "--matrix",
            str(matrix_path),
            "--schema",
            str(schema_path),
            "--contract",
            str(ROOT / "contracts/kernel/kernel-contract.json"),
            "--json",
            "-",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert validated.returncode == 0
    assert json.loads(validated.stdout) == {"errors": [], "verdict": "pass"}
    generated = subprocess.run(
        [
            *base,
            "generate",
            "--contract",
            str(ROOT / "contracts/kernel/kernel-contract.json"),
            "--case-id",
            "v1-b1-h2-s16-d16-seeded-interior-seed0",
            "--seed",
            "42",
            "--json",
            "-",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert generated.returncode == 0
    payload = json.loads(generated.stdout)
    assert payload["verdict"] == "pass"
    assert payload["seed"] == 42
    assert len({payload["tensors"][name]["sha256"] for name in ("q", "k", "v")}) == 3


ROOT = Path(__file__).resolve().parents[2]
