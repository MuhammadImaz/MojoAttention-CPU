from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from itertools import product
from pathlib import Path

import pytest

from mojoattention.domain.kernel_contract import compute_kernel_contract_digest, load_kernel_contract
from mojoattention.validation.kernel_contract import render_kernel_contract, validate_kernel_contract

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "contracts/kernel/kernel-contract.json"
SCHEMA_PATH = ROOT / "schemas/kernel-contract.schema.json"
DOC_PATH = ROOT / "docs/kernel-contract.md"


def contract() -> dict[str, object]:
    return json.loads(CONTRACT_PATH.read_bytes())


def codes(record: object) -> set[str]:
    return {item.code for item in validate_kernel_contract(record, SCHEMA_PATH)}


def test_canonical_contract_and_projection_pass() -> None:
    record = contract()
    assert validate_kernel_contract(record, SCHEMA_PATH) == ()
    loaded = load_kernel_contract(CONTRACT_PATH, SCHEMA_PATH)
    assert loaded.contract_digest == record["contract_digest"]
    assert compute_kernel_contract_digest(record) == record["contract_digest"]
    assert render_kernel_contract(record) == DOC_PATH.read_text(encoding="utf-8")


def test_supported_domain_is_exact_ordered_cartesian_product() -> None:
    record = contract()
    domain = record["supported_domain"]
    expected = [
        {"B": b, "H": h, "S": s, "D": d} for b, h, s, d in product([1], [2, 4], [1, 16, 32, 64, 128], [16, 32, 64])
    ]
    assert domain["shapes"] == expected
    assert domain["required_total"] == len(expected) == 30
    assert domain["device"] == "cpu"
    assert domain["dtype"] == "float32"
    assert domain["finite_only"] is True
    assert domain["maximum_absolute_value"] == 20


def test_semantics_memory_and_abi_are_singular() -> None:
    record = contract()
    assert record["axes"] == [
        {"symbol": "B", "meaning": "batch"},
        {"symbol": "H", "meaning": "query-key-value-head"},
        {"symbol": "S", "meaning": "query-key-position"},
        {"symbol": "D", "meaning": "head-feature"},
    ]
    semantics = record["semantics"]
    assert semantics["score_equation"].endswith("/sqrt(D)")
    assert semantics["mask_predicate"] == "j>i"
    assert semantics["softmax_axis"] == "key-j"
    assert semantics["accumulation_dtype"] == "float32"
    assert semantics["q_is_pre_scaled"] is False
    memory = record["memory"]
    assert memory["layout"] == "BHSD-row-major"
    assert memory["pairwise_non_overlapping"] is True
    assert memory["implicit_copies"] is False
    assert memory["complete_output_write"] is True
    assert record["native_abi"]["argument_order"] == ["q", "k", "v", "out", "B", "H", "S", "D"]


def test_error_registry_is_complete_ordered_and_safe() -> None:
    errors = contract()["errors"]
    assert [item["precedence"] for item in errors] == list(range(1, len(errors) + 1))
    assert len({item["code"] for item in errors}) == len(errors)
    required = {
        "KERNEL-DEVICE",
        "KERNEL-DTYPE",
        "KERNEL-RANK",
        "KERNEL-SHAPE",
        "KERNEL-BATCH",
        "KERNEL-HEADS",
        "KERNEL-SEQUENCE",
        "KERNEL-DIMENSION",
        "KERNEL-LAYOUT",
        "KERNEL-NONFINITE",
        "KERNEL-MAGNITUDE",
        "KERNEL-INPUT-OVERLAP",
        "KERNEL-OUTPUT-SHAPE",
        "KERNEL-OUTPUT-LAYOUT",
        "KERNEL-OUTPUT-OVERLAP",
        "KERNEL-OWNERSHIP",
        "KERNEL-LIFETIME",
        "KERNEL-INCOMPLETE-WRITE",
    }
    assert {item["code"] for item in errors} == required
    forbidden = {"address", "path", "timestamp", "value", "values"}
    assert all(not forbidden.intersection(item["context_keys"]) for item in errors)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda item: item.update({"unknown": True}), "KCON-001"),
        (lambda item: item.pop("semantics"), "KCON-001"),
        (lambda item: item.update({"schema_version": "2.0.0"}), "KCON-001"),
        (lambda item: item.update({"contract_digest": "sha256:" + "0" * 64}), "KCON-002"),
        (lambda item: item["supported_domain"].update({"required_total": 29}), "KCON-003"),
        (lambda item: item["supported_domain"]["shapes"].pop(), "KCON-003"),
        (lambda item: item["supported_domain"]["head_dimensions"].append(128), "KCON-003"),
        (lambda item: item["semantics"].update({"softmax_axis": "query-i"}), "KCON-004"),
        (lambda item: item["semantics"].update({"mask_predicate": "j<i"}), "KCON-004"),
        (lambda item: item["semantics"].update({"accumulation_dtype": "float64"}), "KCON-004"),
        (lambda item: item["memory"].update({"implicit_copies": True}), "KCON-005"),
        (lambda item: item["memory"].update({"pairwise_non_overlapping": False}), "KCON-005"),
        (lambda item: item["memory"].update({"complete_output_write": False}), "KCON-005"),
        (lambda item: item["native_abi"]["argument_order"].reverse(), "KCON-006"),
        (lambda item: item["axes"].reverse(), "KCON-004"),
        (lambda item: item["supported_domain"].update({"finite_only": False}), "KCON-003"),
        (lambda item: item["supported_domain"].update({"maximum_absolute_value": 21}), "KCON-003"),
        (lambda item: item["errors"].reverse(), "KCON-007"),
        (lambda item: item["golden_examples"][1]["expected_output"].append(99), "KCON-008"),
        (lambda item: item["semantics"].update({"score_equation": "wrong"}), "KCON-004"),
        (lambda item: item["errors"][0].update({"message": "changed"}), "KCON-007"),
        (lambda item: item["errors"][0]["context_keys"].append("address"), "KCON-007"),
        (
            lambda item: item["supported_domain"]["shapes"].append(deepcopy(item["supported_domain"]["shapes"][0])),
            "KCON-001",
        ),
    ],
)
def test_semantic_mutations_fail(mutation: object, expected_code: str) -> None:
    changed = deepcopy(contract())
    mutation(changed)
    if expected_code != "KCON-002":
        changed["contract_digest"] = compute_kernel_contract_digest(changed)
    assert expected_code in codes(changed)
    assert validate_kernel_contract(contract(), SCHEMA_PATH) == ()


def test_cli_validate_show_and_contract_invalid_exit() -> None:
    base = [sys.executable, "-m", "mojoattention.cli.main", "kernel-contract"]
    validate = subprocess.run(
        [*base, "validate", "--contract", str(CONTRACT_PATH), "--schema", str(SCHEMA_PATH), "--json", "-"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert validate.returncode == 0
    assert json.loads(validate.stdout) == {"errors": [], "verdict": "pass"}
    show = subprocess.run(
        [*base, "show", "--contract", str(CONTRACT_PATH), "--schema", str(SCHEMA_PATH)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert show.returncode == 0
    assert show.stdout == DOC_PATH.read_text(encoding="utf-8")
    invalid = deepcopy(contract())
    invalid["contract_digest"] = "sha256:" + "0" * 64
    temporary = ROOT / ".cache/kernel-contract-invalid.json"
    temporary.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_text(json.dumps(invalid), encoding="utf-8")
    try:
        failed = subprocess.run(
            [*base, "validate", "--contract", str(temporary), "--schema", str(SCHEMA_PATH), "--json", "-"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        temporary.unlink(missing_ok=True)
    assert failed.returncode == 3
    assert json.loads(failed.stdout)["verdict"] == "contract-invalid"
