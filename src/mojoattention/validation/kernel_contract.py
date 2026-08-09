from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import product
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from mojoattention.domain.kernel_contract import compute_kernel_contract_digest


@dataclass(frozen=True, slots=True)
class KernelContractError:
    code: str
    message: str
    context: dict[str, object]


AXES = [
    {"symbol": "B", "meaning": "batch"},
    {"symbol": "H", "meaning": "query-key-value-head"},
    {"symbol": "S", "meaning": "query-key-position"},
    {"symbol": "D", "meaning": "head-feature"},
]
ARGUMENT_ORDER = ["q", "k", "v", "out", "B", "H", "S", "D"]
ERROR_CODES = [
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
]
ERROR_MESSAGES = [
    "tensor device is unsupported",
    "tensor dtype is unsupported",
    "tensor rank is unsupported",
    "Q K and V shapes must match",
    "batch size is unsupported",
    "head count is unsupported",
    "sequence length is unsupported",
    "head dimension is unsupported",
    "tensor layout is unsupported",
    "tensor contains a nonfinite element",
    "tensor magnitude exceeds the supported bound",
    "input storage ranges overlap",
    "output shape must equal Q shape",
    "output layout must equal Q layout",
    "output storage overlaps an input",
    "tensor ownership is unsupported",
    "tensor lifetime is unsupported",
    "native operation did not completely write output",
]
ERROR_CONTEXT_KEYS = [
    ["tensor", "detected_device", "supported_device"],
    ["tensor", "detected_dtype", "supported_dtype"],
    ["tensor", "detected_rank", "required_rank"],
    ["q_shape", "k_shape", "v_shape"],
    ["detected_batch", "supported_batches"],
    ["detected_heads", "supported_heads"],
    ["detected_sequence", "supported_sequences"],
    ["detected_dimension", "supported_dimensions"],
    ["tensor", "detected_strides", "required_layout"],
    ["tensor", "index"],
    ["tensor", "index", "maximum_absolute_value"],
    ["first_tensor", "second_tensor"],
    ["detected_shape", "required_shape"],
    ["detected_strides", "required_strides"],
    ["input_tensor"],
    ["tensor", "required_owner"],
    ["tensor", "required_lifetime"],
    ["first_unwritten_index"],
]
GOLDEN_EXAMPLES = [
    {
        "case_id": "sequence-one",
        "purpose": "S=1 proves output equals V",
        "shape": {"B": 1, "H": 2, "S": 1, "D": 16},
        "q": [1],
        "k": [2],
        "v": [3],
        "expected_output": [3],
    },
    {
        "case_id": "two-token-causal",
        "purpose": "first query cannot observe the second key or value",
        "shape": {"B": 1, "H": 2, "S": 16, "D": 16},
        "q": [1, 1],
        "k": [1, 2],
        "v": [3, 9],
        "expected_output": [3, 7.386351],
    },
    {
        "case_id": "scale-sensitive-d16",
        "purpose": "D=16 distinguishes exactly-once square-root scaling",
        "shape": {"B": 1, "H": 2, "S": 16, "D": 16},
        "q": [4, 0],
        "k": [0, 4],
        "v": [2, 6],
        "expected_output": [2, 5.928055],
    },
]


def _schema_errors(record: object, schema_path: Path) -> tuple[KernelContractError, ...]:
    try:
        schema = json.loads(schema_path.read_bytes())
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(record),
            key=lambda item: (tuple(str(part) for part in item.absolute_path), item.message),
        )
    except (OSError, json.JSONDecodeError, TypeError, SchemaError) as error:
        return (
            KernelContractError("KCON-001", "kernel contract schema is unavailable or invalid", {"error": str(error)}),
        )
    return tuple(
        KernelContractError(
            "KCON-001",
            "kernel contract does not satisfy its schema",
            {"path": "/".join(str(part) for part in error.absolute_path)},
        )
        for error in errors
    )


def _expected_shapes() -> list[dict[str, int]]:
    return [{"B": b, "H": h, "S": s, "D": d} for b, h, s, d in product([1], [2, 4], [1, 16, 32, 64, 128], [16, 32, 64])]


def validate_kernel_contract(record: object, schema_path: Path) -> tuple[KernelContractError, ...]:
    errors = list(_schema_errors(record, schema_path))
    if errors or not isinstance(record, dict):
        return tuple(errors)
    if record["contract_digest"] != compute_kernel_contract_digest(record):
        errors.append(KernelContractError("KCON-002", "kernel contract digest does not bind canonical content", {}))
    domain = record["supported_domain"]
    assert isinstance(domain, dict)
    expected_domain = {
        "device": "cpu",
        "dtype": "float32",
        "batch_sizes": [1],
        "head_counts": [2, 4],
        "sequence_lengths": [1, 16, 32, 64, 128],
        "head_dimensions": [16, 32, 64],
        "finite_only": True,
        "maximum_absolute_value": 20,
        "required_total": 30,
    }
    domain_changed = any(domain.get(key) != value for key, value in expected_domain.items())
    if domain_changed or domain.get("shapes") != _expected_shapes():
        errors.append(
            KernelContractError("KCON-003", "supported domain or shape inventory differs from MVP authority", {})
        )
    semantics = record["semantics"]
    assert isinstance(semantics, dict)
    expected_semantics = {
        "score_equation": "score[b,h,i,j]=sum_d(Q[b,h,i,d]*K[b,h,j,d])/sqrt(D)",
        "mask_predicate": "j>i",
        "softmax_axis": "key-j",
        "output_equation": "O[b,h,i,d]=sum_j<=i(prob[b,h,i,j]*V[b,h,j,d])",
        "input_q_scaling": "unscaled",
        "q_is_pre_scaled": False,
        "scaling_count": 1,
        "arithmetic_dtype": "float32",
        "accumulation_dtype": "float32",
        "fully_masked_rows": "outside-contract",
    }
    if record["axes"] != AXES or any(semantics.get(key) != value for key, value in expected_semantics.items()):
        errors.append(
            KernelContractError("KCON-004", "mathematical semantics differ from causal attention authority", {})
        )
    memory = record["memory"]
    assert isinstance(memory, dict)
    expected_memory = {
        "rank": 4,
        "layout": "BHSD-row-major",
        "standard_contiguous_only": True,
        "channels_last_supported": False,
        "equal_qkv_shapes": True,
        "output_shape_equals_q": True,
        "output_strides_equal_q": True,
        "pairwise_non_overlapping": True,
        "implicit_copies": False,
        "input_mutation": False,
        "output_allocation": "pytorch-caller",
        "output_initialized_on_entry": False,
        "complete_output_write": True,
        "hidden_allocation": False,
    }
    if any(memory.get(key) != value for key, value in expected_memory.items()):
        errors.append(KernelContractError("KCON-005", "memory or ownership semantics differ from authority", {}))
    abi = record["native_abi"]
    assert isinstance(abi, dict)
    expected_abi = {
        "argument_order": ARGUMENT_ORDER,
        "tensor_element_type": "float32",
        "dimension_type": "int64",
        "minimum_alignment_bytes": 4,
        "input_lifetime": "borrowed-call-scoped",
        "output_lifetime": "caller-owned",
        "completion": "synchronous-before-return",
    }
    if any(abi.get(key) != value for key, value in expected_abi.items()):
        errors.append(KernelContractError("KCON-006", "native ABI differs from authority", {}))
    registry = record["errors"]
    assert isinstance(registry, list)
    registry_valid = (
        [item.get("code") for item in registry if isinstance(item, dict)] == ERROR_CODES
        and [item.get("message") for item in registry if isinstance(item, dict)] == ERROR_MESSAGES
        and [item.get("context_keys") for item in registry if isinstance(item, dict)] == ERROR_CONTEXT_KEYS
        and [item.get("precedence") for item in registry if isinstance(item, dict)] == list(range(1, 19))
        and all(
            isinstance(item, dict) and item.get("message") and isinstance(item.get("context_keys"), list)
            for item in registry
        )
    )
    if not registry_valid:
        errors.append(KernelContractError("KCON-007", "stable error registry or precedence differs from authority", {}))
    examples = record["golden_examples"]
    if examples != GOLDEN_EXAMPLES:
        errors.append(KernelContractError("KCON-008", "golden semantic examples are incomplete or reordered", {}))
    return tuple(errors)


def render_kernel_contract(record: dict[str, object]) -> str:
    domain = record["supported_domain"]
    semantics = record["semantics"]
    abi = record["native_abi"]
    assert isinstance(domain, dict) and isinstance(semantics, dict) and isinstance(abi, dict)
    lines = [
        "# MojoAttention Kernel Contract",
        "",
        f"Contract: `{record['contract_id']}` v{record['contract_version']}",
        f"Digest: `{record['contract_digest']}`",
        "",
        "## Semantics",
        "",
        f"- Score: `{semantics['score_equation']}`",
        f"- Causal mask rejects `{semantics['mask_predicate']}`.",
        f"- Softmax axis: `{semantics['softmax_axis']}`.",
        f"- Output: `{semantics['output_equation']}`.",
        "- Q is unscaled on entry; scaling occurs exactly once; arithmetic and accumulation are float32.",
        "",
        "## Supported domain",
        "",
        "- Device: CPU",
        "- Dtype: float32",
        "- Layout: contiguous BHSD row-major",
        "- B: 1",
        "- H: 2, 4",
        "- S: 1, 16, 32, 64, 128",
        "- D: 16, 32, 64",
        "- Inputs: finite and `abs(x) <= 20`",
        f"- Shape specializations: {domain['required_total']}",
        "",
        "| B | H | S | D |",
        "|---:|---:|---:|---:|",
    ]
    shapes = domain["shapes"]
    assert isinstance(shapes, list)
    lines.extend(f"| {item['B']} | {item['H']} | {item['S']} | {item['D']} |" for item in shapes)
    lines.extend(
        [
            "",
            "## Memory and ABI",
            "",
            "- Q, K, V, and output are pairwise non-overlapping.",
            "- PyTorch allocates output; native code completely writes it synchronously without hidden copies.",
            f"- Argument order: `{', '.join(abi['argument_order'])}`; dimensions are signed int64; "
            "minimum alignment is 4 bytes.",
            "",
            "## Stable errors",
            "",
            "| Precedence | Code | Message | Context keys |",
            "|---:|---|---|---|",
        ]
    )
    registry = record["errors"]
    assert isinstance(registry, list)
    lines.extend(
        f"| {item['precedence']} | `{item['code']}` | {item['message']} | {', '.join(item['context_keys']) or 'none'} |"
        for item in registry
    )
    lines.extend(["", "## Golden examples", ""])
    examples = record["golden_examples"]
    assert isinstance(examples, list)
    for item in examples:
        lines.extend(
            [
                f"### `{item['case_id']}`",
                "",
                str(item["purpose"]),
                "",
                f"Expected output: `{json.dumps(item['expected_output'], separators=(',', ':'))}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Versioning and validation",
            "",
            "Any semantic or domain change changes the canonical digest and requires complete downstream "
            "regeneration and revalidation.",
            "",
            "```bash",
            "scripts/run.sh mojoattention kernel-contract validate --contract "
            "contracts/kernel/kernel-contract.json --schema schemas/kernel-contract.schema.json --json -",
            "scripts/run.sh mojoattention kernel-contract show --contract contracts/kernel/kernel-contract.json "
            "--schema schemas/kernel-contract.schema.json",
            "```",
            "",
        ]
    )
    return "\n".join(lines)
