from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
import torch

from mojoattention.domain.kernel_cases import CaseMatrixEntry, generate_case, matrix_entries
from mojoattention.domain.kernel_contract import KernelContract, compute_kernel_contract_digest, load_kernel_contract
from mojoattention.validation.attention_inputs import (
    AttentionValidationResult,
    KernelContractAuthorityError,
    validate_and_dispatch,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = load_kernel_contract(ROOT / "contracts/kernel/kernel-contract.json")
EXPECTED_CONTEXTS: dict[str, dict[str, object]] = {
    "KERNEL-DTYPE": {"tensor": "q", "detected_dtype": "float64", "supported_dtype": "float32"},
    "KERNEL-RANK": {"tensor": "q", "detected_rank": 3, "required_rank": 4},
    "KERNEL-SHAPE": {
        "q_shape": [1, 2, 16, 16],
        "k_shape": [1, 2, 1, 16],
        "v_shape": [1, 2, 16, 16],
    },
    "KERNEL-BATCH": {"detected_batch": 2, "supported_batches": [1]},
    "KERNEL-HEADS": {"detected_heads": 1, "supported_heads": [2, 4]},
    "KERNEL-SEQUENCE": {"detected_sequence": 2, "supported_sequences": [1, 16, 32, 64, 128]},
    "KERNEL-DIMENSION": {"detected_dimension": 15, "supported_dimensions": [16, 32, 64]},
    "KERNEL-LAYOUT": {"tensor": "q", "detected_strides": [512, 256, 1, 16], "required_layout": "BHSD-row-major"},
    "KERNEL-MAGNITUDE": {"tensor": "q", "index": [0, 0, 0, 0], "maximum_absolute_value": 20.0},
    "KERNEL-OUTPUT-SHAPE": {"detected_shape": [1, 2, 1, 16], "required_shape": [1, 2, 16, 16]},
    "KERNEL-OUTPUT-LAYOUT": {
        "detected_strides": [512, 256, 1, 16],
        "required_strides": [512, 256, 16, 1],
    },
    "KERNEL-INPUT-OVERLAP": {"first_tensor": "q", "second_tensor": "k"},
    "KERNEL-OUTPUT-OVERLAP": {"input_tensor": "q"},
}


class DispatchSpy:
    def __init__(self, write: bool = True) -> None:
        self.calls = 0
        self.write = write

    def __call__(self, q: torch.Tensor, k: torch.Tensor, v: torch.Tensor, out: torch.Tensor) -> None:
        self.calls += 1
        if self.write:
            out.zero_()


class IdentityDispatch(DispatchSpy):
    def __init__(self) -> None:
        super().__init__()
        self.arguments: tuple[torch.Tensor, ...] | None = None

    def __call__(self, q: torch.Tensor, k: torch.Tensor, v: torch.Tensor, out: torch.Tensor) -> None:
        self.arguments = (q, k, v, out)
        super().__call__(q, k, v, out)


def assert_exact_contract_error(result: object, code: str) -> None:
    validation = cast("AttentionValidationResult", result)
    authority = next(item for item in cast(list[dict[str, object]], CONTRACT.raw["errors"]) if item["code"] == code)
    assert validation.error is not None
    assert validation.error.code == code
    assert validation.error.message == authority["message"]
    assert validation.error.context == EXPECTED_CONTEXTS[code]
    assert list(validation.error.context) == authority["context_keys"]


def valid() -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    return tuple(torch.zeros((1, 2, 16, 16), dtype=torch.float32) for _ in range(4))  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda q, k, v, out: (q.double(), k, v, out), "KERNEL-DTYPE"),
        (lambda q, k, v, out: (q[0], k[0], v[0], out[0]), "KERNEL-RANK"),
        (lambda q, k, v, out: (q, k[:, :, :1], v, out), "KERNEL-SHAPE"),
        (
            lambda q, k, v, out: (
                q.expand(2, -1, -1, -1),
                k.expand(2, -1, -1, -1),
                v.expand(2, -1, -1, -1),
                out.expand(2, -1, -1, -1),
            ),
            "KERNEL-BATCH",
        ),
        (lambda q, k, v, out: (q[:, :1], k[:, :1], v[:, :1], out[:, :1]), "KERNEL-HEADS"),
        (lambda q, k, v, out: (q[:, :, :2], k[:, :, :2], v[:, :, :2], out[:, :, :2]), "KERNEL-SEQUENCE"),
        (lambda q, k, v, out: (q[..., :15], k[..., :15], v[..., :15], out[..., :15]), "KERNEL-DIMENSION"),
        (
            lambda q, k, v, out: (q.transpose(-1, -2), k.transpose(-1, -2), v.transpose(-1, -2), out.transpose(-1, -2)),
            "KERNEL-LAYOUT",
        ),
    ],
)
def test_invalid_inputs_stop_before_dispatch(
    mutation: Callable[
        [torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor],
        tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor],
    ],
    code: str,
) -> None:
    q, k, v, out = mutation(*valid())
    originals = tuple(value.clone() for value in (q, k, v, out))
    spy = DispatchSpy()
    result = validate_and_dispatch(q, k, v, out, CONTRACT, spy)
    assert_exact_contract_error(result, code)
    assert result.dispatched is False
    assert spy.calls == 0
    for value, original in zip((q, k, v, out), originals, strict=True):
        torch.testing.assert_close(value, original, equal_nan=True)


def test_nonfinite_magnitude_and_precedence_are_stable() -> None:
    q, k, v, out = valid()
    q[0, 0, 0, 0] = torch.nan
    q[0, 0, 0, 1] = 21
    originals = tuple(value.clone() for value in (q, k, v, out))
    spy = DispatchSpy()
    result = validate_and_dispatch(q, k, v, out, CONTRACT, spy)
    assert result.error is not None
    assert (result.error.code, result.error.message, result.error.context) == (
        "KERNEL-NONFINITE",
        "tensor contains a nonfinite element",
        {"tensor": "q", "index": [0, 0, 0, 0]},
    )
    assert spy.calls == 0
    for value, original in zip((q, k, v, out), originals, strict=True):
        torch.testing.assert_close(value, original, equal_nan=True)


def test_magnitude_output_shape_and_output_layout_fail_before_dispatch() -> None:
    q, k, v, out = valid()
    q[0, 0, 0, 0] = 20.0001
    cases = [
        ((q, k, v, out), "KERNEL-MAGNITUDE"),
        ((*valid()[:3], torch.empty((1, 2, 1, 16))), "KERNEL-OUTPUT-SHAPE"),
    ]
    q2, k2, v2, out2 = valid()
    cases.append(((q2, k2, v2, out2.transpose(-1, -2)), "KERNEL-OUTPUT-LAYOUT"))
    for values, expected in cases:
        originals = tuple(value.clone() for value in values)
        spy = DispatchSpy()
        result = validate_and_dispatch(*values, CONTRACT, spy)
        assert_exact_contract_error(result, expected)
        assert spy.calls == 0
        assert all(torch.equal(value, original) for value, original in zip(values, originals, strict=True))


def test_input_and_output_aliases_stop_before_dispatch() -> None:
    q, k, v, out = valid()
    for values, expected in (((q, q, v, out), "KERNEL-INPUT-OVERLAP"), ((q, k, v, q), "KERNEL-OUTPUT-OVERLAP")):
        originals = tuple(value.clone() for value in values)
        spy = DispatchSpy()
        result = validate_and_dispatch(*values, CONTRACT, spy)
        assert_exact_contract_error(result, expected)
        assert spy.calls == 0
        assert all(torch.equal(value, original) for value, original in zip(values, originals, strict=True))


def test_partial_input_storage_overlap_stops_before_dispatch() -> None:
    shape = (1, 2, 16, 16)
    count = 1 * 2 * 16 * 16
    storage = torch.zeros(count + count // 2)
    q = storage[:count].view(shape)
    k = storage[count // 2 :].view(shape)
    v, out = valid()[2:]
    originals = tuple(value.clone() for value in (q, k, v, out))
    spy = DispatchSpy()
    result = validate_and_dispatch(q, k, v, out, CONTRACT, spy)
    assert_exact_contract_error(result, "KERNEL-INPUT-OVERLAP")
    assert spy.calls == 0
    assert all(torch.equal(value, original) for value, original in zip((q, k, v, out), originals, strict=True))


def test_external_buffer_overlap_with_distinct_storage_bases_stops_before_dispatch() -> None:
    shape = (1, 2, 16, 16)
    byte_count = 1 * 2 * 16 * 16 * 4
    backing = bytearray(byte_count + 256)
    q = torch.frombuffer(memoryview(backing)[:byte_count], dtype=torch.float32).view(shape)
    k = torch.frombuffer(memoryview(backing)[256:], dtype=torch.float32).view(shape)
    v, out = valid()[2:]
    originals = tuple(value.clone() for value in (q, k, v, out))
    spy = DispatchSpy()
    result = validate_and_dispatch(q, k, v, out, CONTRACT, spy)
    assert result.error is not None
    assert (result.error.code, result.error.message, result.error.context) == (
        "KERNEL-INPUT-OVERLAP",
        "input storage ranges overlap",
        {"first_tensor": "q", "second_tensor": "k"},
    )
    assert spy.calls == 0
    assert all(torch.equal(value, original) for value, original in zip((q, k, v, out), originals, strict=True))


def test_opaque_and_lazy_negative_layouts_are_rejected_stably() -> None:
    q, k, v, out = valid()
    for invalid in (q.to_mkldnn(), torch._neg_view(q)):
        invalid_original = invalid.to_dense().clone() if invalid.is_mkldnn else invalid.clone()
        originals = tuple(value.clone() for value in (k, v, out))
        spy = DispatchSpy()
        result = validate_and_dispatch(invalid, k, v, out, CONTRACT, spy)
        assert result.error is not None
        assert (result.error.code, result.error.message, result.error.context["tensor"]) == (
            "KERNEL-LAYOUT",
            "tensor layout is unsupported",
            "q",
        )
        assert spy.calls == 0
        observed = invalid.to_dense() if invalid.is_mkldnn else invalid
        assert torch.equal(observed, invalid_original)
        assert all(torch.equal(value, original) for value, original in zip((k, v, out), originals, strict=True))


def test_zero_stride_and_channels_last_like_layouts_are_rejected() -> None:
    q, k, v, out = valid()
    zero_stride = torch.zeros((1, 2, 16, 1)).expand(1, 2, 16, 16)
    channels_last = q.contiguous(memory_format=torch.channels_last)
    for invalid in (zero_stride, channels_last):
        originals = tuple(value.clone() for value in (invalid, k, v, out))
        spy = DispatchSpy()
        result = validate_and_dispatch(invalid, k, v, out, CONTRACT, spy)
        assert result.error is not None
        assert (result.error.code, result.error.message, result.error.context) == (
            "KERNEL-LAYOUT",
            "tensor layout is unsupported",
            {"tensor": "q", "detected_strides": list(invalid.stride()), "required_layout": "BHSD-row-major"},
        )
        assert spy.calls == 0
        assert all(
            torch.equal(value, original) for value, original in zip((invalid, k, v, out), originals, strict=True)
        )


def test_non_tensor_is_rejected_as_unsupported_ownership() -> None:
    _, k, v, out = valid()
    spy = DispatchSpy()
    result = validate_and_dispatch(cast(torch.Tensor, object()), k, v, out, CONTRACT, spy)
    assert result.error is not None
    assert (result.error.code, result.error.message, result.error.context) == (
        "KERNEL-OWNERSHIP",
        "tensor ownership is unsupported",
        {"tensor": "q", "required_owner": "pytorch-caller"},
    )
    assert spy.calls == 0


def test_meta_device_is_rejected_before_dispatch() -> None:
    _, k, v, out = valid()
    originals = tuple(value.clone() for value in (k, v, out))
    spy = DispatchSpy()
    result = validate_and_dispatch(torch.empty((1, 2, 16, 16), device="meta"), k, v, out, CONTRACT, spy)
    assert result.error is not None
    assert (result.error.code, result.error.message, result.error.context) == (
        "KERNEL-DEVICE",
        "tensor device is unsupported",
        {"tensor": "q", "detected_device": "meta", "supported_device": "cpu"},
    )
    assert spy.calls == 0
    assert all(torch.equal(value, original) for value, original in zip((k, v, out), originals, strict=True))


def test_contract_digest_tampering_is_a_stable_authority_failure() -> None:
    raw = deepcopy(CONTRACT.raw)
    domain = raw["supported_domain"]
    assert isinstance(domain, dict)
    domain["maximum_absolute_value"] = 19
    tampered = KernelContract(
        CONTRACT.schema_version,
        CONTRACT.contract_id,
        CONTRACT.contract_version,
        CONTRACT.contract_digest,
        CONTRACT.shapes,
        raw,
    )
    with pytest.raises(KernelContractAuthorityError, match="kernel contract digest does not bind canonical content"):
        validate_and_dispatch(*valid(), tampered, DispatchSpy())


def test_self_consistent_alternate_contract_is_not_authoritative() -> None:
    raw = deepcopy(CONTRACT.raw)
    raw["contract_version"] = 999
    raw["contract_digest"] = compute_kernel_contract_digest(raw)
    alternate = KernelContract(
        CONTRACT.schema_version,
        CONTRACT.contract_id,
        999,
        cast(str, raw["contract_digest"]),
        CONTRACT.shapes,
        raw,
    )
    with pytest.raises(KernelContractAuthorityError, match="kernel contract digest does not bind canonical content"):
        validate_and_dispatch(*valid(), alternate, DispatchSpy())


def test_mixed_typed_contract_metadata_is_not_authoritative() -> None:
    mixed = KernelContract(
        CONTRACT.schema_version,
        CONTRACT.contract_id,
        999,
        CONTRACT.contract_digest,
        CONTRACT.shapes,
        deepcopy(CONTRACT.raw),
    )
    with pytest.raises(KernelContractAuthorityError, match="kernel contract digest does not bind canonical content"):
        validate_and_dispatch(*valid(), mixed, DispatchSpy())


def test_valid_dispatch_once_and_incomplete_write_detected() -> None:
    q, k, v, out = valid()
    spy = DispatchSpy()
    passed = validate_and_dispatch(q, k, v, out, CONTRACT, spy)
    assert passed.error is None and passed.dispatched is True and spy.calls == 1
    q, k, v, out = valid()
    incomplete = DispatchSpy(write=False)
    failed = validate_and_dispatch(q, k, v, out, CONTRACT, incomplete)
    assert failed.error is not None
    assert (failed.error.code, failed.error.message, failed.error.context) == (
        "KERNEL-INCOMPLETE-WRITE",
        "native operation did not completely write output",
        {"first_unwritten_index": [0, 0, 0, 0]},
    )
    assert incomplete.calls == 1


def test_grad_and_inference_outputs_are_writable_at_the_native_boundary() -> None:
    q, k, v, _ = valid()
    grad_out = torch.empty_like(q, requires_grad=True)
    assert validate_and_dispatch(q, k, v, grad_out, CONTRACT, DispatchSpy()).error is None
    with torch.inference_mode():
        inference_out = torch.empty_like(q)
    assert validate_and_dispatch(q, k, v, inference_out, CONTRACT, DispatchSpy()).error is None


def test_nonfinite_native_output_cannot_satisfy_complete_write() -> None:
    class NonfiniteDispatch:
        def __call__(self, q: torch.Tensor, k: torch.Tensor, v: torch.Tensor, out: torch.Tensor) -> None:
            out.fill_(torch.nan)

    result = validate_and_dispatch(*valid(), CONTRACT, NonfiniteDispatch())
    assert result.error is not None and result.error.code == "KERNEL-INCOMPLETE-WRITE"
    assert result.dispatched is True


@pytest.mark.parametrize("entry", matrix_entries(CONTRACT), ids=lambda entry: entry.case_id)
def test_every_protected_case_dispatches_once_with_original_identities(entry: object) -> None:
    case_entry = cast(CaseMatrixEntry, entry)
    generated = generate_case(case_entry.shape, case_entry.kind, case_entry.seed)
    dimensions = (
        case_entry.shape.batch,
        case_entry.shape.heads,
        case_entry.shape.sequence,
        case_entry.shape.head_dimension,
    )
    q = torch.frombuffer(bytearray(generated.q), dtype=torch.float32).reshape(dimensions)
    k = torch.frombuffer(bytearray(generated.k), dtype=torch.float32).reshape(dimensions)
    v = torch.frombuffer(bytearray(generated.v), dtype=torch.float32).reshape(dimensions)
    values = (q, k, v, torch.empty_like(q))
    spy = IdentityDispatch()
    result = validate_and_dispatch(*values, CONTRACT, spy)
    assert result.error is None and result.dispatched is True and spy.calls == 1
    assert spy.arguments is not None
    assert all(actual is expected for actual, expected in zip(spy.arguments, values, strict=True))
