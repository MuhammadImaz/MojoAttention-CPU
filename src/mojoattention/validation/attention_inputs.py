from __future__ import annotations

from dataclasses import dataclass

import torch

from mojoattention.domain.attention import AttentionDispatch
from mojoattention.domain.kernel_contract import KernelContract, compute_kernel_contract_digest

_UNWRITTEN_F32_BITS = 0x7FC01234


class KernelContractAuthorityError(RuntimeError):
    """The supplied authority is malformed or does not bind its content."""


@dataclass(frozen=True, slots=True)
class AttentionInputError:
    code: str
    message: str
    context: dict[str, object]


@dataclass(frozen=True, slots=True)
class AttentionValidationResult:
    error: AttentionInputError | None
    dispatched: bool


def _error(contract: KernelContract, code: str, context: dict[str, object]) -> AttentionInputError:
    try:
        errors = contract.raw["errors"]
        if not isinstance(errors, list):
            raise TypeError
        item = next(entry for entry in errors if isinstance(entry, dict) and entry.get("code") == code)
        keys = item["context_keys"]
        message = item["message"]
        if not isinstance(keys, list) or not isinstance(message, str) or not all(isinstance(key, str) for key in keys):
            raise TypeError
        bounded = {key: context[key] for key in keys}
    except (KeyError, StopIteration, TypeError) as error:
        raise KernelContractAuthorityError("kernel contract error registry is invalid") from error
    return AttentionInputError(code, message, bounded)


def _require_bound_authority(contract: KernelContract) -> None:
    try:
        recorded = contract.raw["contract_digest"]
        computed = compute_kernel_contract_digest(contract.raw)
    except (KeyError, TypeError, ValueError) as error:
        raise KernelContractAuthorityError("kernel contract authority is invalid") from error
    if recorded != contract.contract_digest or recorded != computed:
        raise KernelContractAuthorityError("kernel contract digest does not bind canonical content")


def _shape(value: torch.Tensor) -> list[int]:
    return list(value.shape)


def _ranges_overlap(left: torch.Tensor, right: torch.Tensor) -> bool:
    if left.untyped_storage().data_ptr() != right.untyped_storage().data_ptr():
        return False
    left_start = left.storage_offset() * left.element_size()
    right_start = right.storage_offset() * right.element_size()
    left_end = left_start + left.numel() * left.element_size()
    right_end = right_start + right.numel() * right.element_size()
    return left_start < right_end and right_start < left_end


def _first_nonfinite(value: torch.Tensor) -> list[int] | None:
    positions = (~torch.isfinite(value)).nonzero()
    return positions[0].tolist() if positions.numel() else None


def _first_excess(value: torch.Tensor, maximum: float) -> list[int] | None:
    positions = (torch.abs(value) > maximum).nonzero()
    return positions[0].tolist() if positions.numel() else None


def _has_standard_storage(value: torch.Tensor) -> bool:
    return value.layout is torch.strided and not value.is_conj() and not value.is_neg()


def _first_unwritten(value: torch.Tensor) -> list[int] | None:
    positions = (value.view(torch.int32) == _UNWRITTEN_F32_BITS).nonzero()
    return positions[0].tolist() if positions.numel() else None


def validate_and_dispatch(
    q: torch.Tensor,
    k: torch.Tensor,
    v: torch.Tensor,
    out: torch.Tensor,
    contract: KernelContract,
    dispatch: AttentionDispatch[torch.Tensor],
) -> AttentionValidationResult:
    _require_bound_authority(contract)
    tensors = (("q", q), ("k", k), ("v", v), ("out", out))
    for name, value in tensors:
        if not isinstance(value, torch.Tensor):
            return AttentionValidationResult(
                _error(contract, "KERNEL-OWNERSHIP", {"tensor": name, "required_owner": "pytorch-caller"}), False
            )
    for name, value in tensors:
        if value.device.type != "cpu":
            return AttentionValidationResult(
                _error(
                    contract,
                    "KERNEL-DEVICE",
                    {"tensor": name, "detected_device": value.device.type, "supported_device": "cpu"},
                ),
                False,
            )
    for name, value in tensors:
        if value.dtype != torch.float32:
            return AttentionValidationResult(
                _error(
                    contract,
                    "KERNEL-DTYPE",
                    {
                        "tensor": name,
                        "detected_dtype": str(value.dtype).removeprefix("torch."),
                        "supported_dtype": "float32",
                    },
                ),
                False,
            )
    for name, value in tensors:
        if value.ndim != 4:
            return AttentionValidationResult(
                _error(contract, "KERNEL-RANK", {"tensor": name, "detected_rank": value.ndim, "required_rank": 4}),
                False,
            )
    if q.shape != k.shape or q.shape != v.shape:
        return AttentionValidationResult(
            _error(contract, "KERNEL-SHAPE", {"q_shape": _shape(q), "k_shape": _shape(k), "v_shape": _shape(v)}), False
        )
    b, h, s, d = q.shape
    domain = contract.raw["supported_domain"]
    assert isinstance(domain, dict)
    checks = (
        ("KERNEL-BATCH", b, "supported_batches", domain["batch_sizes"], "detected_batch"),
        ("KERNEL-HEADS", h, "supported_heads", domain["head_counts"], "detected_heads"),
        ("KERNEL-SEQUENCE", s, "supported_sequences", domain["sequence_lengths"], "detected_sequence"),
        ("KERNEL-DIMENSION", d, "supported_dimensions", domain["head_dimensions"], "detected_dimension"),
    )
    for code, detected, supported_key, supported, detected_key in checks:
        if detected not in supported:
            return AttentionValidationResult(
                _error(contract, code, {detected_key: detected, supported_key: supported}), False
            )
    for name, value in tensors[:3]:
        if not _has_standard_storage(value) or not value.is_contiguous():
            return AttentionValidationResult(
                _error(
                    contract,
                    "KERNEL-LAYOUT",
                    {"tensor": name, "detected_strides": list(value.stride()), "required_layout": "BHSD-row-major"},
                ),
                False,
            )
    for name, value in tensors[:3]:
        if (index := _first_nonfinite(value)) is not None:
            return AttentionValidationResult(
                _error(contract, "KERNEL-NONFINITE", {"tensor": name, "index": index}), False
            )
    maximum = float(domain["maximum_absolute_value"])
    for name, value in tensors[:3]:
        if (index := _first_excess(value, maximum)) is not None:
            return AttentionValidationResult(
                _error(
                    contract, "KERNEL-MAGNITUDE", {"tensor": name, "index": index, "maximum_absolute_value": maximum}
                ),
                False,
            )
    for first_name, first, second_name, second in (("q", q, "k", k), ("q", q, "v", v), ("k", k, "v", v)):
        if _ranges_overlap(first, second):
            return AttentionValidationResult(
                _error(contract, "KERNEL-INPUT-OVERLAP", {"first_tensor": first_name, "second_tensor": second_name}),
                False,
            )
    if out.shape != q.shape:
        return AttentionValidationResult(
            _error(contract, "KERNEL-OUTPUT-SHAPE", {"detected_shape": _shape(out), "required_shape": _shape(q)}), False
        )
    if not _has_standard_storage(out) or not out.is_contiguous() or out.stride() != q.stride():
        return AttentionValidationResult(
            _error(
                contract,
                "KERNEL-OUTPUT-LAYOUT",
                {"detected_strides": list(out.stride()), "required_strides": list(q.stride())},
            ),
            False,
        )
    for name, value in tensors[:3]:
        if _ranges_overlap(value, out):
            return AttentionValidationResult(_error(contract, "KERNEL-OUTPUT-OVERLAP", {"input_tensor": name}), False)
    with torch.inference_mode():
        out.view(torch.int32).fill_(_UNWRITTEN_F32_BITS)
        dispatch(q, k, v, out)
    if (index := _first_unwritten(out)) is not None:
        return AttentionValidationResult(
            _error(contract, "KERNEL-INCOMPLETE-WRITE", {"first_unwritten_index": index}), True
        )
    return AttentionValidationResult(None, True)
