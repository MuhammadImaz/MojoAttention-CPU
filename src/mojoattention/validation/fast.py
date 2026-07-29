from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

Verdict = Literal["pass", "product-fail", "infrastructure-invalid", "contract-invalid"]


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(_canonical(value)).hexdigest()}"


@dataclass(frozen=True)
class FastError:
    code: str
    message: str
    context: Mapping[str, object]


@dataclass(frozen=True)
class FastCheck:
    validation_id: str
    case_id: str
    kind: Literal["foundation", "canary"]
    seed: int
    required_count: int
    expected_verdict: Verdict
    reproduction_argv: tuple[str, ...]


@dataclass(frozen=True)
class RunnerConfig:
    timeout_seconds: int
    max_output_bytes: int
    locale: str
    environment: tuple[str, ...]
    shard_index: int
    shard_total: int


@dataclass(frozen=True)
class FastManifest:
    schema_version: str
    suite_id: str
    manifest_digest: str
    config_digest: str
    seed: int
    required_total: int
    reference_target_ns: int
    runner_config: RunnerConfig
    checks: tuple[FastCheck, ...]


@dataclass(frozen=True)
class Observation:
    validation_id: str
    case_id: str
    seed: int
    selected: int
    collected: int
    completed: int
    skipped: int
    xfailed: int
    deselected: int
    collection_errors: int
    shard_index: int
    shard_total: int
    status: Literal["pass", "fail"]
    failure_class: Verdict = "product-fail"


def load_manifest(manifest_bytes: bytes, schema_bytes: bytes) -> FastManifest:
    try:
        schema = json.loads(schema_bytes)
        value = json.loads(manifest_bytes)
        Draft202012Validator.check_schema(schema)
        errors = tuple(Draft202012Validator(schema).iter_errors(value))
    except (json.JSONDecodeError, TypeError, SchemaError) as error:
        raise ValueError("Fast manifest or schema is invalid") from error
    if errors or not isinstance(value, dict):
        raise ValueError(f"Fast manifest is schema-invalid: {errors[0].message if errors else 'not an object'}")
    unsigned = dict(value)
    claimed_manifest = unsigned.pop("manifest_digest")
    if claimed_manifest != _digest(unsigned):
        raise ValueError("Fast manifest digest mismatch")
    config = value["runner_config"]
    if value["config_digest"] != _digest(config):
        raise ValueError("Fast runner configuration digest mismatch")
    shard = config["shard"]
    checks = tuple(
        FastCheck(
            validation_id=item["validation_id"],
            case_id=item["case_id"],
            kind=item["kind"],
            seed=item["seed"],
            required_count=item["required_count"],
            expected_verdict=item["expected_verdict"],
            reproduction_argv=tuple(item["reproduction_argv"]),
        )
        for item in value["checks"]
    )
    return FastManifest(
        schema_version=value["schema_version"],
        suite_id=value["suite_id"],
        manifest_digest=value["manifest_digest"],
        config_digest=value["config_digest"],
        seed=value["seed"],
        required_total=value["required_total"],
        reference_target_ns=value["reference_target_ns"],
        runner_config=RunnerConfig(
            timeout_seconds=config["timeout_seconds"],
            max_output_bytes=config["max_output_bytes"],
            locale=config["locale"],
            environment=tuple(config["environment"]),
            shard_index=shard["shard_index"],
            shard_total=shard["shard_total"],
        ),
        checks=checks,
    )


def _error(code: str, message: str, **context: object) -> FastError:
    return FastError(code, message, MappingProxyType(context))


def evaluate_observations(
    manifest: FastManifest,
    observations: tuple[Observation, ...],
) -> tuple[Verdict, tuple[FastError, ...]]:
    errors: list[FastError] = []
    expected_ids = tuple(item.validation_id for item in manifest.checks)
    actual_ids = tuple(item.validation_id for item in observations)
    if actual_ids != expected_ids:
        errors.append(_error("FAST-INV-001", "observed validation inventory differs from manifest"))
    if len(actual_ids) != len(set(actual_ids)) or len(actual_ids) != manifest.required_total:
        errors.append(_error("FAST-INV-002", "validation cardinality is incomplete or duplicated"))
    for index, check in enumerate(manifest.checks):
        if index >= len(observations):
            break
        observed = observations[index]
        expected_identity = (
            check.validation_id,
            check.case_id,
            check.seed,
            check.required_count,
            manifest.runner_config.shard_index,
            manifest.runner_config.shard_total,
        )
        actual_identity = (
            observed.validation_id,
            observed.case_id,
            observed.seed,
            observed.selected,
            observed.shard_index,
            observed.shard_total,
        )
        if actual_identity != expected_identity:
            errors.append(_error("FAST-INV-003", "validation identity, count, seed, or shard drifted", index=index))
        completion = (
            observed.collected,
            observed.completed,
            observed.skipped,
            observed.xfailed,
            observed.deselected,
            observed.collection_errors,
        )
        if completion != (1, 1, 0, 0, 0, 0):
            errors.append(_error("FAST-INV-004", "validation did not complete exactly once", index=index))
    if errors:
        return "contract-invalid", tuple(errors)
    failures = [item for item in observations if item.status == "fail"]
    if not failures:
        return "pass", ()
    priority: tuple[Verdict, ...] = ("contract-invalid", "infrastructure-invalid", "product-fail")
    verdict: Verdict = "product-fail"
    for candidate in priority:
        if any(failure.failure_class == candidate for failure in failures):
            verdict = candidate
            break
    return verdict, tuple(
        _error("FAST-RUN-001", "validation reported failure", validation_id=item.validation_id) for item in failures
    )
