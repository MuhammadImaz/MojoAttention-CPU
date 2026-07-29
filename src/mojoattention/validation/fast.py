from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from mojoattention.validation.evidence import canonical_bytes, digest_bytes

Verdict = Literal["pass", "product-fail", "infrastructure-invalid", "contract-invalid"]
FAST_PROTOCOL = {
    "schema_version": "1.0.0",
    "suite_id": "fast",
    "state_machine": (
        "declared",
        "selected",
        "started",
        "completed",
        "recorded",
        "evidence-closed",
    ),
}
FAST_PROTOCOL_DIGEST = digest_bytes(canonical_bytes(FAST_PROTOCOL))


@dataclass(frozen=True, slots=True)
class FastError:
    code: str
    message: str
    context: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class FastCheck:
    validation_id: str
    case_id: str
    kind: Literal["foundation", "canary"]
    seed: int
    required_count: int
    expected_verdict: Verdict
    reproduction_argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunnerConfig:
    timeout_seconds: int
    max_output_bytes: int
    locale: str
    environment: tuple[str, ...]
    shard_index: int
    shard_total: int


@dataclass(frozen=True, slots=True)
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


@dataclass(frozen=True, slots=True)
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


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    output_truncated: bool
    failure_class: Verdict | None = None
    error: FastError | None = None


@dataclass(frozen=True, slots=True)
class AdapterResult:
    observation: Observation
    errors: tuple[FastError, ...] = ()

    @classmethod
    def passed(cls, check: FastCheck) -> AdapterResult:
        return cls(_completed_observation(check, "pass", "product-fail"))

    @classmethod
    def failed(cls, check: FastCheck, failure_class: Verdict, error: FastError) -> AdapterResult:
        if failure_class == "pass":
            raise ValueError("a failed adapter result cannot use the pass verdict")
        return cls(_completed_observation(check, "fail", failure_class), (error,))


@dataclass(frozen=True, slots=True)
class FastRunResult:
    verdict: Verdict
    observations: tuple[Observation, ...]
    errors: tuple[FastError, ...]
    elapsed_ns: int
    elapsed_unit: Literal["nanoseconds"] = "nanoseconds"


CheckAdapter = Callable[[FastCheck], AdapterResult]


def evidence_validations(
    result: FastRunResult,
    reproduction_argv: Mapping[str, tuple[str, ...]],
    *,
    reference_target_ns: int | None = None,
) -> list[dict[str, Any]]:
    """Translate structured runner observations into the shared evidence interface."""

    validations: list[dict[str, Any]] = []
    for observation in result.observations:
        related = [
            error for error in result.errors if error.context.get("validation_id") in (None, observation.validation_id)
        ]
        if observation.status == "fail" and not related:
            related = [
                _error(
                    "FAST-RUN-001",
                    "validation reported failure",
                    validation_id=observation.validation_id,
                )
            ]
        validations.append(
            {
                "validation_id": observation.validation_id,
                "case_id": observation.case_id,
                "status": observation.status,
                "reproduction_argv": list(reproduction_argv[observation.validation_id]),
                "metrics": [
                    {
                        "name": "run-elapsed",
                        "value": result.elapsed_ns,
                        "value_type": "integer",
                        "unit": "nanoseconds",
                    },
                    {
                        "name": "seed",
                        "value": observation.seed,
                        "value_type": "integer",
                        "unit": "seed",
                    },
                    *(
                        [
                            {
                                "name": "reference-target",
                                "value": reference_target_ns,
                                "value_type": "integer",
                                "unit": "nanoseconds",
                            }
                        ]
                        if reference_target_ns is not None
                        else []
                    ),
                    *[
                        {
                            "name": name,
                            "value": value,
                            "value_type": "integer",
                            "unit": unit,
                        }
                        for name, value, unit in (
                            ("selected", observation.selected, "count"),
                            ("collected", observation.collected, "count"),
                            ("completed", observation.completed, "count"),
                            ("skipped", observation.skipped, "count"),
                            ("xfailed", observation.xfailed, "count"),
                            ("deselected", observation.deselected, "count"),
                            ("collection-errors", observation.collection_errors, "count"),
                            ("shard-index", observation.shard_index, "index"),
                            ("shard-total", observation.shard_total, "count"),
                        )
                    ],
                ],
                "errors": [
                    {"code": error.code, "message": error.message, "context": dict(error.context)} for error in related
                ]
                if observation.status == "fail"
                else [],
                "attachments": [],
            }
        )
    return validations


def verify_fast_evidence(
    manifest: FastManifest,
    result: FastRunResult,
    evidence: Mapping[str, Any],
) -> tuple[FastError, ...]:
    """Bind an independently verified evidence root back to the authenticated run."""

    verdict, inventory_errors = evaluate_observations(manifest, result.observations)
    expected = evidence_validations(
        result,
        {check.validation_id: check.reproduction_argv for check in manifest.checks},
        reference_target_ns=manifest.reference_target_ns,
    )
    expected.sort(key=lambda item: item["validation_id"])
    exact = (
        verdict == result.verdict
        and (result.verdict != "pass" or not result.errors)
        and evidence.get("verdict") == result.verdict
        and evidence.get("seed") == manifest.seed
        and evidence.get("declared_validation_ids") == [check.validation_id for check in manifest.checks]
        and evidence.get("declared_case_ids") == [check.case_id for check in manifest.checks]
        and evidence.get("validations") == expected
    )
    if inventory_errors or not exact:
        return (_error("FAST-EVID-001", "published evidence differs from authenticated Fast completion"),)
    return ()


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
    if claimed_manifest != digest_bytes(canonical_bytes(unsigned)):
        raise ValueError("Fast manifest digest mismatch")
    config = value["runner_config"]
    if value["config_digest"] != digest_bytes(canonical_bytes(config)):
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


def _completed_observation(check: FastCheck, status: Literal["pass", "fail"], failure_class: Verdict) -> Observation:
    return Observation(
        validation_id=check.validation_id,
        case_id=check.case_id,
        seed=check.seed,
        selected=check.required_count,
        collected=check.required_count,
        completed=check.required_count,
        skipped=0,
        xfailed=0,
        deselected=0,
        collection_errors=0,
        shard_index=0,
        shard_total=1,
        status=status,
        failure_class=failure_class,
    )


def _reject_recursive_or_unbounded(argv: tuple[str, ...]) -> None:
    normalized = tuple(part.rstrip("/") for part in argv)
    if not normalized:
        raise ValueError("subprocess argv must not be empty")
    if normalized[0].endswith("quality.sh"):
        raise ValueError("Fast cannot invoke the complete quality script")
    if "pytest" in normalized:
        pytest_index = normalized.index("pytest")
        selections = tuple(part for part in normalized[pytest_index + 1 :] if not part.startswith("-"))
        if not selections or any(item == "tests" for item in selections):
            raise ValueError("Fast pytest execution requires focused bounded selections")
    if "validate" in normalized and "--suite" in normalized:
        suite_index = normalized.index("--suite")
        if suite_index + 1 < len(normalized) and normalized[suite_index + 1] == "fast":
            raise ValueError("recursive Fast execution is forbidden")


def run_bounded_argv(argv: tuple[str, ...], cwd: Path, config: RunnerConfig) -> ProcessResult:
    _reject_recursive_or_unbounded(argv)
    environment = {name: os.environ[name] for name in config.environment if name in os.environ}
    environment["LC_ALL"] = config.locale
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=environment,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=config.timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        error = _error("FAST-EXEC-001", "required executable is unavailable", executable=argv[0])
        return ProcessResult(None, b"", b"", False, "infrastructure-invalid", error)
    except subprocess.TimeoutExpired:
        error = _error("FAST-EXEC-002", "bounded subprocess timed out", timeout_seconds=config.timeout_seconds)
        return ProcessResult(None, b"", b"", False, "infrastructure-invalid", error)
    except OSError:
        error = _error("FAST-EXEC-003", "bounded subprocess could not execute")
        return ProcessResult(None, b"", b"", False, "infrastructure-invalid", error)
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    limit = config.max_output_bytes
    truncated = len(stdout) > limit or len(stderr) > limit
    if completed.returncode != 0:
        error = _error(
            "FAST-EXEC-004",
            "bounded subprocess returned a nonzero exit",
            returncode=completed.returncode,
        )
        return ProcessResult(
            completed.returncode,
            stdout[:limit],
            stderr[:limit],
            truncated,
            "product-fail",
            error,
        )
    return ProcessResult(completed.returncode, stdout[:limit], stderr[:limit], truncated)


def execute_checks(
    manifest: FastManifest,
    adapters: Mapping[str, CheckAdapter],
    *,
    clock: Callable[[], int] = time.monotonic_ns,
) -> FastRunResult:
    started = clock()
    observations: list[Observation] = []
    adapter_errors: list[FastError] = []
    for check in manifest.checks:
        adapter = adapters.get(check.validation_id)
        if adapter is None:
            adapter_errors.append(
                _error("FAST-ADAPTER-001", "required validation adapter is missing", validation_id=check.validation_id)
            )
            observations.append(_completed_observation(check, "fail", "contract-invalid"))
            continue
        try:
            result = adapter(check)
        except Exception:
            adapter_errors.append(
                _error(
                    "FAST-ADAPTER-002",
                    "validation adapter failed to produce a structured result",
                    validation_id=check.validation_id,
                )
            )
            observations.append(_completed_observation(check, "fail", "infrastructure-invalid"))
            continue
        observations.append(result.observation)
        adapter_errors.extend(result.errors)
    elapsed_ns = max(0, clock() - started)
    verdict, inventory_errors = evaluate_observations(manifest, tuple(observations))
    errors = (*adapter_errors, *inventory_errors)
    if any(error.code == "FAST-ADAPTER-001" for error in adapter_errors):
        verdict = "contract-invalid"
    elif any(error.code == "FAST-ADAPTER-002" for error in adapter_errors) and verdict != "contract-invalid":
        verdict = "infrastructure-invalid"
    return FastRunResult(verdict, tuple(observations), tuple(errors), elapsed_ns)


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
