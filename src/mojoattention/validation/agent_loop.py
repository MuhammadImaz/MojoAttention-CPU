from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from mojoattention.validation.authority import authorize_write
from mojoattention.validation.paths import contains

SchemaSource = Path | bytes
LoopStatus = Literal[
    "awaiting-validation",
    "validation-failed",
    "retry-authorized",
    "awaiting-human-review",
    "stopped",
]
StopReason = Literal[
    "causality",
    "nonfinite",
    "unsupported-input",
    "unexpected-fallback",
    "missing-routing",
    "nondeterminism",
    "scope-expansion",
    "protected-conflict",
    "validation-weakening",
    "non-improving-retry",
    "retry-budget-exhausted",
    "human-escalation",
]

SEMANTIC_STOP_FAILURES: Mapping[str, StopReason] = {
    "causality": "causality",
    "nonfinite": "nonfinite",
    "unsupported-input": "unsupported-input",
    "unexpected-fallback": "unexpected-fallback",
    "missing-routing": "missing-routing",
    "nondeterminism": "nondeterminism",
    "scope-expansion": "scope-expansion",
    "protected-conflict": "protected-conflict",
    "validation-weakening": "validation-weakening",
    "non-improving-retry": "non-improving-retry",
}
HUMAN_ESCALATION_FAILURES: tuple[str, ...] = (
    "protected-authorization-conflict",
    "contract-invalid",
    "authenticated-controls-unavailable",
    "toolchain-incompatibility",
    "stable-runner-only-failure",
    "unexplained-flakiness",
)


@dataclass(frozen=True)
class AgentLoopError:
    code: str
    message: str
    context: dict[str, object]


@dataclass(frozen=True)
class Diagnosis:
    validation_id: str
    verdict: str
    error_code: str
    failure_signature: str
    evidence_digest: str
    affected_paths: tuple[str, ...]
    reproduction_argv: tuple[str, ...]


@dataclass(frozen=True)
class Improvement:
    validation_id: str
    case_id: str
    config_digest: str
    metric_name: str
    direction: str
    before: int
    after: int


@dataclass(frozen=True)
class EvidenceBinding:
    run_id: str
    evidence_digest: str
    source_revision: str
    source_tree: str
    contract_digest: str
    lifecycle: str
    independently_verified: bool
    verdict: str
    validation_ids: tuple[str, ...]


@dataclass(frozen=True)
class ControlBinding:
    contract_digest: str
    source_revision: str
    source_tree: str
    trusted_base_revision: str
    trusted_base_tree: str
    assigned_role: str
    allowed_paths: tuple[str, ...]
    protected_paths: tuple[str, ...]


@dataclass(frozen=True)
class LoopHeader:
    schema_version: str
    loop_id: str
    contract_digest: str
    source_revision: str
    source_tree: str
    trusted_base_revision: str
    trusted_base_tree: str
    assigned_role: str
    retry_budget: int
    allowed_paths: tuple[str, ...]
    protected_paths: tuple[str, ...]
    created_at: str
    header_digest: str


@dataclass(frozen=True)
class LoopEvent:
    schema_version: str
    loop_id: str
    sequence: int
    prior_event_digest: str
    event_digest: str
    attempt: int
    transition: str
    status: LoopStatus
    control_binding: ControlBinding
    validation_id: str | None
    evidence_bindings: tuple[EvidenceBinding, ...]
    diagnosis: Diagnosis | None
    improvement: Improvement | None
    stop_reason: StopReason | None
    actor_kind: str
    timestamp: str


@dataclass(frozen=True)
class LoopState:
    header: LoopHeader
    events: tuple[LoopEvent, ...]
    status: LoopStatus
    attempt: int
    retries_consumed: int
    last_validation: str | None
    evidence_run_id: str | None
    terminal: bool
    errors: tuple[AgentLoopError, ...] = ()


@dataclass(frozen=True)
class ValidationObservation:
    validation_id: str
    case_id: str
    config_digest: str
    status: str
    metric_name: str | None
    direction: str | None
    value: int | None


@dataclass(frozen=True)
class RepairRequest:
    diagnosis: Diagnosis
    improvement: Improvement
    repair_paths: tuple[str, ...]
    previous_observations: tuple[ValidationObservation, ...]
    current_observations: tuple[ValidationObservation, ...]
    operation: str
    actor_kind: str
    requests_approval: bool
    infrastructure_identity_before: str | None
    infrastructure_identity_after: str | None
    semantic_state_before: str | None
    semantic_state_after: str | None
    previous_failure_signatures: tuple[str, ...] = ()
    failure_kind: str | None = None


@dataclass(frozen=True)
class RetryDecision:
    allowed: bool
    stop_reason: StopReason | None
    errors: tuple[AgentLoopError, ...]


class AgentLoopContractError(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def digest_record(record: dict[str, Any], own_digest_field: str) -> str:
    payload = {key: value for key, value in record.items() if key != own_digest_field}
    return f"sha256:{hashlib.sha256(canonical_bytes(payload)).hexdigest()}"


def seal_header(header: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(header)
    sealed["header_digest"] = digest_record(sealed, "header_digest")
    return sealed


def seal_event(event: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(event)
    sealed["event_digest"] = digest_record(sealed, "event_digest")
    return sealed


def _load_schema(source: SchemaSource) -> dict[str, Any]:
    raw = source if isinstance(source, bytes) else source.read_bytes()
    schema = json.loads(raw)
    if not isinstance(schema, dict):
        raise ValueError("agent loop schema must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


def validate_agent_loop_record(record: object, schema_source: SchemaSource) -> tuple[AgentLoopError, ...]:
    validator = Draft202012Validator(_load_schema(schema_source), format_checker=FormatChecker())
    errors: list[AgentLoopError] = []
    for error in sorted(validator.iter_errors(record), key=lambda item: tuple(str(part) for part in item.path)):
        errors.append(
            AgentLoopError(
                "LOOP-001",
                "agent loop record is invalid",
                {
                    "path": "/".join(str(part) for part in error.absolute_path),
                    "validator": str(error.validator),
                },
            )
        )
    return tuple(errors)


def _reject(code: str, message: str, **context: object) -> None:
    error = AgentLoopError(code, message, context)
    raise AgentLoopContractError(
        f"{error.code}: {error.message}: " + json.dumps(error.context, sort_keys=True, separators=(",", ":"))
    )


def classify_stop_reason(failure: str) -> StopReason | None:
    if failure in SEMANTIC_STOP_FAILURES:
        return SEMANTIC_STOP_FAILURES[failure]
    if failure in HUMAN_ESCALATION_FAILURES:
        return "human-escalation"
    return None


def _decision_error(code: str, message: str, reason: StopReason, **context: object) -> RetryDecision:
    return RetryDecision(False, reason, (AgentLoopError(code, message, context),))


def _observation_map(
    observations: tuple[ValidationObservation, ...],
) -> dict[tuple[str, str, str], ValidationObservation] | None:
    mapped: dict[tuple[str, str, str], ValidationObservation] = {}
    for observation in observations:
        key = (observation.validation_id, observation.case_id, observation.config_digest)
        if key in mapped:
            return None
        mapped[key] = observation
    return mapped


def _objective_improvement(request: RepairRequest) -> bool:
    previous = _observation_map(request.previous_observations)
    current = _observation_map(request.current_observations)
    if previous is None or current is None:
        return False
    if any(
        current.get(identity) is None or (before.status != "fail" and current[identity].status == "fail")
        for identity, before in previous.items()
    ):
        return False
    if any(observation.status == "fail" and identity not in previous for identity, observation in current.items()):
        return False
    proof = request.improvement
    identity = (proof.validation_id, proof.case_id, proof.config_digest)
    before = previous.get(identity)
    after = current.get(identity)
    if before is None or after is None:
        return False
    if before.status == "fail" and after.status == "pass":
        return True
    if (
        before.metric_name != proof.metric_name
        or after.metric_name != proof.metric_name
        or before.direction != proof.direction
        or after.direction != proof.direction
        or before.value != proof.before
        or after.value != proof.after
        or proof.direction not in {"increase", "decrease"}
    ):
        return False
    return proof.after > proof.before if proof.direction == "increase" else proof.after < proof.before


def evaluate_retry(
    state: LoopState,
    request: RepairRequest,
    authority_manifest: dict[str, Any],
    root: Path,
) -> RetryDecision:
    if state.terminal:
        return _decision_error("LOOP-201", "terminal loop cannot authorize repair", "human-escalation")
    if state.status != "validation-failed" or state.last_validation is None:
        return _decision_error("LOOP-202", "retry requires a failed validation state", "human-escalation")
    if state.retries_consumed >= state.header.retry_budget or state.attempt >= 5:
        return _decision_error("LOOP-203", "retry budget is exhausted", "retry-budget-exhausted")
    diagnosis = request.diagnosis
    prior = state.events[-1]
    prior_evidence = prior.evidence_bindings
    if (
        prior.transition != "validation-recorded"
        or prior.validation_id != diagnosis.validation_id
        or len(prior_evidence) != 1
        or prior_evidence[0].evidence_digest != diagnosis.evidence_digest
        or diagnosis.verdict != prior_evidence[0].verdict
        or not re.fullmatch(r"(?:LOOP|FAST)-[0-9]{3}", diagnosis.error_code)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", diagnosis.failure_signature)
        or not diagnosis.affected_paths
        or not diagnosis.reproduction_argv
        or len(diagnosis.reproduction_argv) > 64
    ):
        return _decision_error("LOOP-204", "diagnosis does not bind the failed validation", "human-escalation")
    if diagnosis.failure_signature in request.previous_failure_signatures:
        return _decision_error("LOOP-205", "failure signature was already attempted", "non-improving-retry")
    mandatory_stop = classify_stop_reason(request.failure_kind) if request.failure_kind is not None else None
    if mandatory_stop is not None:
        return _decision_error("LOOP-206", "failure kind forbids automated retry", mandatory_stop)
    if diagnosis.verdict == "contract-invalid":
        return _decision_error("LOOP-207", "contract invalidity requires a newly approved loop", "human-escalation")
    if request.requests_approval or request.actor_kind != "agent":
        return _decision_error("LOOP-208", "automated repair cannot approve protected work", "protected-conflict")
    if tuple(diagnosis.affected_paths) != request.repair_paths:
        return _decision_error("LOOP-209", "repair paths differ from diagnosed paths", "scope-expansion")
    role = next(
        (item for item in authority_manifest["roles"] if item["id"] == state.header.assigned_role),
        None,
    )
    for path in request.repair_paths:
        if role is not None and any(contains(scope, path) for scope in role["indirect_output_paths"]):
            return _decision_error(
                "LOOP-210",
                "indirect outputs cannot be implementation repair targets",
                "scope-expansion",
                path=path,
            )
        authority_error = authorize_write(
            authority_manifest,
            state.header.assigned_role,
            request.operation,
            path,
            state.header.allowed_paths,
            root=root,
        )
        if authority_error is not None:
            reason: StopReason = (
                "protected-conflict"
                if authority_error.code in {"AUTH-004", "AUTH-006", "AUTH-009"} or path in state.header.protected_paths
                else "scope-expansion"
            )
            return _decision_error(
                "LOOP-210",
                "repair is outside effective contract and role authority",
                reason,
                authority_code=authority_error.code,
                path=path,
            )
    if diagnosis.verdict == "infrastructure-invalid" and (
        request.infrastructure_identity_before is None
        or request.infrastructure_identity_after is None
        or request.infrastructure_identity_before == request.infrastructure_identity_after
        or request.semantic_state_before is None
        or request.semantic_state_before != request.semantic_state_after
    ):
        return _decision_error(
            "LOOP-211",
            "infrastructure repair lacks changed infrastructure and stable semantic identity",
            "human-escalation",
        )
    if not _objective_improvement(request):
        return _decision_error("LOOP-212", "repair has no comparable objective improvement", "non-improving-retry")
    return RetryDecision(True, None, ())


def _header(record: dict[str, Any]) -> LoopHeader:
    return LoopHeader(
        schema_version=record["schema_version"],
        loop_id=record["loop_id"],
        contract_digest=record["contract_digest"],
        source_revision=record["source_revision"],
        source_tree=record["source_tree"],
        trusted_base_revision=record["trusted_base_revision"],
        trusted_base_tree=record["trusted_base_tree"],
        assigned_role=record["assigned_role"],
        retry_budget=record["retry_budget"],
        allowed_paths=tuple(record["allowed_paths"]),
        protected_paths=tuple(record["protected_paths"]),
        created_at=record["created_at"],
        header_digest=record["header_digest"],
    )


def _diagnosis(value: dict[str, Any] | None) -> Diagnosis | None:
    if value is None:
        return None
    return Diagnosis(
        validation_id=value["validation_id"],
        verdict=value["verdict"],
        error_code=value["error_code"],
        failure_signature=value["failure_signature"],
        evidence_digest=value["evidence_digest"],
        affected_paths=tuple(value["affected_paths"]),
        reproduction_argv=tuple(value["reproduction_argv"]),
    )


def _improvement(value: dict[str, Any] | None) -> Improvement | None:
    if value is None:
        return None
    metric = value["metric"]
    return Improvement(
        validation_id=value["validation_id"],
        case_id=value["case_id"],
        config_digest=value["config_digest"],
        metric_name=metric["name"],
        direction=metric["direction"],
        before=metric["before"],
        after=metric["after"],
    )


def _evidence(value: dict[str, Any]) -> EvidenceBinding:
    return EvidenceBinding(
        run_id=value["run_id"],
        evidence_digest=value["evidence_digest"],
        source_revision=value["source_revision"],
        source_tree=value["source_tree"],
        contract_digest=value["contract_digest"],
        lifecycle=value["lifecycle"],
        independently_verified=value["independently_verified"],
        verdict=value["verdict"],
        validation_ids=tuple(value["validation_ids"]),
    )


def _event(record: dict[str, Any]) -> LoopEvent:
    validation = record["validation_binding"]
    controls = record["control_binding"]
    return LoopEvent(
        schema_version=record["schema_version"],
        loop_id=record["loop_id"],
        sequence=record["sequence"],
        prior_event_digest=record["prior_event_digest"],
        event_digest=record["event_digest"],
        attempt=record["attempt"],
        transition=record["transition"],
        status=cast(LoopStatus, record["status"]),
        control_binding=ControlBinding(
            contract_digest=controls["contract_digest"],
            source_revision=controls["source_revision"],
            source_tree=controls["source_tree"],
            trusted_base_revision=controls["trusted_base_revision"],
            trusted_base_tree=controls["trusted_base_tree"],
            assigned_role=controls["assigned_role"],
            allowed_paths=tuple(controls["allowed_paths"]),
            protected_paths=tuple(controls["protected_paths"]),
        ),
        validation_id=None if validation is None else validation["validation_id"],
        evidence_bindings=tuple(_evidence(value) for value in record["evidence_bindings"]),
        diagnosis=_diagnosis(record["diagnosis"]),
        improvement=_improvement(record["improvement_proof"]),
        stop_reason=cast(StopReason | None, record["stop_reason"]),
        actor_kind=record["actor_kind"],
        timestamp=record["timestamp"],
    )


_ALLOWED_TRANSITIONS: Mapping[str | None, frozenset[tuple[str, str]]] = {
    None: frozenset({("initialized", "awaiting-validation")}),
    "awaiting-validation": frozenset(
        {
            ("validation-recorded", "validation-failed"),
            ("awaiting-human-review", "awaiting-human-review"),
            ("stopped", "stopped"),
        }
    ),
    "validation-failed": frozenset(
        {
            ("retry-authorized", "retry-authorized"),
            ("stopped", "stopped"),
        }
    ),
    "retry-authorized": frozenset(
        {
            ("validation-recorded", "validation-failed"),
            ("awaiting-human-review", "awaiting-human-review"),
            ("stopped", "stopped"),
        }
    ),
}
_TERMINAL = frozenset({"awaiting-human-review", "stopped"})


def _expected_controls(header: LoopHeader) -> dict[str, object]:
    return {
        "contract_digest": header.contract_digest,
        "source_revision": header.source_revision,
        "source_tree": header.source_tree,
        "trusted_base_revision": header.trusted_base_revision,
        "trusted_base_tree": header.trusted_base_tree,
        "assigned_role": header.assigned_role,
        "allowed_paths": list(header.allowed_paths),
        "protected_paths": list(header.protected_paths),
    }


def replay_journal(
    header_record: dict[str, Any],
    event_records: list[dict[str, Any]],
    schema_source: SchemaSource,
) -> LoopState:
    if validate_agent_loop_record(header_record, schema_source):
        _reject("LOOP-001", "agent loop header is invalid")
    if digest_record(header_record, "header_digest") != header_record["header_digest"]:
        _reject("LOOP-002", "agent loop header digest does not match")
    header = _header(header_record)
    prior = header.header_digest
    retries_consumed = 0
    last_validation: str | None = None
    evidence_run_id: str | None = None
    status: str | None = None
    attempt = 1
    events: list[LoopEvent] = []
    seen_event_digests: set[str] = set()
    seen_evidence: set[tuple[str, str]] = set()
    for expected_sequence, record in enumerate(event_records, start=1):
        if validate_agent_loop_record(record, schema_source):
            _reject("LOOP-001", "agent loop event is invalid", sequence=expected_sequence)
        if digest_record(record, "event_digest") != record["event_digest"]:
            _reject("LOOP-003", "agent loop event digest does not match", sequence=expected_sequence)
        if record["event_digest"] in seen_event_digests:
            _reject("LOOP-004", "agent loop event is duplicated", sequence=expected_sequence)
        if record["sequence"] != expected_sequence:
            _reject(
                "LOOP-004",
                "agent loop event sequence is not contiguous",
                expected=expected_sequence,
                actual=record["sequence"],
            )
        if record["prior_event_digest"] != prior:
            _reject("LOOP-005", "agent loop event prior digest does not match", sequence=expected_sequence)
        if record["loop_id"] != header.loop_id:
            _reject("LOOP-006", "agent loop event belongs to another loop", sequence=expected_sequence)
        if record["control_binding"] != _expected_controls(header):
            _reject("LOOP-012", "agent loop event control binding changed", sequence=expected_sequence)
        if status in _TERMINAL:
            _reject("LOOP-011", "terminal agent loop history cannot be extended", sequence=expected_sequence)
        transition = (record["transition"], record["status"])
        if transition not in _ALLOWED_TRANSITIONS.get(status, frozenset()):
            _reject("LOOP-010", "agent loop transition is not allowed", sequence=expected_sequence)
        if record["transition"] == "retry-authorized":
            retries_consumed += 1
            if record["attempt"] != attempt + 1:
                _reject("LOOP-007", "retry must increment the attempt exactly once", sequence=expected_sequence)
            if retries_consumed > header.retry_budget:
                _reject("LOOP-008", "retry budget is exhausted", sequence=expected_sequence)
        elif record["attempt"] != attempt:
            _reject("LOOP-007", "non-retry event changed the attempt", sequence=expected_sequence)
        bindings = record["evidence_bindings"]
        if record["transition"] in {"validation-recorded", "awaiting-human-review"} and len(bindings) != 1:
            _reject(
                "LOOP-013", "validation transition requires one complete evidence identity", sequence=expected_sequence
            )
        for binding in bindings:
            identity = (binding["run_id"], binding["evidence_digest"])
            if identity in seen_evidence:
                _reject("LOOP-013", "evidence identity is duplicated", sequence=expected_sequence)
            if (
                binding["source_revision"] != header.source_revision
                or binding["source_tree"] != header.source_tree
                or binding["contract_digest"] != header.contract_digest
            ):
                _reject(
                    "LOOP-013", "evidence identity conflicts with immutable loop controls", sequence=expected_sequence
                )
            evidence_run_id = binding["run_id"]
            seen_evidence.add(identity)
        if record["transition"] == "validation-recorded":
            validation = record["validation_binding"]
            if validation is None or validation["validation_id"] not in bindings[0]["validation_ids"]:
                _reject("LOOP-013", "validation identity is absent from evidence", sequence=expected_sequence)
            expected_status = {
                "pass": "pass",
                "product-fail": "fail",
                "infrastructure-invalid": "invalid",
                "contract-invalid": "invalid",
            }[bindings[0]["verdict"]]
            if validation["status"] != expected_status:
                _reject("LOOP-013", "validation verdict conflicts with evidence", sequence=expected_sequence)
            last_validation = record["event_digest"]
        if record["transition"] == "awaiting-human-review":
            validation = record["validation_binding"]
            if validation is None or validation["status"] != "pass" or bindings[0]["verdict"] != "pass":
                _reject("LOOP-013", "human review requires passing evidence", sequence=expected_sequence)
        if record["transition"] == "stopped" and record["stop_reason"] is None:
            _reject("LOOP-014", "terminal stop requires a typed reason", sequence=expected_sequence)
        if record["transition"] != "stopped" and record["stop_reason"] is not None:
            _reject("LOOP-014", "non-stop transition cannot record a stop reason", sequence=expected_sequence)
        attempt = record["attempt"]
        status = record["status"]
        prior = record["event_digest"]
        seen_event_digests.add(prior)
        events.append(_event(record))
    if status is None:
        _reject("LOOP-009", "agent loop journal has no events")
    return LoopState(
        header=header,
        events=tuple(events),
        status=cast(LoopStatus, status),
        attempt=attempt,
        retries_consumed=retries_consumed,
        last_validation=last_validation,
        evidence_run_id=evidence_run_id,
        terminal=status in _TERMINAL,
    )


def derive_journal_state(
    header: dict[str, Any],
    events: list[dict[str, Any]],
    schema_source: SchemaSource,
) -> dict[str, Any]:
    state = replay_journal(header, events, schema_source)
    last_validation = next(
        (record for record in reversed(events) if record["event_digest"] == state.last_validation),
        None,
    )
    return {
        "status": state.status,
        "attempt": state.attempt,
        "retries_consumed": state.retries_consumed,
        "last_validation": last_validation,
    }


_LOOP_ID = re.compile(r"^[0-9a-f]{32}$")
_EVENT_FILE = re.compile(r"^([0-9]{8})\.json$")
_MAX_RECORD_BYTES = 16 * 1024 * 1024


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _object_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode)


def _open_directory_at(parent_fd: int, name: str, *, create: bool = False) -> int:
    if "/" in name or name in {"", ".", ".."}:
        _reject("LOOP-304", "journal directory component is unsafe", component=name)
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as error:
        _reject("LOOP-304", "journal directory boundary is unavailable or unsafe", component=name, error=str(error))
    value = os.fstat(descriptor)
    if not stat.S_ISDIR(value.st_mode) or value.st_nlink < 2:
        os.close(descriptor)
        _reject("LOOP-304", "journal boundary is not a directory", component=name)
    return descriptor


def _read_regular_at(parent_fd: int, name: str) -> bytes:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as error:
        _reject("LOOP-305", "journal record cannot be opened safely", record=name, error=str(error))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _reject("LOOP-305", "journal record must be a single-link regular file", record=name)
        chunks: list[bytes] = []
        total = 0
        while block := os.read(descriptor, 1024 * 1024):
            total += len(block)
            if total > _MAX_RECORD_BYTES:
                _reject("LOOP-305", "journal record exceeds size limit", record=name)
            chunks.append(block)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            _reject("LOOP-305", "journal record changed while being read", record=name)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_exclusive_at(parent_fd: int, name: str, payload: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short journal write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _rename_noreplace_at(parent_fd: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError:
        _reject("LOOP-306", "atomic no-replace publication is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), 1) != 0:
        error_number = ctypes.get_errno()
        _reject(
            "LOOP-302",
            "journal publication target already exists or cannot be sealed",
            target=target,
            error=os.strerror(error_number),
        )


def _remove_owned_stage(parent_fd: int, name: str) -> None:
    try:
        stage_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for child in os.listdir(stage_fd):
            value = os.stat(child, dir_fd=stage_fd, follow_symlinks=False)
            if stat.S_ISDIR(value.st_mode):
                child_fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
                try:
                    for leaf in os.listdir(child_fd):
                        os.unlink(leaf, dir_fd=child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(child, dir_fd=stage_fd)
            else:
                os.unlink(child, dir_fd=stage_fd)
    finally:
        os.close(stage_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


class AgentLoopJournal:
    def __init__(self, project_root: Path, schema_source: SchemaSource) -> None:
        if not project_root.is_absolute():
            _reject("LOOP-304", "project root must be absolute")
        try:
            descriptor = os.open(project_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            _reject("LOOP-304", "project root is unavailable or unsafe", error=str(error))
        self._project_fd = descriptor
        self._schema_source = schema_source

    def __del__(self) -> None:
        descriptor = getattr(self, "_project_fd", -1)
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
            self._project_fd = -1

    def _loops_fd(self, *, create: bool) -> int:
        reports_fd = _open_directory_at(self._project_fd, "reports", create=create)
        try:
            return _open_directory_at(reports_fd, "agent-loops", create=create)
        finally:
            os.close(reports_fd)

    def start(self, immutable_metadata: dict[str, Any]) -> LoopState:
        forbidden = {"record_type", "loop_id", "header_digest"}
        supplied = sorted(forbidden.intersection(immutable_metadata))
        if supplied:
            _reject("LOOP-301", "caller supplied internally generated header fields", fields=supplied)
        loops_fd = self._loops_fd(create=True)
        loop_id = secrets.token_hex(16)
        owner_token = secrets.token_hex(16)
        stage_name = f".loop.{loop_id}.{owner_token}.tmp"
        stage_created = False
        try:
            os.mkdir(stage_name, mode=0o700, dir_fd=loops_fd)
            stage_created = True
            stage_fd = _open_directory_at(loops_fd, stage_name)
            try:
                events_fd = _open_directory_at(stage_fd, "events", create=True)
                try:
                    header = seal_header(
                        {
                            **immutable_metadata,
                            "record_type": "header",
                            "loop_id": loop_id,
                        }
                    )
                    controls = {
                        key: header[key]
                        for key in (
                            "contract_digest",
                            "source_revision",
                            "source_tree",
                            "trusted_base_revision",
                            "trusted_base_tree",
                            "assigned_role",
                            "allowed_paths",
                            "protected_paths",
                        )
                    }
                    genesis = seal_event(
                        {
                            "record_type": "event",
                            "schema_version": header["schema_version"],
                            "loop_id": loop_id,
                            "sequence": 1,
                            "prior_event_digest": header["header_digest"],
                            "attempt": 1,
                            "control_binding": controls,
                            "transition": "initialized",
                            "status": "awaiting-validation",
                            "validation_binding": None,
                            "evidence_bindings": [],
                            "diagnosis": None,
                            "improvement_proof": None,
                            "stop_reason": None,
                            "actor_kind": "system",
                            "timestamp": header["created_at"],
                        }
                    )
                    replay_journal(header, [genesis], self._schema_source)
                    _write_exclusive_at(stage_fd, "header.json", canonical_bytes(header) + b"\n")
                    _write_exclusive_at(events_fd, "00000001.json", canonical_bytes(genesis) + b"\n")
                    _write_exclusive_at(stage_fd, ".writer.lock", b"")
                    os.fsync(events_fd)
                finally:
                    os.close(events_fd)
                os.fsync(stage_fd)
            finally:
                os.close(stage_fd)
            _rename_noreplace_at(loops_fd, stage_name, loop_id)
            os.fsync(loops_fd)
        except BaseException:
            if stage_created:
                _remove_owned_stage(loops_fd, stage_name)
            raise
        finally:
            os.close(loops_fd)
        return self.inspect(loop_id)

    def _open_loop(self, loop_id: str) -> tuple[int, int]:
        if not _LOOP_ID.fullmatch(loop_id):
            _reject("LOOP-304", "loop identity is malformed")
        loops_fd = self._loops_fd(create=False)
        try:
            loop_fd = _open_directory_at(loops_fd, loop_id)
        finally:
            os.close(loops_fd)
        events_fd = _open_directory_at(loop_fd, "events")
        return loop_fd, events_fd

    def _read_chain(self, loop_fd: int, events_fd: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        loop_before = _identity(os.fstat(loop_fd))
        events_before = _identity(os.fstat(events_fd))
        try:
            header = json.loads(_read_regular_at(loop_fd, "header.json"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            _reject("LOOP-305", "journal header is malformed", error=str(error))
        records: list[dict[str, Any]] = []
        event_names: list[tuple[int, str]] = []
        for name in os.listdir(events_fd):
            match = _EVENT_FILE.fullmatch(name)
            if match is not None:
                event_names.append((int(match.group(1)), name))
            elif not (name.startswith(".event.") and name.endswith(".tmp")):
                _reject("LOOP-305", "journal event directory contains an unknown record", record=name)
        for expected, (number, name) in enumerate(sorted(event_names), start=1):
            if number != expected:
                _reject("LOOP-004", "journal event filenames are not contiguous", expected=expected, actual=number)
            try:
                value = json.loads(_read_regular_at(events_fd, name))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                _reject("LOOP-305", "journal event is malformed", record=name, error=str(error))
            if not isinstance(value, dict):
                _reject("LOOP-305", "journal event must be an object", record=name)
            records.append(value)
        if _identity(os.fstat(loop_fd)) != loop_before or _identity(os.fstat(events_fd)) != events_before:
            _reject("LOOP-307", "journal parent changed while being read")
        if not isinstance(header, dict):
            _reject("LOOP-305", "journal header must be an object")
        return header, records

    def inspect(self, loop_id: str) -> LoopState:
        loop_fd, events_fd = self._open_loop(loop_id)
        try:
            header, records = self._read_chain(loop_fd, events_fd)
            return replay_journal(header, records, self._schema_source)
        finally:
            os.close(events_fd)
            os.close(loop_fd)

    def _assert_published_identity(self, loop_id: str, expected: tuple[int, int, int]) -> None:
        loops_fd = self._loops_fd(create=False)
        try:
            reopened = _open_directory_at(loops_fd, loop_id)
            try:
                if _object_identity(os.fstat(reopened)) != expected:
                    _reject("LOOP-307", "published journal identity changed")
            finally:
                os.close(reopened)
        finally:
            os.close(loops_fd)

    def append(self, loop_id: str, event_fields: dict[str, Any]) -> LoopState:
        forbidden = {"loop_id", "sequence", "prior_event_digest", "event_digest"}
        supplied = sorted(forbidden.intersection(event_fields))
        if supplied:
            _reject("LOOP-301", "caller supplied internally generated event fields", fields=supplied)
        loop_fd, events_fd = self._open_loop(loop_id)
        lock_fd = -1
        owned_temp: str | None = None
        try:
            lock_fd = os.open(".writer.lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=loop_fd)
            lock_stat = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1:
                _reject("LOOP-305", "journal writer lock is unsafe")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _reject("LOOP-303", "another writer owns this loop")
            loop_identity = _object_identity(os.fstat(loop_fd))
            events_identity = _object_identity(os.fstat(events_fd))
            self._assert_published_identity(loop_id, loop_identity)
            header, records = self._read_chain(loop_fd, events_fd)
            state = replay_journal(header, records, self._schema_source)
            prior = state.events[-1].event_digest
            event = seal_event(
                {
                    **event_fields,
                    "loop_id": loop_id,
                    "sequence": len(records) + 1,
                    "prior_event_digest": prior,
                }
            )
            replay_journal(header, [*records, event], self._schema_source)
            if (
                _object_identity(os.fstat(loop_fd)) != loop_identity
                or _object_identity(os.fstat(events_fd)) != events_identity
            ):
                _reject("LOOP-307", "journal parent identity changed before append")
            owner_token = secrets.token_hex(16)
            temp_name = f".event.{owner_token}.tmp"
            _write_exclusive_at(events_fd, temp_name, canonical_bytes(event) + b"\n")
            owned_temp = temp_name
            final_name = f"{event['sequence']:08d}.json"
            _rename_noreplace_at(events_fd, owned_temp, final_name)
            owned_temp = None
            os.fsync(events_fd)
            if (
                _object_identity(os.fstat(loop_fd)) != loop_identity
                or _object_identity(os.fstat(events_fd)) != events_identity
            ):
                _reject("LOOP-307", "journal parent identity changed after append")
            self._assert_published_identity(loop_id, loop_identity)
            header_after, records_after = self._read_chain(loop_fd, events_fd)
            return replay_journal(header_after, records_after, self._schema_source)
        finally:
            if owned_temp is not None:
                try:
                    os.unlink(owned_temp, dir_fd=events_fd)
                    os.fsync(events_fd)
                except FileNotFoundError:
                    pass
            if lock_fd >= 0:
                os.close(lock_fd)
            os.close(events_fd)
            os.close(loop_fd)
