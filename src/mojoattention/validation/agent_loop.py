from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

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
