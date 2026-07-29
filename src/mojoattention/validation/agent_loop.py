from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

SchemaSource = Path | bytes


@dataclass(frozen=True)
class AgentLoopError:
    code: str
    message: str
    context: dict[str, object]


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


def derive_journal_state(
    header: dict[str, Any],
    events: list[dict[str, Any]],
    schema_source: SchemaSource,
) -> dict[str, Any]:
    header_errors = validate_agent_loop_record(header, schema_source)
    if header_errors:
        _reject("LOOP-001", "agent loop header is invalid")
    if digest_record(header, "header_digest") != header["header_digest"]:
        _reject("LOOP-002", "agent loop header digest does not match")
    prior = header["header_digest"]
    retries_consumed = 0
    last_validation: dict[str, Any] | None = None
    status: str | None = None
    attempt = 1
    for expected_sequence, event in enumerate(events, start=1):
        event_errors = validate_agent_loop_record(event, schema_source)
        if event_errors:
            _reject("LOOP-001", "agent loop event is invalid", sequence=expected_sequence)
        if digest_record(event, "event_digest") != event["event_digest"]:
            _reject("LOOP-003", "agent loop event digest does not match", sequence=expected_sequence)
        if event["sequence"] != expected_sequence:
            _reject(
                "LOOP-004",
                "agent loop event sequence is not contiguous",
                expected=expected_sequence,
                actual=event["sequence"],
            )
        if event["prior_event_digest"] != prior:
            _reject("LOOP-005", "agent loop event prior digest does not match", sequence=expected_sequence)
        if event["loop_id"] != header["loop_id"]:
            _reject("LOOP-006", "agent loop event belongs to another loop", sequence=expected_sequence)
        if event["transition"] == "retry-authorized":
            retries_consumed += 1
            if event["attempt"] != attempt + 1:
                _reject("LOOP-007", "retry must increment the attempt exactly once", sequence=expected_sequence)
            if retries_consumed > header["retry_budget"]:
                _reject("LOOP-008", "retry budget is exhausted", sequence=expected_sequence)
        elif event["attempt"] != attempt:
            _reject("LOOP-007", "non-retry event changed the attempt", sequence=expected_sequence)
        attempt = event["attempt"]
        status = event["status"]
        if event["transition"] == "validation-recorded":
            last_validation = event
        prior = event["event_digest"]
    if status is None:
        _reject("LOOP-009", "agent loop journal has no events")
    return {
        "status": status,
        "attempt": attempt,
        "retries_consumed": retries_consumed,
        "last_validation": last_validation,
    }
