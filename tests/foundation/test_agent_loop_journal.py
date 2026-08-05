from __future__ import annotations

import fcntl
import json
from pathlib import Path
from typing import Any

import pytest

import mojoattention.validation.agent_loop as agent_loop
from mojoattention.validation.agent_loop import AgentLoopContractError, AgentLoopJournal

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "agent-loop-state.schema.json"
DIGEST = "sha256:" + "a" * 64


def metadata() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "contract_digest": DIGEST,
        "source_revision": "a" * 40,
        "source_tree": "b" * 40,
        "trusted_base_revision": "c" * 40,
        "trusted_base_tree": "d" * 40,
        "assigned_role": "implementation-agent",
        "retry_budget": 2,
        "allowed_paths": ["src/mojoattention/validation/agent_loop.py"],
        "protected_paths": ["schemas/agent-loop-state.schema.json"],
        "created_at": "2026-07-29T12:00:00Z",
    }


def stopped_event() -> dict[str, Any]:
    return {
        "record_type": "event",
        "schema_version": "1.0.0",
        "attempt": 1,
        "control_binding": {
            "contract_digest": DIGEST,
            "source_revision": "a" * 40,
            "source_tree": "b" * 40,
            "trusted_base_revision": "c" * 40,
            "trusted_base_tree": "d" * 40,
            "assigned_role": "implementation-agent",
            "allowed_paths": ["src/mojoattention/validation/agent_loop.py"],
            "protected_paths": ["schemas/agent-loop-state.schema.json"],
        },
        "transition": "stopped",
        "status": "stopped",
        "validation_binding": None,
        "evidence_bindings": [],
        "validation_observations": [],
        "diagnosis": None,
        "improvement_proof": None,
        "stop_reason": "causality",
        "actor_kind": "system",
        "timestamp": "2026-07-29T12:00:01Z",
    }


def test_start_generates_identity_and_fixed_append_only_layout(tmp_path: Path) -> None:
    journal = AgentLoopJournal(tmp_path, SCHEMA)
    state = journal.start(metadata())
    assert len(state.header.loop_id) == 32
    loop = tmp_path / "reports" / "agent-loops" / state.header.loop_id
    assert sorted(path.relative_to(loop).as_posix() for path in loop.rglob("*.json")) == [
        "events/00000001.json",
        "header.json",
    ]
    assert state.status == "awaiting-validation"
    assert journal.inspect(state.header.loop_id) == state


def test_callers_cannot_choose_loop_identity_or_overwrite_history(tmp_path: Path) -> None:
    journal = AgentLoopJournal(tmp_path, SCHEMA)
    supplied = metadata()
    supplied["loop_id"] = "1" * 32
    with pytest.raises(AgentLoopContractError, match="LOOP-301"):
        journal.start(supplied)
    assert not (tmp_path / "reports").exists()


def test_append_rereads_full_chain_and_terminal_history_is_immutable(tmp_path: Path) -> None:
    first_process = AgentLoopJournal(tmp_path, SCHEMA)
    started = first_process.start(metadata())
    second_process = AgentLoopJournal(tmp_path, SCHEMA)
    terminal = second_process.append(started.header.loop_id, stopped_event())
    assert terminal.terminal is True
    assert terminal.events[-1].sequence == 2
    with pytest.raises(AgentLoopContractError, match="LOOP-011"):
        first_process.append(started.header.loop_id, stopped_event())
    assert len(list((tmp_path / "reports" / "agent-loops" / started.header.loop_id / "events").glob("*.json"))) == 2


def test_tampered_chain_is_rejected_before_append(tmp_path: Path) -> None:
    journal = AgentLoopJournal(tmp_path, SCHEMA)
    started = journal.start(metadata())
    event = tmp_path / "reports" / "agent-loops" / started.header.loop_id / "events" / "00000001.json"
    payload = json.loads(event.read_text())
    payload["actor_kind"] = "agent"
    event.write_text(json.dumps(payload))
    with pytest.raises(AgentLoopContractError, match="LOOP-003"):
        journal.append(started.header.loop_id, stopped_event())
    assert not event.with_name("00000002.json").exists()


def test_concurrent_writer_loses_without_mutating_history(tmp_path: Path) -> None:
    journal = AgentLoopJournal(tmp_path, SCHEMA)
    started = journal.start(metadata())
    lock_path = tmp_path / "reports" / "agent-loops" / started.header.loop_id / ".writer.lock"
    with lock_path.open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(AgentLoopContractError, match="LOOP-303"):
            journal.append(started.header.loop_id, stopped_event())
    assert journal.inspect(started.header.loop_id).status == "awaiting-validation"


def test_symlinked_output_boundary_and_hardlinked_record_fail_closed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "reports").symlink_to(outside, target_is_directory=True)
    with pytest.raises(AgentLoopContractError, match="LOOP-304"):
        AgentLoopJournal(tmp_path, SCHEMA).start(metadata())
    (tmp_path / "reports").unlink()
    journal = AgentLoopJournal(tmp_path, SCHEMA)
    started = journal.start(metadata())
    header = tmp_path / "reports" / "agent-loops" / started.header.loop_id / "header.json"
    (tmp_path / "header-alias.json").hardlink_to(header)
    with pytest.raises(AgentLoopContractError, match="LOOP-305"):
        journal.inspect(started.header.loop_id)


def test_unsealed_tail_is_never_consumed_or_cleaned_by_reader(tmp_path: Path) -> None:
    journal = AgentLoopJournal(tmp_path, SCHEMA)
    started = journal.start(metadata())
    events = tmp_path / "reports" / "agent-loops" / started.header.loop_id / "events"
    orphan = events / ".event.foreign.tmp"
    orphan.write_text("{}")
    assert journal.inspect(started.header.loop_id).status == "awaiting-validation"
    assert orphan.read_text() == "{}"


def test_concurrent_creator_collision_preserves_first_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tokens = iter(["1" * 32, "2" * 32])
    monkeypatch.setattr(agent_loop.secrets, "token_hex", lambda _size: next(tokens))
    first = AgentLoopJournal(tmp_path, SCHEMA).start(metadata())
    tokens = iter(["1" * 32, "3" * 32])
    monkeypatch.setattr(agent_loop.secrets, "token_hex", lambda _size: next(tokens))
    with pytest.raises(AgentLoopContractError, match="LOOP-302"):
        AgentLoopJournal(tmp_path, SCHEMA).start(metadata())
    assert AgentLoopJournal(tmp_path, SCHEMA).inspect(first.header.loop_id) == first
    loops = tmp_path / "reports" / "agent-loops"
    assert sorted(path.name for path in loops.iterdir()) == [first.header.loop_id]


def test_interrupted_append_removes_only_owned_unsealed_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal = AgentLoopJournal(tmp_path, SCHEMA)
    started = journal.start(metadata())
    events = tmp_path / "reports" / "agent-loops" / started.header.loop_id / "events"
    orphan = events / ".event.foreign.tmp"
    orphan.write_text("{}")

    def fail_publication(_parent_fd: int, _source: str, _target: str) -> None:
        raise OSError("injected publication interruption")

    monkeypatch.setattr(agent_loop, "_rename_noreplace_at", fail_publication)
    with pytest.raises(OSError, match="injected"):
        journal.append(started.header.loop_id, stopped_event())
    assert orphan.exists()
    assert sorted(path.name for path in events.iterdir()) == [".event.foreign.tmp", "00000001.json"]
