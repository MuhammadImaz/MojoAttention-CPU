#!/usr/bin/env python3
"""Dependency-free trusted CI gate used before candidate code or installs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SchemaIssue:
    absolute_path: tuple[str | int, ...]
    message: str

    @property
    def path(self) -> tuple[str | int, ...]:
        return self.absolute_path


class SchemaError(ValueError):
    pass


class Draft202012Validator:
    """Strict dependency-free evaluator for the schema vocabulary used by CI controls."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self.check_schema(schema)
        self.schema = schema

    @staticmethod
    def check_schema(schema: object) -> None:
        if not isinstance(schema, dict) or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise SchemaError("schema must declare JSON Schema Draft 2020-12")

    def iter_errors(self, instance: object) -> tuple[SchemaIssue, ...]:
        return tuple(self._validate(instance, self.schema, ()))

    def _validate(self, value: object, schema: object, path: tuple[str | int, ...]) -> list[SchemaIssue]:
        if schema is False:
            return [SchemaIssue(path, "value is forbidden")]
        if schema is True:
            return []
        if not isinstance(schema, dict):
            return [SchemaIssue(path, "schema node is invalid")]
        if "$ref" in schema:
            ref = schema["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                return [SchemaIssue(path, "only local schema references are supported")]
            target: object = self.schema
            try:
                for part in ref[2:].split("/"):
                    target = target[part.replace("~1", "/").replace("~0", "~")]  # type: ignore[index]
            except KeyError, TypeError:
                return [SchemaIssue(path, "schema reference cannot be resolved")]
            return self._validate(value, target, path)
        errors: list[SchemaIssue] = []
        for child in schema.get("allOf", []):
            errors.extend(self._validate(value, child, path))
        expected_type = schema.get("type")
        types_by_name = {
            "object": lambda item: isinstance(item, dict),
            "array": lambda item: isinstance(item, list),
            "string": lambda item: isinstance(item, str),
            "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
            "boolean": lambda item: isinstance(item, bool),
            "null": lambda item: item is None,
        }
        if expected_type is not None:
            names = [expected_type] if isinstance(expected_type, str) else expected_type
            valid_type = isinstance(names, list) and any(
                name in types_by_name and types_by_name[name](value) for name in names
            )
            if not valid_type:
                return errors + [SchemaIssue(path, "value has the wrong type")]
        if "const" in schema and value != schema["const"]:
            errors.append(SchemaIssue(path, "value differs from const"))
        if "enum" in schema and value not in schema["enum"]:
            errors.append(SchemaIssue(path, "value is not in enum"))
        if isinstance(value, dict):
            required = schema.get("required", [])
            for name in required:
                if name not in value:
                    errors.append(SchemaIssue((*path, name), "required property is missing"))
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                for name in value.keys() - properties.keys():
                    errors.append(SchemaIssue((*path, name), "additional property is forbidden"))
            for name, child in properties.items():
                if name in value:
                    errors.extend(self._validate(value[name], child, (*path, name)))
        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0):
                errors.append(SchemaIssue(path, "array has too few items"))
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                errors.append(SchemaIssue(path, "array has too many items"))
            if schema.get("uniqueItems"):
                encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
                if len(encoded) != len(set(encoded)):
                    errors.append(SchemaIssue(path, "array items are not unique"))
            prefixes = schema.get("prefixItems", [])
            for index, child in enumerate(prefixes):
                if index < len(value):
                    errors.extend(self._validate(value[index], child, (*path, index)))
            items = schema.get("items")
            start = len(prefixes)
            if items is not None:
                for index in range(start, len(value)):
                    errors.extend(self._validate(value[index], items, (*path, index)))
            for contains in schema.get("allOf", []):
                has_match = (
                    isinstance(contains, dict)
                    and "contains" in contains
                    and any(
                        not self._validate(item, contains["contains"], (*path, index))
                        for index, item in enumerate(value)
                    )
                )
                if isinstance(contains, dict) and "contains" in contains and not has_match:
                    errors.append(SchemaIssue(path, "array does not contain a required item"))
        if isinstance(value, str):
            if len(value) < schema.get("minLength", 0):
                errors.append(SchemaIssue(path, "string is too short"))
            if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
                errors.append(SchemaIssue(path, "string does not match pattern"))
        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(SchemaIssue(path, "integer is below minimum"))
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(SchemaIssue(path, "integer is above maximum"))
        return errors


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return raw, value


def _load_trusted_evaluator(control_root: Path) -> Any:
    jsonschema_module = types.ModuleType("jsonschema")
    jsonschema_module.Draft202012Validator = Draft202012Validator  # type: ignore[attr-defined]
    exceptions_module = types.ModuleType("jsonschema.exceptions")
    exceptions_module.SchemaError = SchemaError  # type: ignore[attr-defined]
    sys.modules["jsonschema"] = jsonschema_module
    sys.modules["jsonschema.exceptions"] = exceptions_module
    sys.modules["mojoattention"] = types.ModuleType("mojoattention")
    sys.modules["mojoattention.validation"] = types.ModuleType("mojoattention.validation")
    for name in ("paths", "protected_assets"):
        qualified = f"mojoattention.validation.{name}"
        spec = importlib.util.spec_from_file_location(qualified, control_root / "validator" / f"{name}.py")
        if spec is None or spec.loader is None:
            raise ValueError(f"trusted {name} module cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualified] = module
        spec.loader.exec_module(module)
    return sys.modules["mojoattention.validation.protected_assets"]


def run_gate(trusted_root: Path, control_root: Path, authorization_text: str, event_name: str) -> dict[str, object]:
    base = os.environ["TRUSTED_BASE"]
    head = os.environ["CANDIDATE_HEAD"]
    policy_bytes, policy = _load_json(control_root / "contracts/protected-assets.json")
    policy_schema_bytes, policy_schema = _load_json(control_root / "schemas/protected-assets.schema.json")
    registry_bytes, registry = _load_json(control_root / "contracts/required-checks.json")
    registry_schema_bytes, registry_schema = _load_json(control_root / "schemas/required-checks.schema.json")
    for record, schema, name in ((policy, policy_schema, "policy"), (registry, registry_schema, "registry")):
        issues = Draft202012Validator(schema).iter_errors(record)
        if issues:
            raise ValueError(f"{name} is schema-invalid at {issues[0].absolute_path}")
    protected_assets = _load_trusted_evaluator(control_root)
    policy_input = protected_assets.TrustedPolicyInput(
        policy_bytes=policy_bytes,
        schema_bytes=policy_schema_bytes,
        identity=protected_assets.git_blob_oid(policy_bytes),
        policy_digest="sha256:" + _digest(policy_bytes),
        schema_digest="sha256:" + _digest(policy_schema_bytes),
    )
    inspection, errors = protected_assets.inspect_repository_changes(trusted_root, base, head, policy_input)
    if errors or inspection is None:
        raise ValueError("trusted evaluator rejected policy or change identity")
    authorization = json.loads(authorization_text) if authorization_text else None
    context = None
    contract_digest = "sha256:" + "0" * 64
    if isinstance(authorization, dict):
        anchor = authorization.get("approval_anchor_revision")
        if (
            not isinstance(anchor, str)
            or subprocess.run(
                ["git", "merge-base", "--is-ancestor", anchor, base], cwd=trusted_root, check=False
            ).returncode
        ):
            raise ValueError("approval anchor is not in authenticated trusted history")
        contract_digest = authorization.get("contract_digest", "")
        context = protected_assets.AuthorizationContext(authorization, anchor, contract_digest)
    decision = protected_assets.evaluate_protected_changes(
        inspection.policy,
        inspection.effects,
        inspection.identity,
        inspection.change_set_digest,
        contract_digest,
        context,
    )
    blocking_decisions = tuple(item for item in decision if item.code not in {"PROT-003", "PROT-004"})
    if blocking_decisions:
        raise ValueError("trusted evaluator rejected protected change identity or policy")
    source = (control_root / "registry-source").read_text(encoding="utf-8").strip()
    return {
        "trusted_validation": "pass",
        "registry_source": source,
        "protected_change_review": sorted(item.code for item in decision),
    }


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 2:
        print("contract-invalid: trusted gate requires trusted-root and control-root", file=sys.stderr)
        return 3
    try:
        result = run_gate(
            Path(values[0]),
            Path(values[1]),
            os.environ.get("EXTERNAL_AUTHORIZATION", ""),
            os.environ["EVENT_NAME"],
        )
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"contract-invalid: {error}", file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
