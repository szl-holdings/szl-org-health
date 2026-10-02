#!/usr/bin/env python3
"""Execute the public Series-A Draft 2020-12 schema without dependencies."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
SUPPORTED_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "else",
        "enum",
        "format",
        "if",
        "items",
        "maximum",
        "maxItems",
        "minimum",
        "minItems",
        "minLength",
        "oneOf",
        "pattern",
        "properties",
        "propertyNames",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
    }
)
TYPE_NAMES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
RFC3339 = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[Tt]"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<fraction>\.\d+)?(?P<zone>[Zz]|[+-]\d{2}:\d{2})$"
)
MAX_VALIDATION_DEPTH = 256
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class ContractError(ValueError):
    """The schema contract or supplied artifact cannot be checked exactly."""


def _load_semantic_validator() -> Any:
    """Load the exact source-bound semantic validator without changing sys.path."""

    name = "build_series_a_diligence"
    expected = (REPOSITORY_ROOT / "build_series_a_diligence.py").resolve()
    module = sys.modules.get(name)
    if module is not None:
        location = getattr(module, "__file__", None)
        try:
            loaded = Path(location).resolve() if isinstance(location, str) else None
        except OSError:
            loaded = None
        if loaded != expected:
            raise ContractError(
                "semantic validator is already loaded from an unexpected path"
            )
    else:
        spec = importlib.util.spec_from_file_location(name, expected)
        if spec is None or spec.loader is None:
            raise ContractError("cannot load the exact semantic validator")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise ContractError("cannot execute the exact semantic validator") from exc
    validator = getattr(module, "validate_artifact", None)
    if not callable(validator):
        raise ContractError("exact semantic validator has no validate_artifact call")
    return validator


def _semantic_errors(artifact: dict[str, Any]) -> list[str]:
    try:
        errors = _load_semantic_validator()(artifact)
    except ContractError:
        raise
    except Exception as exc:
        raise ContractError("semantic artifact validation could not complete") from exc
    if not isinstance(errors, list) or any(
        not isinstance(error, str) for error in errors
    ):
        raise ContractError("semantic validator returned a malformed result")
    return errors


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-standard JSON constant is forbidden: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON member is forbidden: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is forbidden: {path}")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid UTF-8 JSON: {path}") from exc
    return value, raw


def _schema_path(parent: str, key: str) -> str:
    return f"{parent}/{key.replace('~', '~0').replace('/', '~1')}"


def _assert_nonnegative_integer(value: Any, path: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{path} must be a nonnegative integer")


def assert_supported_schema(schema: Any, path: str = "#", depth: int = 0) -> None:
    if depth > MAX_VALIDATION_DEPTH:
        raise ContractError(f"schema nesting exceeds {MAX_VALIDATION_DEPTH}: {path}")
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise ContractError(f"schema node must be an object or boolean: {path}")
    unsupported = sorted(set(schema) - SUPPORTED_KEYWORDS)
    if unsupported:
        joined = ", ".join(unsupported)
        raise ContractError(f"unsupported schema keyword(s) at {path}: {joined}")

    for keyword in ("$schema", "$id", "title", "$ref", "format", "pattern"):
        if keyword in schema and not isinstance(schema[keyword], str):
            raise ContractError(f"{_schema_path(path, keyword)} must be a string")
    if "$ref" in schema and not (
        schema["$ref"] == "#" or schema["$ref"].startswith("#/")
    ):
        raise ContractError(
            f"{_schema_path(path, '$ref')} must be a local JSON Pointer"
        )
    if "format" in schema and schema["format"] != "date-time":
        raise ContractError(
            f"unsupported asserted format at {_schema_path(path, 'format')}: "
            f"{schema['format']}"
        )
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise ContractError(
                f"invalid regular expression at {_schema_path(path, 'pattern')}"
            ) from exc

    if "type" in schema:
        declared = schema["type"]
        names = [declared] if isinstance(declared, str) else declared
        if (
            not isinstance(names, list)
            or not names
            or any(not isinstance(name, str) for name in names)
            or len(names) != len(set(names))
            or not set(names).issubset(TYPE_NAMES)
        ):
            raise ContractError(
                f"invalid type declaration at {_schema_path(path, 'type')}"
            )
    if "required" in schema:
        required = schema["required"]
        if (
            not isinstance(required, list)
            or any(not isinstance(name, str) for name in required)
            or len(required) != len(set(required))
        ):
            raise ContractError(
                f"invalid required declaration at {_schema_path(path, 'required')}"
            )
    if "enum" in schema:
        enum_values = schema["enum"]
        enum_path = _schema_path(path, "enum")
        if not isinstance(enum_values, list) or not enum_values:
            raise ContractError(f"enum must be a nonempty array at {enum_path}")
        if any(
            _json_equal(enum_values[left], enum_values[right])
            for left in range(len(enum_values))
            for right in range(left + 1, len(enum_values))
        ):
            raise ContractError(
                f"enum values must be JSON-semantically unique at {enum_path}"
            )

    for keyword in ("minItems", "maxItems", "minLength"):
        if keyword in schema:
            _assert_nonnegative_integer(
                schema[keyword],
                _schema_path(path, keyword),
            )
    for keyword in ("minimum", "maximum"):
        if keyword in schema:
            value = schema[keyword]
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
            ):
                raise ContractError(
                    f"{_schema_path(path, keyword)} must be a finite number"
                )
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise ContractError(f"{_schema_path(path, 'uniqueItems')} must be a boolean")

    for keyword in ("properties", "$defs"):
        if keyword not in schema:
            continue
        children = schema[keyword]
        if not isinstance(children, dict):
            raise ContractError(f"{_schema_path(path, keyword)} must be an object")
        for name, child in children.items():
            assert_supported_schema(
                child,
                _schema_path(_schema_path(path, keyword), name),
                depth + 1,
            )
    for keyword in (
        "additionalProperties",
        "contains",
        "else",
        "if",
        "items",
        "propertyNames",
        "then",
    ):
        if keyword in schema:
            assert_supported_schema(
                schema[keyword],
                _schema_path(path, keyword),
                depth + 1,
            )
    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword not in schema:
            continue
        children = schema[keyword]
        if not isinstance(children, list) or not children:
            raise ContractError(
                f"{_schema_path(path, keyword)} must be a nonempty array"
            )
        for index, child in enumerate(children):
            assert_supported_schema(
                child,
                _schema_path(_schema_path(path, keyword), str(index)),
                depth + 1,
            )


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _matches_type(instance: Any, expected: str) -> bool:
    if expected == "null":
        return instance is None
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "number":
        return (
            isinstance(instance, (int, float))
            and not isinstance(instance, bool)
            and math.isfinite(instance)
        )
    if expected == "integer":
        return (
            isinstance(instance, int)
            and not isinstance(instance, bool)
            or isinstance(instance, float)
            and math.isfinite(instance)
            and instance.is_integer()
        )
    raise ContractError(f"unsupported type reached validator: {expected}")


def _valid_rfc3339(value: str) -> bool:
    match = RFC3339.fullmatch(value)
    if match is None:
        return False
    try:
        dt.date.fromisoformat(match["date"])
    except ValueError:
        return False
    hour = int(match["hour"])
    minute = int(match["minute"])
    second = int(match["second"])
    if hour > 23 or minute > 59 or second > 60:
        return False
    zone = match["zone"]
    if zone not in {"Z", "z"}:
        zone_hour, zone_minute = map(int, zone[1:].split(":"))
        if zone_hour > 23 or zone_minute > 59:
            return False
    return True


def _instance_path(parent: str, key: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{parent}.{key}"
    return f"{parent}[{json.dumps(key, ensure_ascii=True)}]"


class Draft202012Validator:
    """Fail-closed evaluator for every assertion keyword used by this schema."""

    def __init__(self, schema: dict[str, Any]) -> None:
        if schema.get("$schema") != DRAFT_2020_12:
            raise ContractError(f"schema must declare exactly {DRAFT_2020_12}")
        assert_supported_schema(schema)
        self.schema = schema

    def _resolve_ref(self, reference: str) -> Any:
        if reference == "#":
            return self.schema
        if not reference.startswith("#/"):
            raise ContractError(
                f"only local JSON Pointer references are supported: {reference}"
            )
        current: Any = self.schema
        for raw_part in reference[2:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdecimal():
                index = int(part)
                if index >= len(current):
                    raise ContractError(f"unresolved schema reference: {reference}")
                current = current[index]
            else:
                raise ContractError(f"unresolved schema reference: {reference}")
        return current

    def validate(self, instance: Any) -> list[str]:
        return self._validate(self.schema, instance, "$", 0)

    def _validate(
        self,
        schema: Any,
        instance: Any,
        path: str,
        depth: int,
    ) -> list[str]:
        if depth > MAX_VALIDATION_DEPTH:
            raise ContractError(
                f"validation nesting exceeds {MAX_VALIDATION_DEPTH}: {path}"
            )
        if schema is True:
            return []
        if schema is False:
            return [f"{path}: false schema rejects value"]
        errors: list[str] = []

        if "$ref" in schema:
            errors.extend(
                self._validate(
                    self._resolve_ref(schema["$ref"]),
                    instance,
                    path,
                    depth + 1,
                )
            )
        if "type" in schema:
            declared = schema["type"]
            names = [declared] if isinstance(declared, str) else declared
            if not any(_matches_type(instance, name) for name in names):
                errors.append(f"{path}: expected type {json.dumps(declared)}")
        if "const" in schema and not _json_equal(instance, schema["const"]):
            errors.append(f"{path}: value does not equal const")
        if "enum" in schema and not any(
            _json_equal(instance, candidate) for candidate in schema["enum"]
        ):
            errors.append(f"{path}: value is not in enum")

        if isinstance(instance, str):
            if "minLength" in schema and len(instance) < schema["minLength"]:
                errors.append(f"{path}: string is shorter than minLength")
            if "pattern" in schema and re.search(schema["pattern"], instance) is None:
                errors.append(f"{path}: string does not match pattern")
            if schema.get("format") == "date-time" and not _valid_rfc3339(instance):
                errors.append(f"{path}: string is not RFC3339 date-time")

        is_number = (
            isinstance(instance, (int, float))
            and not isinstance(instance, bool)
            and math.isfinite(instance)
        )
        if is_number:
            if "minimum" in schema and instance < schema["minimum"]:
                errors.append(f"{path}: number is below minimum")
            if "maximum" in schema and instance > schema["maximum"]:
                errors.append(f"{path}: number is above maximum")

        if isinstance(instance, dict):
            for name in schema.get("required", []):
                if name not in instance:
                    errors.append(
                        f"{_instance_path(path, name)}: required property is missing"
                    )
            properties = schema.get("properties", {})
            for name in sorted(set(instance) & set(properties)):
                errors.extend(
                    self._validate(
                        properties[name],
                        instance[name],
                        _instance_path(path, name),
                        depth + 1,
                    )
                )
            if "propertyNames" in schema:
                for name in sorted(instance):
                    errors.extend(
                        self._validate(
                            schema["propertyNames"],
                            name,
                            f"{_instance_path(path, name)}<propertyName>",
                            depth + 1,
                        )
                    )
            additional = schema.get("additionalProperties", True)
            for name in sorted(set(instance) - set(properties)):
                additional_path = _instance_path(path, name)
                if additional is False:
                    errors.append(
                        f"{additional_path}: additional property is forbidden"
                    )
                elif additional is not True:
                    errors.extend(
                        self._validate(
                            additional,
                            instance[name],
                            additional_path,
                            depth + 1,
                        )
                    )

        if isinstance(instance, list):
            if "minItems" in schema and len(instance) < schema["minItems"]:
                errors.append(f"{path}: array has fewer than minItems")
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                errors.append(f"{path}: array has more than maxItems")
            if schema.get("uniqueItems") is True and any(
                _json_equal(instance[left], instance[right])
                for left in range(len(instance))
                for right in range(left + 1, len(instance))
            ):
                errors.append(f"{path}: array items are not unique")
            if "items" in schema:
                for index, item in enumerate(instance):
                    errors.extend(
                        self._validate(
                            schema["items"],
                            item,
                            f"{path}[{index}]",
                            depth + 1,
                        )
                    )
            if "contains" in schema and not any(
                not self._validate(
                    schema["contains"], item, f"{path}[{index}]", depth + 1
                )
                for index, item in enumerate(instance)
            ):
                errors.append(f"{path}: array has no item matching contains")

        for child in schema.get("allOf", []):
            errors.extend(self._validate(child, instance, path, depth + 1))
        if "anyOf" in schema and not any(
            not self._validate(child, instance, path, depth + 1)
            for child in schema["anyOf"]
        ):
            errors.append(f"{path}: value does not match anyOf")
        if "oneOf" in schema:
            matches = sum(
                not self._validate(child, instance, path, depth + 1)
                for child in schema["oneOf"]
            )
            if matches != 1:
                errors.append(f"{path}: value matches {matches} oneOf branches")
        if "if" in schema:
            condition_matches = not self._validate(
                schema["if"],
                instance,
                path,
                depth + 1,
            )
            selected = "then" if condition_matches else "else"
            if selected in schema:
                errors.extend(
                    self._validate(schema[selected], instance, path, depth + 1)
                )
        return errors


def _fixture(
    artifact: dict[str, Any],
    mutate: Any,
) -> dict[str, Any]:
    value = copy.deepcopy(artifact)
    mutate(value)
    return value


def _canonical_artifact_digest(artifact: dict[str, Any]) -> str:
    stored_digest = artifact.get("digest_sha256")
    if not isinstance(stored_digest, str):
        raise ContractError("artifact digest_sha256 must be a string")
    unsigned = dict(artifact)
    unsigned.pop("digest_sha256", None)
    try:
        canonical = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ContractError("artifact cannot be independently canonicalized") from exc
    computed_digest = hashlib.sha256(canonical).hexdigest()
    if stored_digest != computed_digest:
        raise ContractError(
            "artifact digest_sha256 does not match independent canonical recomputation"
        )
    return computed_digest


def adversarial_fixtures(
    artifact: dict[str, Any],
) -> list[tuple[str, dict[str, Any], str]]:
    spaces_state = artifact["inventory"]["huggingface"]["subinventory_states"]["spaces"]
    invalid_public_count = 0 if spaces_state != "MEASURED" else None
    return [
        (
            "missing-required-claim-boundary",
            _fixture(artifact, lambda value: value.pop("claim_boundary")),
            "$.claim_boundary:",
        ),
        (
            "unexpected-root-member",
            _fixture(
                artifact,
                lambda value: value.__setitem__("schema_parse_only_bypass", True),
            ),
            "$.schema_parse_only_bypass:",
        ),
        (
            "all-zero-digest",
            _fixture(
                artifact,
                lambda value: value.__setitem__("digest_sha256", "0" * 64),
            ),
            "$.digest_sha256:",
        ),
        (
            "fixed-unavailable-component-overclaim",
            _fixture(
                artifact,
                lambda value: value["governed_mcp"].__setitem__(
                    "state",
                    "MEASURED",
                ),
            ),
            "$.governed_mcp:",
        ),
        (
            "duplicate-gap",
            _fixture(
                artifact,
                lambda value: value["gaps"].append(copy.deepcopy(value["gaps"][0])),
            ),
            "$.gaps:",
        ),
        (
            "invalid-date-time",
            _fixture(
                artifact,
                lambda value: value.__setitem__(
                    "assessed_at",
                    "2026-08-30 12:00:00",
                ),
            ),
            "$.assessed_at:",
        ),
        (
            "conditional-public-space-count",
            _fixture(
                artifact,
                lambda value: value["summary"].__setitem__(
                    "hf_public_spaces",
                    invalid_public_count,
                ),
            ),
            "$.summary.hf_public_spaces:",
        ),
        (
            "boolean-integer-confusion",
            _fixture(
                artifact,
                lambda value: value["source_binding"].__setitem__(
                    "compiler_revision_verified",
                    1,
                ),
            ),
            "$.source_binding.compiler_revision_verified:",
        ),
    ]


def verify(schema_path: Path, artifact_path: Path) -> dict[str, Any]:
    schema_value, schema_raw = load_json(schema_path)
    artifact_value, _artifact_raw = load_json(artifact_path)
    if not isinstance(schema_value, dict):
        raise ContractError("schema root must be an object")
    if not isinstance(artifact_value, dict):
        raise ContractError("artifact root must be an object")
    validator = Draft202012Validator(schema_value)
    errors = validator.validate(artifact_value)
    if errors:
        detail = "; ".join(errors[:8])
        raise ContractError(f"real artifact violates public schema: {detail}")
    artifact_digest = _canonical_artifact_digest(artifact_value)
    semantic_errors = _semantic_errors(artifact_value)
    if semantic_errors:
        detail = ", ".join(semantic_errors[:12])
        raise ContractError(f"real artifact violates semantic contract: {detail}")

    verified: list[str] = []
    for name, fixture, expected_path in adversarial_fixtures(artifact_value):
        fixture_errors = validator.validate(fixture)
        if not fixture_errors:
            raise ContractError(f"invalid fixture was accepted: {name}")
        if not any(error.startswith(expected_path) for error in fixture_errors):
            detail = "; ".join(fixture_errors[:4])
            raise ContractError(
                f"invalid fixture missed expected assertion {name}: {detail}"
            )
        verified.append(name)
    return {
        "state": "SCHEMA_CONTRACT_VERIFIED",
        "schema_draft": DRAFT_2020_12,
        "schema_sha256": hashlib.sha256(schema_raw).hexdigest(),
        "artifact": str(artifact_path),
        "artifact_digest_sha256": artifact_digest,
        "real_artifact_valid": True,
        "semantic_contract_valid": True,
        "adversarial_fixtures_verified": verified,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        receipt = verify(args.schema, args.artifact)
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, OSError, RecursionError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {"state": "FAILED", "error": str(exc)[:800]},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
