#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Edge contract: what an UNPAID client receives from the SZL Cloudflare edge.

``edge/contract.yaml`` declares, per host and path, the response an unpaid,
unauthenticated client must receive:

  free      2xx, 3xx, or an origin authentication refusal (401/403). Never 402.
  paid      402 carrying an x402 v2 ``PAYMENT-REQUIRED`` header whose decoded
            terms equal the live rule: amount, scheme, network, asset, payTo
            and the resource URL.
  internal  403 that is not a bot challenge: a Cloudflare block, a Cloudflare
            Access refusal, or an origin 403.

Every check sends one real request per declared method and never follows a
redirect. POST requests carry a small, deliberately invalid JSON body, so a
request that leaks past the paywall is rejected by the origin's validator
instead of starting a generation. Each response is classified as one of
402-paywall, 402-unparsed, 403-challenge, 403-edge-block, 403-access,
401/403-origin-auth, 5xx-origin, 2xx, 3xx, 404, 4xx or transport-error, and
every check is PASS or FAIL. There is no partial credit and no retry.

Outputs: a JSON receipt with a ``.sha256`` sidecar and, under GitHub Actions,
a Markdown step summary. Exit 0 when every check passes, 1 when any check
fails, 2 when the contract file or the command line is invalid.

Standard library only. The YAML reader accepts a strict, documented subset
(block mappings and sequences, quoted or simple plain scalars, flat flow
lists, comments) and rejects every other construct instead of guessing.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONTRACT_SCHEMA = "szl.edge-contract/v1"
RECEIPT_SCHEMA = "szl.edge-contract-receipt/v1"
DEFAULT_CONTRACT = "edge/contract.yaml"
DEFAULT_RECEIPT = "reports/edge-contract-receipt.json"
MAX_CONTRACT_BYTES = 256 * 1024
MAX_PAYMENT_HEADER_CHARS = 16 * 1024
MAX_OFFERS = 16
# Cloudflare Monetization Gateway limits (configuration/rules: "The minimum
# settlement amount is $0.001, or 1,000 atomic units. The maximum price is
# $100, or 100,000,000 atomic units").
MIN_PRICE_ATOMIC = 1_000
MAX_PRICE_ATOMIC = 100_000_000

CLASSES = ("free", "paid", "internal")
METHODS = ("GET", "POST")
OUTCOMES = (
    "ok",
    "redirect",
    "origin-auth",
    "access-denied",
    "edge-block",
    "challenge",
    "paywall",
    "payment-unparsed",
    "not-found",
    "client-error",
    "origin-5xx",
    "unexpected-status",
    "transport-error",
)
DEFAULT_ACCEPT = {
    "free": ("ok", "redirect", "origin-auth"),
    "paid": ("paywall",),
    "internal": ("edge-block", "access-denied", "origin-auth"),
}

TOP_KEYS = frozenset(
    {
        "schema",
        "as_of",
        "owner_decision",
        "sources",
        "unpaid_client",
        "payment_terms",
        "rules_inventory",
        "checks",
        "unprobed_rules",
        "not_covered",
    }
)
REQUIRED_TOP_KEYS = frozenset({"schema", "as_of", "unpaid_client", "payment_terms", "checks"})
CLIENT_KEYS = frozenset(
    {
        "user_agent",
        "exempt_user_agent_substrings",
        "timeout_seconds",
        "max_body_bytes",
        "post_body",
        "post_content_type",
    }
)
TERMS_KEYS = frozenset({"x402_version", "scheme", "network", "asset", "pay_to"})
CHECK_KEYS = frozenset(
    {"id", "class", "host", "path", "methods", "evidence", "rule_id", "price_atomic", "accept", "note"}
)
REQUIRED_CHECK_KEYS = frozenset({"id", "class", "host", "path", "methods", "evidence"})
INVENTORY_KEYS = frozenset({"zone", "rule_id", "description", "price_atomic", "audience", "scope"})
UNPROBED_KEYS = frozenset({"rule_id", "reason"})
NOT_COVERED_KEYS = frozenset({"target", "reason"})
AUDIENCES = ("everyone", "verified-bots")

CHECK_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
HOST_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
PATH_RE = re.compile(r"/[A-Za-z0-9._~/-]{0,255}")
RULE_ID_RE = re.compile(r"[0-9a-f]{32}")
EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
UA_RE = re.compile(r"[\x20-\x7e]{1,200}")
AS_OF_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class ContractError(ValueError):
    """The contract file or the command line is invalid (exit 2)."""


# --------------------------------------------------------------------------
# Strict YAML subset reader
# --------------------------------------------------------------------------

_KEY_ENTRY_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*):(?: (.*))?")
_PLAIN_RE = re.compile(r"[A-Za-z_/][A-Za-z0-9_./-]*")
_INT_RE = re.compile(r"0|[1-9][0-9]*")
# YAML 1.1 readers (for example PyYAML) resolve these plain words to booleans or
# null. Requiring quotes keeps every conforming YAML reader in agreement.
_AMBIGUOUS_PLAIN = frozenset(
    {
        "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO",
        "on", "On", "ON", "off", "Off", "OFF",
        "True", "TRUE", "False", "FALSE", "Null", "NULL",
    }
)


@dataclass(frozen=True)
class _Line:
    number: int
    indent: int
    text: str


def _strip_comment(raw: str, number: int) -> str:
    """Drop a trailing ``# comment`` that is outside quoted scalars."""
    quote = None
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
        elif quote == "'":
            if char == "'":
                if index + 1 < len(raw) and raw[index + 1] == "'":
                    index += 2
                    continue
                quote = None
        elif char == "#" and (index == 0 or raw[index - 1] == " "):
            return raw[:index]
        elif char in "\"'":
            quote = char
        index += 1
    if quote is not None:
        raise ContractError(f"line {number}: unterminated quoted scalar")
    return raw


def _logical_lines(text: str) -> list[_Line]:
    if text.startswith("\ufeff"):
        raise ContractError("a byte-order mark is not allowed")
    if "\r" in text:
        raise ContractError("carriage returns are not allowed; use LF line endings")
    if "\t" in text:
        raise ContractError("tab characters are not allowed")
    lines: list[_Line] = []
    document_start_allowed = True
    for number, raw in enumerate(text.split("\n"), start=1):
        stripped = _strip_comment(raw, number).rstrip(" ")
        if not stripped:
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        body = stripped[indent:]
        if body == "---" and indent == 0 and document_start_allowed:
            document_start_allowed = False
            continue
        document_start_allowed = False
        if body.startswith(("---", "...", "%", "? ", "&", "*", "!", "|", ">")) or body == "?":
            raise ContractError(f"line {number}: unsupported YAML construct {body[:12]!r}")
        lines.append(_Line(number, indent, body))
    return lines


def _is_sequence_item(text: str) -> bool:
    return text == "-" or text.startswith("- ")


def _split_flow_items(inner: str, number: int) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    quote = None
    index = 0
    while index < len(inner):
        char = inner[index]
        if quote == '"':
            current.append(char)
            if char == "\\" and index + 1 < len(inner):
                current.append(inner[index + 1])
                index += 2
                continue
            if char == '"':
                quote = None
        elif quote == "'":
            current.append(char)
            if char == "'":
                if index + 1 < len(inner) and inner[index + 1] == "'":
                    current.append("'")
                    index += 2
                    continue
                quote = None
        elif char == ",":
            items.append("".join(current))
            current = []
        elif char in "[]{}":
            raise ContractError(f"line {number}: nested flow collections are not supported")
        else:
            if char in "\"'":
                quote = char
            current.append(char)
        index += 1
    if quote is not None:
        raise ContractError(f"line {number}: unterminated quoted scalar in a flow list")
    items.append("".join(current))
    return items


def _parse_double_quoted(text: str, number: int) -> str:
    index = 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            break
        index += 1
    else:
        raise ContractError(f"line {number}: unterminated double-quoted scalar")
    if index != len(text) - 1:
        raise ContractError(f"line {number}: characters after a closing quote")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        raise ContractError(
            f"line {number}: only JSON-compatible escapes are allowed in double quotes"
        ) from None
    return value


def _parse_single_quoted(text: str, number: int) -> str:
    chars: list[str] = []
    index = 1
    while index < len(text):
        char = text[index]
        if char == "'":
            if index + 1 < len(text) and text[index + 1] == "'":
                chars.append("'")
                index += 2
                continue
            break
        chars.append(char)
        index += 1
    else:
        raise ContractError(f"line {number}: unterminated single-quoted scalar")
    if index != len(text) - 1:
        raise ContractError(f"line {number}: characters after a closing quote")
    return "".join(chars)


def _parse_plain(text: str, number: int) -> Any:
    if text == "true":
        return True
    if text == "false":
        return False
    if text == "null":
        return None
    if _INT_RE.fullmatch(text):
        return int(text)
    if text in _AMBIGUOUS_PLAIN or not _PLAIN_RE.fullmatch(text):
        raise ContractError(f"line {number}: {text!r} must be quoted")
    return text


def _parse_scalar(text: str, number: int, *, in_flow: bool = False) -> Any:
    if text.startswith('"'):
        return _parse_double_quoted(text, number)
    if text.startswith("'"):
        return _parse_single_quoted(text, number)
    if text.startswith("["):
        if in_flow:
            raise ContractError(f"line {number}: nested flow collections are not supported")
        if not text.endswith("]"):
            raise ContractError(f"line {number}: a flow list must end with ']' on the same line")
        inner = text[1:-1].strip()
        if not inner:
            return []
        values = []
        for item in _split_flow_items(inner, number):
            item = item.strip()
            if not item:
                raise ContractError(f"line {number}: empty item in a flow list")
            values.append(_parse_scalar(item, number, in_flow=True))
        return values
    if text.startswith("{"):
        raise ContractError(f"line {number}: flow mappings are not supported")
    return _parse_plain(text, number)


def _parse_block(lines: list[_Line], pos: int, indent: int) -> tuple[Any, int]:
    if lines[pos].indent != indent:
        raise ContractError(f"line {lines[pos].number}: unexpected indentation")
    if _is_sequence_item(lines[pos].text):
        return _parse_sequence(lines, pos, indent)
    return _parse_mapping(lines, pos, indent)


def _nested_value(lines: list[_Line], pos: int, parent: _Line) -> tuple[Any, int]:
    if pos >= len(lines) or lines[pos].indent <= parent.indent:
        raise ContractError(
            f"line {parent.number}: missing value (write '' or [] explicitly for empty values)"
        )
    return _parse_block(lines, pos, lines[pos].indent)


def _parse_mapping(lines: list[_Line], pos: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while pos < len(lines):
        line = lines[pos]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise ContractError(f"line {line.number}: unexpected indentation")
        if _is_sequence_item(line.text):
            raise ContractError(f"line {line.number}: a sequence item where a mapping key was expected")
        match = _KEY_ENTRY_RE.fullmatch(line.text)
        if match is None:
            raise ContractError(f"line {line.number}: expected 'key: value'")
        key, rest = match.group(1), match.group(2)
        if key in result:
            raise ContractError(f"line {line.number}: duplicate key {key!r}")
        if rest is None or not rest.strip():
            value, pos = _nested_value(lines, pos + 1, line)
        else:
            value = _parse_scalar(rest.strip(), line.number)
            pos += 1
        result[key] = value
    return result, pos


def _parse_sequence(lines: list[_Line], pos: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while pos < len(lines):
        line = lines[pos]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise ContractError(f"line {line.number}: unexpected indentation")
        if not _is_sequence_item(line.text):
            raise ContractError(f"line {line.number}: expected a '- ' sequence item")
        content = line.text[2:]
        if not content.strip():
            value, pos = _nested_value(lines, pos + 1, line)
        elif content.startswith(" "):
            raise ContractError(f"line {line.number}: use exactly one space after '-'")
        elif _is_sequence_item(content):
            raise ContractError(f"line {line.number}: nested '- -' sequences are not supported")
        elif _KEY_ENTRY_RE.fullmatch(content):
            child = [_Line(line.number, indent + 2, content), *lines[pos + 1 :]]
            value, consumed = _parse_mapping(child, 0, indent + 2)
            pos += consumed
        else:
            value = _parse_scalar(content, line.number)
            pos += 1
        items.append(value)
    return items, pos


def parse_yaml_subset(text: str) -> dict[str, Any]:
    """Parse the documented YAML subset into plain Python values."""
    lines = _logical_lines(text)
    if not lines:
        raise ContractError("the document is empty")
    if lines[0].indent != 0:
        raise ContractError(f"line {lines[0].number}: the document must start at column 0")
    if _is_sequence_item(lines[0].text):
        raise ContractError("the top level must be a mapping")
    value, pos = _parse_mapping(lines, 0, 0)
    if pos != len(lines):
        raise ContractError(f"line {lines[pos].number}: unexpected content")
    return value


# --------------------------------------------------------------------------
# Contract model and validation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class UnpaidClient:
    user_agent: str
    exempt_user_agent_substrings: tuple[str, ...]
    timeout_seconds: int
    max_body_bytes: int
    post_body: str
    post_content_type: str


@dataclass(frozen=True)
class PaymentTerms:
    x402_version: int
    scheme: str
    network: str
    asset: str
    pay_to: str


@dataclass(frozen=True)
class Check:
    id: str
    cls: str
    host: str
    path: str
    methods: tuple[str, ...]
    evidence: str
    accept: tuple[str, ...]
    rule_id: str | None = None
    price_atomic: int | None = None

    @property
    def url(self) -> str:
        return f"https://{self.host}{self.path}"


@dataclass(frozen=True)
class Contract:
    schema: str
    as_of: str
    client: UnpaidClient
    terms: PaymentTerms
    checks: tuple[Check, ...]
    sha256: str
    path: str


def _require_mapping(value: Any, where: str, allowed: frozenset[str], required: frozenset[str]) -> dict:
    if not isinstance(value, dict):
        raise ContractError(f"{where} must be a mapping")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ContractError(f"{where} has unknown keys: {', '.join(unknown)}")
    missing = sorted(required - set(value))
    if missing:
        raise ContractError(f"{where} is missing keys: {', '.join(missing)}")
    return value


def _require_str(value: Any, where: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{where} must be a non-empty string")
    if pattern is not None and not pattern.fullmatch(value):
        raise ContractError(f"{where} has an invalid value {value!r}")
    return value


def _require_int(value: Any, where: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ContractError(f"{where} must be an integer in [{low}, {high}]")
    return value


def _require_str_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ContractError(f"{where} must be a non-empty list")
    items = tuple(_require_str(item, f"{where}[{index}]") for index, item in enumerate(value))
    if len(set(items)) != len(items):
        raise ContractError(f"{where} has duplicate entries")
    return items


def _validate_client(raw: Any) -> UnpaidClient:
    data = _require_mapping(raw, "unpaid_client", CLIENT_KEYS, CLIENT_KEYS)
    user_agent = _require_str(data["user_agent"], "unpaid_client.user_agent", pattern=UA_RE)
    exempt = _require_str_list(
        data["exempt_user_agent_substrings"], "unpaid_client.exempt_user_agent_substrings"
    )
    lowered = user_agent.lower()
    for substring in exempt:
        if substring.lower() in lowered:
            raise ContractError(
                "unpaid_client.user_agent contains the paywall-exempt substring "
                f"{substring!r}; the live rules would not charge this probe"
            )
    post_body = data["post_body"]
    if not isinstance(post_body, str) or len(post_body.encode("utf-8")) > 4096:
        raise ContractError("unpaid_client.post_body must be a string of at most 4096 bytes")
    return UnpaidClient(
        user_agent=user_agent,
        exempt_user_agent_substrings=exempt,
        timeout_seconds=_require_int(data["timeout_seconds"], "unpaid_client.timeout_seconds", 1, 60),
        max_body_bytes=_require_int(
            data["max_body_bytes"], "unpaid_client.max_body_bytes", 1024, 1024 * 1024
        ),
        post_body=post_body,
        post_content_type=_require_str(
            data["post_content_type"], "unpaid_client.post_content_type", pattern=UA_RE
        ),
    )


def _validate_terms(raw: Any) -> PaymentTerms:
    data = _require_mapping(raw, "payment_terms", TERMS_KEYS, TERMS_KEYS)
    return PaymentTerms(
        x402_version=_require_int(data["x402_version"], "payment_terms.x402_version", 1, 99),
        scheme=_require_str(data["scheme"], "payment_terms.scheme", pattern=re.compile(r"[a-z]{1,32}")),
        network=_require_str(
            data["network"], "payment_terms.network", pattern=re.compile(r"[a-z0-9]{1,32}:[0-9]{1,20}")
        ),
        asset=_require_str(data["asset"], "payment_terms.asset", pattern=EVM_ADDRESS_RE),
        pay_to=_require_str(data["pay_to"], "payment_terms.pay_to", pattern=EVM_ADDRESS_RE),
    )


def _validate_check(raw: Any, index: int) -> Check:
    where = f"checks[{index}]"
    data = _require_mapping(raw, where, CHECK_KEYS, REQUIRED_CHECK_KEYS)
    check_id = _require_str(data["id"], f"{where}.id", pattern=CHECK_ID_RE)
    where = f"check {check_id!r}"
    cls = data["class"]
    if cls not in CLASSES:
        raise ContractError(f"{where}: class must be one of {', '.join(CLASSES)}")
    host = _require_str(data["host"], f"{where}.host", pattern=HOST_RE)
    path = _require_str(data["path"], f"{where}.path", pattern=PATH_RE)
    methods = _require_str_list(data["methods"], f"{where}.methods")
    for method in methods:
        if method not in METHODS:
            raise ContractError(f"{where}: method {method!r} is not one of {', '.join(METHODS)}")
    evidence = _require_str(data["evidence"], f"{where}.evidence")
    if "note" in data:
        _require_str(data["note"], f"{where}.note")
    rule_id = data.get("rule_id")
    price = data.get("price_atomic")
    if cls == "paid":
        rule_id = _require_str(rule_id, f"{where}.rule_id", pattern=RULE_ID_RE)
        price = _require_int(price, f"{where}.price_atomic", MIN_PRICE_ATOMIC, MAX_PRICE_ATOMIC)
        if "accept" in data:
            raise ContractError(f"{where}: a paid check accepts exactly 402-paywall; remove 'accept'")
        accept = DEFAULT_ACCEPT["paid"]
    else:
        if rule_id is not None or price is not None:
            raise ContractError(f"{where}: rule_id and price_atomic are only valid on paid checks")
        if "accept" in data:
            accept = _require_str_list(data["accept"], f"{where}.accept")
            unknown = [item for item in accept if item not in OUTCOMES]
            if unknown:
                raise ContractError(f"{where}: accept has invalid outcomes {unknown}")
            # accept narrows the class default. It cannot add a 402, a challenge,
            # or any other outcome the class forbids.
            allowed = DEFAULT_ACCEPT[cls]
            widened = [item for item in accept if item not in allowed]
            if widened:
                raise ContractError(
                    f"{where}: accept can only narrow the {cls} defaults "
                    f"({', '.join(allowed)}); refused {widened}"
                )
        else:
            accept = DEFAULT_ACCEPT[cls]
    return Check(
        id=check_id,
        cls=cls,
        host=host,
        path=path,
        methods=methods,
        evidence=evidence,
        accept=tuple(accept),
        rule_id=rule_id,
        price_atomic=price,
    )


def _validate_inventory(raw: Any, checks: tuple[Check, ...], unprobed: Any) -> None:
    if not isinstance(raw, list) or not raw:
        raise ContractError("rules_inventory must be a non-empty list")
    if not isinstance(unprobed, list):
        raise ContractError("unprobed_rules must be a list")
    unprobed_ids: dict[str, str] = {}
    for index, entry in enumerate(unprobed):
        data = _require_mapping(entry, f"unprobed_rules[{index}]", UNPROBED_KEYS, UNPROBED_KEYS)
        rule_id = _require_str(data["rule_id"], f"unprobed_rules[{index}].rule_id", pattern=RULE_ID_RE)
        _require_str(data["reason"], f"unprobed_rules[{index}].reason")
        if rule_id in unprobed_ids:
            raise ContractError(f"unprobed_rules lists {rule_id} twice")
        unprobed_ids[rule_id] = data["reason"]
    inventory: dict[str, dict] = {}
    for index, entry in enumerate(raw):
        data = _require_mapping(entry, f"rules_inventory[{index}]", INVENTORY_KEYS, INVENTORY_KEYS)
        rule_id = _require_str(data["rule_id"], f"rules_inventory[{index}].rule_id", pattern=RULE_ID_RE)
        if rule_id in inventory:
            raise ContractError(f"rules_inventory lists {rule_id} twice")
        _require_str(data["zone"], f"rules_inventory[{index}].zone", pattern=HOST_RE)
        _require_str(data["description"], f"rules_inventory[{index}].description")
        _require_str(data["scope"], f"rules_inventory[{index}].scope")
        _require_int(
            data["price_atomic"], f"rules_inventory[{index}].price_atomic", MIN_PRICE_ATOMIC, MAX_PRICE_ATOMIC
        )
        if data["audience"] not in AUDIENCES:
            raise ContractError(f"rules_inventory[{index}].audience must be one of {', '.join(AUDIENCES)}")
        inventory[rule_id] = data
    probed: set[str] = set()
    for check in checks:
        if check.cls != "paid":
            continue
        rule = inventory.get(check.rule_id or "")
        if rule is None:
            raise ContractError(f"check {check.id!r}: rule {check.rule_id} is not in rules_inventory")
        if rule["audience"] != "everyone":
            raise ContractError(
                f"check {check.id!r}: rule {check.rule_id} charges verified bots only; "
                "an unverified probe cannot observe it"
            )
        if rule["price_atomic"] != check.price_atomic:
            raise ContractError(
                f"check {check.id!r}: price_atomic {check.price_atomic} differs from the "
                f"inventory price {rule['price_atomic']} of rule {check.rule_id}"
            )
        probed.add(rule["rule_id"])
    for rule_id, rule in inventory.items():
        covered = rule_id in probed
        listed = rule_id in unprobed_ids
        if covered and listed:
            raise ContractError(f"rule {rule_id} is both probed and listed in unprobed_rules")
        if not covered and not listed:
            raise ContractError(f"rule {rule_id} is neither probed by a paid check nor listed in unprobed_rules")
    stray = sorted(set(unprobed_ids) - set(inventory))
    if stray:
        raise ContractError(f"unprobed_rules references rules missing from rules_inventory: {stray}")


def load_contract(path: str | os.PathLike[str]) -> Contract:
    """Read, parse and validate a contract file. Raises ContractError."""
    contract_path = Path(path)
    try:
        raw = contract_path.read_bytes()
    except OSError as exc:
        raise ContractError(f"cannot read {contract_path}: {exc.strerror or exc}") from None
    if len(raw) > MAX_CONTRACT_BYTES:
        raise ContractError(f"{contract_path} is larger than {MAX_CONTRACT_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError(f"{contract_path} is not valid UTF-8") from None
    document = parse_yaml_subset(text)
    data = _require_mapping(document, "contract", TOP_KEYS, REQUIRED_TOP_KEYS)
    if data["schema"] != CONTRACT_SCHEMA:
        raise ContractError(f"schema must be {CONTRACT_SCHEMA!r}")
    as_of = _require_str(data["as_of"], "as_of", pattern=AS_OF_RE)
    for key in ("owner_decision",):
        if key in data:
            _require_str(data[key], key)
    if "sources" in data:
        sources = data["sources"]
        if not isinstance(sources, dict) or not sources:
            raise ContractError("sources must be a non-empty mapping")
        for name, value in sources.items():
            _require_str(value, f"sources.{name}")
    if "not_covered" in data:
        if not isinstance(data["not_covered"], list):
            raise ContractError("not_covered must be a list")
        for index, entry in enumerate(data["not_covered"]):
            item = _require_mapping(entry, f"not_covered[{index}]", NOT_COVERED_KEYS, NOT_COVERED_KEYS)
            _require_str(item["target"], f"not_covered[{index}].target")
            _require_str(item["reason"], f"not_covered[{index}].reason")
    client = _validate_client(data["unpaid_client"])
    terms = _validate_terms(data["payment_terms"])
    raw_checks = data["checks"]
    if not isinstance(raw_checks, list) or not raw_checks:
        raise ContractError("checks must be a non-empty list")
    checks = tuple(_validate_check(entry, index) for index, entry in enumerate(raw_checks))
    ids = [check.id for check in checks]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise ContractError(f"duplicate check ids: {', '.join(duplicates)}")
    targets = [(check.host, check.path) for check in checks]
    if len(set(targets)) != len(targets):
        raise ContractError("two checks declare the same host and path")
    if "rules_inventory" in data or "unprobed_rules" in data:
        _validate_inventory(data.get("rules_inventory"), checks, data.get("unprobed_rules", []))
    elif any(check.cls == "paid" for check in checks):
        raise ContractError("paid checks require rules_inventory")
    return Contract(
        schema=data["schema"],
        as_of=as_of,
        client=client,
        terms=terms,
        checks=checks,
        sha256=hashlib.sha256(raw).hexdigest(),
        path=str(path),
    )


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


@dataclass
class Observation:
    status: int | None
    headers: dict[str, list[str]] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None
    elapsed_ms: int = 0

    def header(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])


def parse_connect_to(value: str) -> tuple[str, int]:
    """Parse a loopback-only HOST:PORT override used by the offline tests."""
    host, sep, port_text = value.rpartition(":")
    host = host.strip("[]")
    if not sep or not port_text.isdigit():
        raise ContractError("--connect-to must be HOST:PORT")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ContractError("--connect-to port is out of range")
    if host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ContractError("--connect-to accepts only a loopback address") from None
        if not address.is_loopback:
            raise ContractError("--connect-to accepts only a loopback address")
    return host, port


def fetch(
    method: str,
    check: Check,
    client: UnpaidClient,
    connect_to: tuple[str, int] | None = None,
) -> Observation:
    """Send one request. Live mode is HTTPS with certificate verification.

    ``connect_to`` (tests only) sends plain HTTP to a loopback stub while the
    Host header still names the contract host.
    """
    headers = {
        "Host": check.host,
        "User-Agent": client.user_agent,
        "Accept": "*/*",
        "Connection": "close",
    }
    body = None
    if method == "POST":
        body = client.post_body.encode("utf-8")
        headers["Content-Type"] = client.post_content_type
    started = time.monotonic()
    connection: http.client.HTTPConnection
    if connect_to is None:
        connection = http.client.HTTPSConnection(
            check.host, 443, timeout=client.timeout_seconds, context=ssl.create_default_context()
        )
    else:
        connection = http.client.HTTPConnection(connect_to[0], connect_to[1], timeout=client.timeout_seconds)
    try:
        connection.request(method, check.path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(client.max_body_bytes)
        collected: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            collected.setdefault(name.lower(), []).append(value)
        return Observation(
            status=response.status,
            headers=collected,
            body=payload,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except (OSError, http.client.HTTPException) as exc:
        message = f"{type(exc).__name__}: {exc}"
        return Observation(
            status=None,
            error=message[:300],
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    finally:
        connection.close()


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

_CHALLENGE_MARKERS = (
    (re.compile(rb"window\._cf_chl_opt"), "body marker window._cf_chl_opt"),
    (re.compile(rb"/cdn-cgi/challenge-platform/"), "body marker /cdn-cgi/challenge-platform/"),
    (re.compile(rb"<title>Just a moment\.\.\.</title>", re.IGNORECASE), "body title 'Just a moment...'"),
)
_BLOCK_MARKERS = (
    (re.compile(rb"error code: 10\d\d"), "body marker 'error code: 10xx'"),
    (re.compile(rb"Sorry, you have been blocked", re.IGNORECASE), "body marker 'Sorry, you have been blocked'"),
    (re.compile(rb"Attention Required! \| Cloudflare"), "body title 'Attention Required! | Cloudflare'"),
)
_CF_ERROR_PAGE_MARKERS = (
    re.compile(rb"\| 5\d\d: "),
    re.compile(rb"error code: 5\d\d"),
    re.compile(rb'id="cf-error-details"'),
)
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ORIGIN_TIMING_RE = re.compile(r"cfOrigin;dur=([0-9]+(?:\.[0-9]+)?)")


def decode_payment_required(values: list[str]) -> tuple[dict[str, Any] | None, str]:
    """Decode an x402 v2 PAYMENT-REQUIRED header. Returns (terms, problem)."""
    if not values:
        return None, "402 without a PAYMENT-REQUIRED header"
    if len(values) != 1:
        return None, f"402 with {len(values)} PAYMENT-REQUIRED headers"
    raw = values[0].strip()
    if not raw or len(raw) > MAX_PAYMENT_HEADER_CHARS:
        return None, "PAYMENT-REQUIRED header is empty or too long"
    try:
        normalized = raw.replace("-", "+").replace("_", "/")
        normalized += "=" * (-len(normalized) % 4)
        document = json.loads(base64.b64decode(normalized, validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None, "PAYMENT-REQUIRED is not base64-encoded JSON"
    if not isinstance(document, dict):
        return None, "PAYMENT-REQUIRED does not decode to a JSON object"
    version = document.get("x402Version")
    if not isinstance(version, int) or isinstance(version, bool):
        return None, "PAYMENT-REQUIRED has no integer x402Version"
    accepts = document.get("accepts")
    if not isinstance(accepts, list) or not accepts or len(accepts) > MAX_OFFERS:
        return None, "PAYMENT-REQUIRED has no usable accepts list"
    offers = []
    for entry in accepts:
        if not isinstance(entry, dict):
            return None, "PAYMENT-REQUIRED accepts entry is not an object"
        amount = entry.get("amount")
        if not isinstance(amount, str) or not re.fullmatch(r"[0-9]{1,30}", amount):
            return None, "PAYMENT-REQUIRED amount is not a decimal string of atomic units"
        offer = {"amount": int(amount)}
        for source, target in (("scheme", "scheme"), ("network", "network"), ("asset", "asset"), ("payTo", "pay_to")):
            value = entry.get(source)
            if not isinstance(value, str) or not value or len(value) > 200:
                return None, f"PAYMENT-REQUIRED offer has no {source}"
            offer[target] = value
        offers.append(offer)
    resource = document.get("resource")
    resource_url = resource.get("url") if isinstance(resource, dict) else None
    if resource_url is not None and (not isinstance(resource_url, str) or len(resource_url) > 2048):
        return None, "PAYMENT-REQUIRED resource.url is not a string"
    return {"x402_version": version, "resource_url": resource_url, "offers": offers}, ""


def classify(observation: Observation) -> tuple[str, str]:
    """Return (outcome, evidence) for one response."""
    if observation.status is None:
        return "transport-error", observation.error or "no response"
    status = observation.status
    body = observation.body
    if any(value.strip().lower() == "challenge" for value in observation.header("cf-mitigated")):
        return "challenge", "header cf-mitigated: challenge"
    if status in (403, 429, 503):
        for pattern, evidence in _CHALLENGE_MARKERS:
            if pattern.search(body):
                return "challenge", evidence
    if status == 402:
        decoded, problem = decode_payment_required(observation.header("payment-required"))
        if decoded is not None:
            return "paywall", "header PAYMENT-REQUIRED (x402)"
        return "payment-unparsed", problem
    if 200 <= status < 300:
        return "ok", ""
    if 300 <= status < 400:
        location = (observation.header("location") or [""])[0]
        if re.match(r"https://[A-Za-z0-9.-]+\.cloudflareaccess\.com/", location):
            return "access-denied", "redirect to a Cloudflare Access login"
        return "redirect", f"location {location[:200]}" if location else "no location header"
    if status == 401:
        return "origin-auth", "401 without Cloudflare challenge markers"
    if status == 403:
        if observation.header("cf-access-aud") or observation.header("cf-access-domain"):
            return "access-denied", "header cf-access-aud / cf-access-domain"
        for pattern, evidence in _BLOCK_MARKERS:
            if pattern.search(body):
                return "edge-block", evidence
        return "origin-auth", "403 without Cloudflare block, Access or challenge markers"
    if status == 404:
        return "not-found", ""
    if 400 <= status < 500:
        return "client-error", ""
    if 500 <= status < 600:
        if any(pattern.search(body) for pattern in _CF_ERROR_PAGE_MARKERS):
            return "origin-5xx", "Cloudflare error page: the edge could not get a valid origin response"
        return "origin-5xx", "5xx response body without a Cloudflare error page"
    return "unexpected-status", ""


def outcome_label(outcome: str, status: int | None) -> str:
    """The short label used at the start of every message."""
    if outcome == "paywall":
        return "402-paywall"
    if outcome == "payment-unparsed":
        return "402-unparsed"
    if outcome == "challenge":
        return f"{status}-challenge"
    if outcome == "edge-block":
        return "403-edge-block"
    if outcome == "access-denied":
        return f"{status}-access"
    if outcome == "origin-auth":
        return f"{status}-origin-auth"
    if outcome == "origin-5xx":
        return "5xx-origin"
    if outcome == "ok":
        return "2xx"
    if outcome == "redirect":
        return "3xx"
    if outcome == "not-found":
        return "404"
    if outcome == "client-error":
        return "4xx"
    if outcome == "transport-error":
        return "transport-error"
    return f"{status}-unexpected"


def _same_address(left: str, right: str) -> bool:
    return left.lower() == right.lower()


def _paid_problems(decoded: dict[str, Any], check: Check, terms: PaymentTerms) -> list[str]:
    problems = []
    if decoded["x402_version"] != terms.x402_version:
        problems.append(f"x402Version {decoded['x402_version']} != {terms.x402_version}")
    if decoded["resource_url"] != check.url:
        problems.append(f"resource.url {decoded['resource_url']!r} != probed URL {check.url!r}")
    matching = [
        offer
        for offer in decoded["offers"]
        if offer["scheme"] == terms.scheme
        and offer["network"] == terms.network
        and _same_address(offer["asset"], terms.asset)
        and _same_address(offer["pay_to"], terms.pay_to)
    ]
    if not matching:
        offered = "; ".join(
            f"{o['scheme']}/{o['network']}/{o['asset']}/{o['pay_to']}/{o['amount']}" for o in decoded["offers"]
        )
        problems.append(
            f"no offer with scheme {terms.scheme}, network {terms.network}, asset {terms.asset} "
            f"and payTo {terms.pay_to} (offered: {offered})"
        )
    else:
        amounts = sorted({offer["amount"] for offer in matching})
        if amounts != [check.price_atomic]:
            problems.append(
                f"amount {', '.join(map(str, amounts))} != rule {check.rule_id} price {check.price_atomic}"
            )
    return problems


def evaluate(check: Check, method: str, observation: Observation, terms: PaymentTerms) -> dict[str, Any]:
    """Apply the contract to one observation. Returns a receipt result row."""
    outcome, evidence = classify(observation)
    status = observation.status
    label = outcome_label(outcome, status)
    decoded = None
    if outcome == "paywall":
        decoded, _ = decode_payment_required(observation.header("payment-required"))
    verdict = "FAIL"
    # A per-check accept list can only drop defaults. Outcomes outside the class
    # default (a 402 or a challenge on a free or internal check) never pass,
    # even if a caller built the Check without the loader.
    permitted = frozenset(DEFAULT_ACCEPT[check.cls]).intersection(check.accept)
    if check.cls == "free":
        if outcome in permitted:
            verdict = "PASS"
            message = f"{label}: free surface served to an unpaid client (HTTP {status})"
        elif outcome == "paywall":
            offer = decoded["offers"][0] if decoded else {}
            message = (
                f"402-paywall: a free surface charged {offer.get('amount')} atomic units "
                f"(scheme {offer.get('scheme')}, payTo {offer.get('pay_to')}); a paywall rule now matches this URL"
            )
        elif outcome == "challenge":
            message = (
                f"{label}: Cloudflare challenged the unpaid client ({evidence}); the free surface was not "
                "served and this is bot protection, not the paywall"
            )
        elif outcome == "origin-5xx":
            message = f"5xx-origin: HTTP {status} ({evidence}); not a paywall decision"
        elif outcome == "transport-error":
            message = f"transport-error: {evidence}"
        else:
            message = f"{label}: HTTP {status} is not an accepted free-surface response ({', '.join(check.accept)})"
    elif check.cls == "paid":
        if outcome == "paywall" and decoded is not None:
            problems = _paid_problems(decoded, check, terms)
            if problems:
                message = "402-paywall with the wrong terms: " + "; ".join(problems)
            else:
                verdict = "PASS"
                message = (
                    f"402-paywall: amount {check.price_atomic} = rule {check.rule_id} price; "
                    "scheme, network, asset, payTo and resource URL match"
                )
        elif outcome == "payment-unparsed":
            message = f"402-unparsed: {evidence}"
        elif outcome == "challenge":
            message = (
                f"{label}: Cloudflare challenged the unpaid client ({evidence}) instead of answering 402; "
                "a paying agent cannot reach the paywall"
            )
        elif outcome == "transport-error":
            message = f"transport-error: {evidence}"
        elif outcome == "origin-5xx":
            message = f"5xx-origin: HTTP {status} ({evidence}); the paywall did not answer before the origin"
        elif outcome == "edge-block":
            message = f"403-edge-block: the edge blocked the request ({evidence}) instead of answering 402"
        elif outcome == "access-denied":
            message = f"{label}: Cloudflare Access refused the request ({evidence}) instead of answering 402"
        else:
            message = (
                f"{label}: {method} reached the origin unpaid (HTTP {status}); the paywall rule did not "
                f"charge this {method} request"
            )
    else:  # internal
        if outcome in permitted and status == 403:
            verdict = "PASS"
            message = f"{label}: internal path refused ({evidence})"
        elif outcome == "challenge":
            message = (
                f"{label}: a managed challenge is not a block ({evidence}); a client that solves it "
                "reaches the internal path"
            )
        elif outcome == "paywall":
            message = "402-paywall: the internal path is offered for payment instead of being blocked"
        elif outcome == "ok":
            message = f"2xx: the internal path is served to an unpaid client (HTTP {status})"
        elif outcome == "origin-5xx":
            message = f"5xx-origin: HTTP {status} ({evidence}); the edge did not block the internal path"
        elif outcome == "transport-error":
            message = f"transport-error: {evidence}"
        else:
            message = f"{label}: HTTP {status}; expected a 403 refusal that is not a challenge"
    row: dict[str, Any] = {
        "id": check.id,
        "class": check.cls,
        "method": method,
        "url": check.url,
        "verdict": verdict,
        "outcome": outcome,
        "label": label,
        "status": status,
        "message": message,
        "classification_evidence": evidence,
        "elapsed_ms": observation.elapsed_ms,
        "expected": {
            "accept": list(check.accept),
            **({"rule_id": check.rule_id, "price_atomic": check.price_atomic} if check.cls == "paid" else {}),
        },
    }
    observed: dict[str, Any] = {}
    for name in ("location", "content-type", "cf-ray", "cf-mitigated", "server"):
        values = observation.header(name)
        if values:
            observed[name] = values[0][:200]
    timing = " ".join(observation.header("server-timing"))
    match = _ORIGIN_TIMING_RE.search(timing)
    if match:
        observed["cf_origin_ms"] = float(match.group(1))
    title = _TITLE_RE.search(observation.body)
    if title:
        observed["title"] = re.sub(r"\s+", " ", title.group(1).decode("utf-8", "replace")).strip()[:120]
    if decoded is not None:
        observed["x402"] = decoded
    row["observed"] = observed
    return row


# --------------------------------------------------------------------------
# Receipt, summary and CLI
# --------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_contract(
    contract: Contract,
    *,
    connect_to: tuple[str, int] | None = None,
    only: tuple[str, ...] = (),
) -> dict[str, Any]:
    selected = [check for check in contract.checks if not only or check.id in only]
    missing = sorted(set(only) - {check.id for check in contract.checks})
    if missing:
        raise ContractError(f"--only names unknown checks: {', '.join(missing)}")
    started = _utc_now()
    results = []
    for check in selected:
        for method in check.methods:
            observation = fetch(method, check, contract.client, connect_to)
            results.append(evaluate(check, method, observation, contract.terms))
    failed = [row for row in results if row["verdict"] != "PASS"]
    by_label: dict[str, int] = {}
    for row in failed:
        by_label[row["label"]] = by_label.get(row["label"], 0) + 1
    source = {
        key: os.environ[env]
        for key, env in (
            ("repository", "GITHUB_REPOSITORY"),
            ("sha", "GITHUB_SHA"),
            ("ref", "GITHUB_REF"),
            ("workflow", "GITHUB_WORKFLOW"),
            ("event", "GITHUB_EVENT_NAME"),
            ("run_id", "GITHUB_RUN_ID"),
            ("run_attempt", "GITHUB_RUN_ATTEMPT"),
        )
        if os.environ.get(env)
    }
    return {
        "schema": RECEIPT_SCHEMA,
        "verdict": "FAIL" if failed else "PASS",
        "exit_code": 1 if failed else 0,
        "started_at": started,
        "completed_at": _utc_now(),
        "transport": "loopback-override" if connect_to else "direct-https",
        "selection": "subset" if only else "all",
        "contract": {
            "path": contract.path,
            "sha256": contract.sha256,
            "schema": contract.schema,
            "as_of": contract.as_of,
        },
        "user_agent": contract.client.user_agent,
        "source": source,
        "summary": {
            "requests": len(results),
            "passed": len(results) - len(failed),
            "failed": len(failed),
            "failed_by_label": dict(sorted(by_label.items())),
        },
        "results": results,
    }


def write_receipt(receipt: dict[str, Any], path: str | os.PathLike[str]) -> str:
    """Atomically write the receipt and its sha256 sidecar. Returns the digest."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    for destination, payload in (
        (target, data),
        (target.with_name(target.name + ".sha256"), f"{digest}  {target.name}\n".encode("ascii")),
    ):
        handle, temporary = tempfile.mkstemp(dir=destination.parent, prefix=f".{destination.name}.")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
    return digest


def _markdown_cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_summary(receipt: dict[str, Any]) -> str:
    summary = receipt["summary"]
    lines = [
        f"## Edge contract: {receipt['verdict']}",
        "",
        f"{summary['passed']} of {summary['requests']} unpaid requests met the contract "
        f"(`{receipt['contract']['path']}` sha256 `{receipt['contract']['sha256'][:12]}`, "
        f"transport {receipt['transport']}).",
        "",
        "| Verdict | Method | URL | Status | Message |",
        "|---|---|---|---|---|",
    ]
    ordered = sorted(receipt["results"], key=lambda row: (row["verdict"] == "PASS", row["id"], row["method"]))
    for row in ordered:
        lines.append(
            "| {verdict} | {method} | {url} | {status} | {message} |".format(
                verdict=row["verdict"],
                method=row["method"],
                url=_markdown_cell(row["url"]),
                status=row["status"] if row["status"] is not None else "-",
                message=_markdown_cell(row["message"]),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--contract", default=DEFAULT_CONTRACT, help="contract file (default: %(default)s)")
    parser.add_argument("--receipt", default=DEFAULT_RECEIPT, help="receipt path (default: %(default)s)")
    parser.add_argument("--only", action="append", default=[], metavar="CHECK_ID", help="run only this check (repeatable)")
    parser.add_argument(
        "--connect-to",
        metavar="HOST:PORT",
        help="tests only: send plain HTTP to this loopback address, keeping the contract Host header",
    )
    parser.add_argument("--validate-only", action="store_true", help="validate the contract and exit")
    args = parser.parse_args(argv)
    try:
        contract = load_contract(args.contract)
        if args.validate_only:
            print(f"contract OK: {len(contract.checks)} checks, sha256 {contract.sha256}")
            return 0
        connect_to = parse_connect_to(args.connect_to) if args.connect_to else None
        receipt = run_contract(contract, connect_to=connect_to, only=tuple(args.only))
    except ContractError as exc:
        print(f"edge contract invalid: {exc}", file=sys.stderr)
        return 2
    for row in receipt["results"]:
        print(f"{row['verdict']}  {row['class']:<8} {row['method']:<4} {row['url']}  {row['message']}")
    digest = write_receipt(receipt, args.receipt)
    summary = receipt["summary"]
    print(
        f"edge contract {receipt['verdict']}: {summary['passed']}/{summary['requests']} requests passed; "
        f"receipt {args.receipt} sha256 {digest}"
    )
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as stream:
            stream.write(render_summary(receipt))
    return receipt["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
