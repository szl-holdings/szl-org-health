#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Shared strict helpers for the SZL Ouroboros braid v2 tools.

Canonical JSON, float-free strict loading, create-exclusive output and exact
rational text. Nothing here opens a network connection, runs a subprocess,
signs anything or grants authority. A digest computed here is an identifier
for bytes, NOT a signature and NOT evidence of who produced them.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_catalog_admission import InputError

SHA64 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"szl-holdings/[A-Za-z0-9_.-]{1,80}\Z")
REL_PATH = re.compile(r"[A-Za-z0-9_.+@-]+(?:/[A-Za-z0-9_.+@-]+)*\Z")
RATIONAL = re.compile(r"(0|[1-9][0-9]{0,400})/([1-9][0-9]{0,400})\Z")
FIXED_DOCTRINE = "bounded, terminating, receipt-closed"
GENESIS = "0" * 64
MAX_JSON_DEPTH = 64


def require(condition, code):
    """Raise the typed refusal ``code`` unless ``condition`` holds."""
    if not condition:
        raise InputError(code)


def canonical(value) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, ASCII only.

    Byte-identical to the v1 braid's ``canonical`` so v1 and v2 digests of the
    same value agree. Floats are refused because their text form is not a
    stable identity; exact rationals travel as "p/q" strings instead.
    """
    _refuse_floats(value, 0)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _refuse_floats(value, depth):
    require(depth <= MAX_JSON_DEPTH, "JSON_DEPTH_EXCEEDED")
    kind = type(value)
    if kind is float:
        raise InputError("FLOAT_VALUE_REFUSED")
    if kind is dict:
        for key, item in value.items():
            require(type(key) is str, "JSON_KEY_NOT_TEXT")
            _refuse_floats(item, depth + 1)
    elif kind in (list, tuple):
        for item in value:
            _refuse_floats(item, depth + 1)
    else:
        require(value is None or kind in (str, int, bool), "JSON_VALUE_TYPE_REFUSED")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value) -> str:
    """SHA-256 over the canonical JSON of ``value``."""
    return sha256_hex(canonical(value))


def git_blob_sha1(raw: bytes) -> str:
    """Git's blob object id. A source-object identifier, not a security digest."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
                        usedforsecurity=False).hexdigest()


def _unique(pairs):
    out = {}
    for key, item in pairs:
        if key in out:
            raise InputError("DUPLICATE_JSON_KEY")
        out[key] = item
    return out


def _no_constant(_):
    raise InputError("NONFINITE_JSON_VALUE")


def _no_float(_):
    raise InputError("FLOAT_VALUE_REFUSED")


def strict_json(raw: bytes, *, max_bytes: int):
    """Parse bounded JSON refusing duplicate keys, NaN/Infinity and floats."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= max_bytes, "INPUT_SIZE_INVALID")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique,
                           parse_constant=_no_constant, parse_float=_no_float)
    except InputError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise InputError("INVALID_JSON") from None
    _refuse_floats(value, 0)
    return value


def read_json(path: Path, *, max_bytes: int):
    """Read one regular, non-symlink JSON file. Returns ``(value, sha256_of_bytes)``."""
    require(isinstance(path, Path), "SOURCE_FILE_UNAVAILABLE")
    require(not path.is_symlink() and path.is_file(), "SOURCE_FILE_UNAVAILABLE")
    require(0 < path.stat().st_size <= max_bytes, "INPUT_SIZE_INVALID")
    raw = path.read_bytes()
    return strict_json(raw, max_bytes=max_bytes), sha256_hex(raw)


def write_exclusive(path: Path, value, *, max_bytes: int, checkout: Path | None = None) -> str:
    """Create ``path`` (never overwrite) holding canonical JSON plus a newline.

    Refuses an existing path, a symlink, a missing parent, and any location
    inside ``checkout`` so evidence is never written into a source tree.
    Returns the SHA-256 of the bytes written.
    """
    require(isinstance(path, Path), "OUTPUT_PATH_DENIED")
    require(not path.is_symlink() and not path.exists() and path.parent.is_dir(),
            "OUTPUT_PATH_DENIED")
    if checkout is not None:
        require(not path.resolve().is_relative_to(checkout.resolve()), "OUTPUT_PATH_DENIED")
    raw = canonical(value) + b"\n"
    require(len(raw) <= max_bytes, "OUTPUT_TOO_LARGE")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
    return sha256_hex(raw)


def checkout_root() -> Path:
    """The source tree this tool lives in; outputs must stay outside it."""
    return Path(__file__).resolve().parent.parent


def rational_text(value: Fraction) -> str:
    """Lowest-terms "p/q" text for a non-negative exact rational."""
    require(type(value) is Fraction and value >= 0, "RATIONAL_INVALID")
    return f"{value.numerator}/{value.denominator}"


def parse_rational(text) -> Fraction:
    """Parse lowest-terms "p/q" text. Rejects floats, signs, spaces and non-reduced forms."""
    require(type(text) is str and len(text) <= 810, "RATIONAL_INVALID")
    match = RATIONAL.fullmatch(text)
    require(match is not None, "RATIONAL_INVALID")
    value = Fraction(int(match.group(1)), int(match.group(2)))
    require(rational_text(value) == text, "RATIONAL_NOT_REDUCED")
    return value


def natural(value, code="NATURAL_INVALID", *, maximum=10 ** 15) -> int:
    """A non-negative ``int`` that is not a ``bool`` and is within ``maximum``."""
    require(type(value) is int and 0 <= value <= maximum, code)
    return value


def closed(value, fields, code):
    """Require a ``dict`` whose key set is exactly ``fields``."""
    require(type(value) is dict and set(value) == set(fields), code)
    return value


def lean_code_only(text: str) -> str:
    """Lean source with comments removed (nested ``/- -/`` blocks and ``--`` lines)."""
    out, depth, i, size = [], 0, 0, len(text)
    while i < size:
        pair = text[i:i + 2]
        if pair == "/-":
            depth += 1
            i += 2
        elif pair == "-/" and depth:
            depth -= 1
            i += 2
        elif depth:
            i += 1
        elif pair == "--":
            end = text.find("\n", i)
            i = size if end < 0 else end
        else:
            out.append(text[i])
            i += 1
    return "".join(out)
