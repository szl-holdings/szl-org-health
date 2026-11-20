"""Offline, fail-closed triage for externally researched software ideas.

The input is an untrusted research declaration, not license verification,
independent review, source authentication, deployment or training authorization.

No network, subprocess, filesystem mutations, provider tokens or model calls.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

SCHEMA = "szl.open_source_frontier_candidate.v1"
MAX_BYTES = 16 * 1024
ALLOWED_LICENSES = frozenset({"MIT", "Apache-2.0", "BSD-3-Clause"})
MAX_EVIDENCE_AGE = timedelta(days=90)
MAX_FUTURE_SKEW = timedelta(minutes=5)
_REPO_PATH = re.compile(r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")
_FULL_SHA = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_LICENSE_PATH = re.compile(r"(?:LICENSE|LICENSE\.(?:md|txt)|COPYING|COPYING\.(?:md|txt))\Z", re.IGNORECASE)
_PROPOSAL_APPROACHES = frozenset({"study_only", "dependency_proposal", "fork_proposal", "clean_room_proposal"})


class DuplicateKey(ValueError):
    """Reject ambiguous JSON objects instead of choosing last-key-wins."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey("duplicate key")
        out[key] = value
    return out


def _reject_constant(_: str) -> object:
    raise ValueError("nonstandard JSON constant")


def parse(raw: bytes) -> object:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        raise ValueError("empty, oversize, or non-byte input")
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_reject_constant,
            parse_int=_reject_constant,
        )
    except RecursionError:
        raise ValueError("nesting limit exceeded") from None


def _exact_keys(obj: object, keys: set[str]) -> bool:
    return type(obj) is dict and set(obj) == keys


def _valid_str(value: object, max_len: int = 300) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= max_len and not any(ord(c) < 32 for c in value)


def _repo_url(value: object) -> tuple[str, str] | None:
    if not _valid_str(value, 180):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if (
        parts.scheme != "https"
        or parts.netloc != "github.com"
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        return None
    match = _REPO_PATH.fullmatch(parts.path)
    if not match:
        return None
    owner, name = match.groups()
    if owner in {".", ".."} or name in {".", ".."} or name.endswith(".git"):
        return None
    return owner, name


def _date(value: object) -> datetime | None:
    if type(value) is not str or not value.endswith("Z"):
        return None
    try:
        d = datetime.fromisoformat(value)
        return d if d.utcoffset() == timedelta(0) else None
    except ValueError:
        return None


def evaluate(candidate: object, *, now: datetime | None = None) -> dict[str, object]:
    """Classify *declarations* only. No output of this function grants admission."""
    if now is None:
        now = datetime.now(UTC)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")
    problems: list[str] = []
    if not _exact_keys(candidate, {"schema", "upstream", "proposal"}):
        problems.append("INVALID_TOP_LEVEL_SHAPE")
        return _out(problems)
    if candidate["schema"] != SCHEMA:
        problems.append("UNKNOWN_SCHEMA")
    upstream = candidate["upstream"]
    proposal = candidate["proposal"]
    expected_upstream = {"repo_url", "commit_sha", "declared_spdx", "license_path", "license_sha256", "observed_at_utc"}
    expected_proposal = {"szl_component", "approach", "hypothesis", "negative_test"}
    if not _exact_keys(upstream, expected_upstream):
        problems.append("INVALID_UPSTREAM_SHAPE")
    if not _exact_keys(proposal, expected_proposal):
        problems.append("INVALID_PROPOSAL_SHAPE")
    if problems:
        return _out(problems)
    repo = _repo_url(upstream["repo_url"])
    if not repo:
        problems.append("INVALID_UPSTREAM_URL")
    sha = upstream["commit_sha"]
    if type(sha) is not str or not _FULL_SHA.fullmatch(sha):
        problems.append("UNPINNED_SOURCE")
    lic = upstream["declared_spdx"]
    if type(lic) is not str or lic not in ALLOWED_LICENSES:
        problems.append("LICENSE_REVIEW_REQUIRED")
    licpath = upstream["license_path"]
    if type(licpath) is not str or not _LICENSE_PATH.fullmatch(licpath):
        problems.append("LICENSE_PATH_UNVERIFIABLE")
    digest = upstream["license_sha256"]
    if type(digest) is not str or not _DIGEST.fullmatch(digest):
        problems.append("LICENSE_DIGEST_MISSING")
    observed = _date(upstream["observed_at_utc"])
    if observed is None:
        problems.append("INVALID_OBSERVATION_TIME")
    elif observed - now > MAX_FUTURE_SKEW or now - observed > MAX_EVIDENCE_AGE:
        problems.append("STALE_OR_FUTURE_EVIDENCE")
    if not _valid_str(proposal["szl_component"], 100) or not re.fullmatch(
        r"[a-z][a-z0-9-]{1,63}", str(proposal["szl_component"])
    ):
        problems.append("INVALID_COMPONENT")
    if type(proposal["approach"]) is not str or proposal["approach"] not in _PROPOSAL_APPROACHES:
        problems.append("INVALID_APPROACH")
    if not _valid_str(proposal["hypothesis"], 600):
        problems.append("MISSING_HYPOTHESIS")
    if not _valid_str(proposal["negative_test"], 600):
        problems.append("MISSING_NEGATIVE_TEST")
    return _out(problems)


def _out(problems: list[str]) -> dict[str, object]:
    return {
        "schema": "szl.open_source_frontier_admission_result.v1",
        "classification": "HOLD" if problems else "RESEARCH_CANDIDATE_ONLY",
        "reasons": sorted(set(problems)),
        "source_authenticated": False,
        "license_independently_verified": False,
        "legal_review_completed": False,
        "agent_review_authenticated": False,
        "tests_executed": False,
        "code_copy_authorized": False,
        "merge_authorized": False,
        "deployment_authorized": False,
        "training_authorized": False,
    }


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    try:
        verdict = evaluate(parse(raw))
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        verdict = _out(["INVALID_INPUT"])
    sys.stdout.write(json.dumps(verdict, sort_keys=True) + "\n")
    return 78 if verdict["classification"] == "HOLD" else 0


if __name__ == "__main__":
    raise SystemExit(main())
