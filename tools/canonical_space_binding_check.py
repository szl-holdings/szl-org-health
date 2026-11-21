"""Offline, fail-closed reconciliation of a dated Space inventory to GitHub authority.

No network calls, provider mutations, Space restarts, credentials, or releases.
The canonical source is a separately supplied, blob-hash-verified version of
szl-holdings/.github:estate/alignment.v1.json. Never substitute a Space name
match or an HTTP 200 for immutable source/runtime deployment evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SCHEMA = "szl.canonical-space-authority-reconciliation/v1"
ALIGNMENT_SCHEMA = "szl.estate.alignment/v1"
CANONICAL_SIX = frozenset({"a11oy", "killinchu", "terra", "counsel", "finance", "lyte"})
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"szl-holdings/[a-zA-Z0-9_.-]+\Z")
SPACE = re.compile(r"szlholdings/[a-zA-Z0-9_.-]+\Z", re.I)
SLUG = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
MAX_MANIFEST = 64 * 1024
MAX_INVENTORY = 1024 * 1024


class ContractError(ValueError):
    """Fail closed on ambiguous, truncated, conflicting or unpinned evidence."""


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ContractError("DUPLICATE_JSON_KEY")
        obj[key] = value
    return obj


def _reject_constant(_value):
    raise ContractError("INVALID_JSON_CONSTANT")


def _blob_sha(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def declared_sources(raw: bytes, expected_blob_sha: str) -> dict[str, dict]:
    """Validate one pinned Git blob, returning declaration only, never runtime."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_MANIFEST:
        raise ContractError("MISSING_OR_UNBOUNDED_ALIGNMENT")
    if not isinstance(expected_blob_sha, str) or not SHA40.fullmatch(expected_blob_sha):
        raise ContractError("MISSING_EXACT_BLOB_PIN")
    if _blob_sha(raw) != expected_blob_sha:
        raise ContractError("ALIGNMENT_BLOB_MISMATCH")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("MALFORMED_ALIGNMENT") from exc
    if not isinstance(value, dict) or value.get("schema") != ALIGNMENT_SCHEMA:
        raise ContractError("UNRECOGNIZED_ALIGNMENT_SCHEMA")
    if value.get("github_org") != "szl-holdings" or value.get("hub_org") != "SZLHOLDINGS":
        raise ContractError("AUTHORITY_ORG_MISMATCH")
    alias = value.get("hub_alias_policy")
    if not isinstance(alias, dict):
        raise ContractError("MISSING_ALIAS_POLICY")
    if alias.get("duplicate_authority_spaces_forbidden") is not True:
        raise ContractError("DUPLICATE_AUTHORITY_NOT_FORBIDDEN")
    slugs = alias.get("canonical_public_space_slugs")
    if (
        not isinstance(slugs, list)
        or not all(isinstance(x, str) and SLUG.fullmatch(x) for x in slugs)
        or len(slugs) != len(set(slugs))
        or set(slugs) != CANONICAL_SIX
    ):
        raise ContractError("AMBIGUOUS_CANONICAL_SPACE_SET")
    authority = value.get("authority")
    if not isinstance(authority, dict) or authority.get("governed_fabric") != "szl-holdings/a11oy":
        raise ContractError("UNRECOGNIZED_GOVERNED_FABRIC")
    bodies = value.get("public_bodies")
    if not isinstance(bodies, list) or len(bodies) != 5:
        raise ContractError("MISSING_CANONICAL_BODIES")
    sources = {
        "a11oy": {
            "space": "SZLHOLDINGS/a11oy",
            "backend_source": authority["governed_fabric"],
            "publisher_workflow": "NOT_SPECIFIED",
        }
    }
    seen_body_ids = set()
    for body in bodies:
        if not isinstance(body, dict):
            raise ContractError("INVALID_BODY")
        body_id, surface, repo = (
            body.get("id"), body.get("hub_surface"), body.get("backend_source")
        )
        if (
            not isinstance(body_id, str)
            or not isinstance(surface, str)
            or not SPACE.fullmatch(surface)
            or not isinstance(repo, str)
            or not REPO.fullmatch(repo)
        ):
            raise ContractError("INVALID_BODY_SOURCE_OR_SURFACE")
        slug = surface.split("/", 1)[1]
        if slug not in CANONICAL_SIX - {"a11oy"} or slug in sources:
            raise ContractError("DUPLICATE_OR_NONCANONICAL_BODY_SURFACE")
        if body_id in seen_body_ids:
            raise ContractError("DUPLICATE_BODY_ID")
        seen_body_ids.add(body_id)
        publisher = body.get("publisher_workflow", "NOT_SPECIFIED")
        if not isinstance(publisher, str) or (
            publisher != "NOT_SPECIFIED"
            and not publisher.startswith("szl-holdings/a11oy:.github/workflows/")
        ):
            raise ContractError("UNTRUSTED_PUBLISHER_DECLARATION")
        sources[slug] = {
            "space": "SZLHOLDINGS/" + slug,
            "backend_source": repo,
            "publisher_workflow": publisher,
        }
    if set(sources) != CANONICAL_SIX:
        raise ContractError("INCOMPLETE_CANONICAL_BODY_SET")
    return sources


def inventory_rows(raw: bytes) -> dict[str, dict]:
    """Read only the six-column historical Markdown table; exclude private rows."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_INVENTORY:
        raise ContractError("MISSING_OR_UNBOUNDED_INVENTORY")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ContractError("INVALID_INVENTORY_ENCODING") from exc
    expected_header = ["Space", "Visibility", "SDK", "Stage", "Source repo", "Match"]
    in_table = False
    rows = {}
    for line in lines:
        if not line.startswith("|"):
            if in_table:
                break
            continue
        cols = [part.strip() for part in line.strip().strip("|").split("|")]
        if cols == expected_header:
            if in_table:
                raise ContractError("DUPLICATE_TABLE_HEADER")
            in_table = True
            continue
        if not in_table or all(re.fullmatch(r":?-+:?", col) for col in cols):
            continue
        if len(cols) != 6:
            raise ContractError("BAD_INVENTORY_ROW")
        slug, visibility, _sdk, _stage, repository, match = cols
        if not SLUG.fullmatch(slug):
            raise ContractError("INVALID_INVENTORY_SLUG")
        if slug in rows:
            raise ContractError("DUPLICATE_INVENTORY_SLUG")
        rows[slug] = {"visibility": visibility, "source_repo": repository, "match": match}
    if not in_table:
        raise ContractError("INVENTORY_TABLE_NOT_FOUND")
    return rows


def reconcile(alignment: bytes, blob_sha: str, inventory: bytes) -> dict:
    """Return only canonical six public authority findings; no release claim."""
    sources = declared_sources(alignment, blob_sha)
    rows = inventory_rows(inventory)
    findings = []
    for slug in sorted(CANONICAL_SIX):
        expected = sources[slug]
        observed = rows.get(slug)
        if observed is None:
            state, heuristic = "HOLD_MISSING_INVENTORY_ROW", "UNKNOWN"
        elif observed["visibility"] != "public":
            state, heuristic = "HOLD_VISIBILITY_UNVERIFIED", "UNKNOWN"
        else:
            heuristic = observed["source_repo"]
            repo = heuristic
            if repo != "-" and "/" not in repo:
                repo = "szl-holdings/" + repo
            if repo == expected["backend_source"]:
                state = "CANONICAL_DECLARATION_AGREES_ONLY"
            elif repo == "-":
                state = "HOLD_HEURISTIC_UNBOUND"
            else:
                state = "HOLD_HEURISTIC_CONFLICT"
        findings.append({
            "space": expected["space"],
            "governance_backend_source": expected["backend_source"],
            "historical_heuristic_source": heuristic,
            "declaration_state": state,
            "runtime_source_parity": "UNVERIFIED",
            "live_route_health": "NOT_CHECKED",
            "training_and_production_authorized": False,
        })
    count = sum(x["declaration_state"].startswith("HOLD") for x in findings)
    return {
        "schema": SCHEMA,
        "canonical_governance_blob_sha": blob_sha,
        "scope": "SIX_PUBLIC_CANONICAL_SPACES_DECLARATIONS_ONLY",
        "state": "HOLD_REGISTRY_DRIFT" if count else "DECLARATIONS_RECONCILED_ONLY",
        "drift_count": count,
        "findings": findings,
        "hub_writes": False,
        "publisher_dispatch": False,
        "release_authorized": False,
        "model_training_authorized": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alignment", type=Path, required=True)
    parser.add_argument("--alignment-blob-sha", required=True)
    parser.add_argument("--inventory", type=Path, default=Path("SPACES.md"))
    args = parser.parse_args(argv)
    try:
        raw_manifest = args.alignment.read_bytes()
        raw_inventory = args.inventory.read_bytes()
        result = reconcile(raw_manifest, args.alignment_blob_sha, raw_inventory)
        status = 78 if result["drift_count"] else 0
    except (OSError, ContractError) as exc:
        # Do not print arbitrary input paths, bodies, or exception details.
        result, status = {
            "schema": SCHEMA,
            "state": "HOLD_UNAVAILABLE_OR_INVALID_EVIDENCE",
            "reason": "UNAVAILABLE" if isinstance(exc, OSError) else str(exc),
            "release_authorized": False,
            "hub_writes": False,
        }, 78
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
