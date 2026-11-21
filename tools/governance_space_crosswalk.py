"""Read-only, fail-closed canonical GitHub -> HF Space vertical binding.

This is a governance declaration, not evidence of a deployed or healthy Space.
Use the exact GitHub-owned alignment.v1.json bytes as input; no network calls.
"""
from __future__ import annotations

import hashlib
import json
import re

SCHEMA = "szl.vertical-crosswalk/v1"
SPACE = re.compile(r"^SZLHOLDINGS/[a-z0-9][a-z0-9._-]{0,98}$")
REPO = re.compile(r"^szl-holdings/[a-z0-9][a-z0-9._-]{0,98}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


class BindingHold(ValueError):
    """The declaration cannot be used as trusted binding evidence."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise BindingHold(reason)


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _nonfinite(_value):
    raise BindingHold("NONFINITE_JSON")


def read_manifest(raw: bytes) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= 1_000_000, "INPUT_BUDGET")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, BindingHold):
            raise
        raise BindingHold("INVALID_JSON") from None
    _require(type(document) is dict, "INVALID_MANIFEST")
    return document


def crosswalk(manifest: dict, public_spaces: list[dict], *,
              manifest_commit: str, manifest_blob: str, raw_manifest: bytes) -> dict:
    """Return exact declarations and explicit unverified runtime state."""
    _require(type(manifest_commit) is str and SHA.fullmatch(manifest_commit) is not None
             and manifest_commit != "0" * 40, "UNPINNED_GITHUB_COMMIT")
    _require(type(manifest_blob) is str and SHA.fullmatch(manifest_blob) is not None,
             "UNPINNED_MANIFEST_BLOB")
    observed_blob = hashlib.sha1(
        f"blob {len(raw_manifest)}\0".encode() + raw_manifest
    ).hexdigest()
    _require(observed_blob == manifest_blob, "MANIFEST_BYTES_MISMATCH")
    _require(manifest.get("schema") == "szl.estate.alignment/v1"
             and manifest.get("github_org") == "szl-holdings"
             and manifest.get("hub_org") == "SZLHOLDINGS", "INVALID_AUTHORITY")
    policy = manifest.get("hub_alias_policy")
    _require(type(policy) is dict
             and policy.get("duplicate_authority_spaces_forbidden") is True,
             "INVALID_ALIAS_POLICY")
    canonical = policy.get("canonical_public_space_slugs")
    _require(type(canonical) is list and all(type(x) is str for x in canonical)
             and len(set(canonical)) == len(canonical), "INVALID_CANONICAL_SLUGS")
    bodies = manifest.get("public_bodies")
    _require(type(bodies) is list and 0 < len(bodies) <= 64, "INVALID_PUBLIC_BODIES")
    _require(type(public_spaces) is list and len(public_spaces) <= 3000,
             "INVALID_SPACE_SNAPSHOT")
    visible = {}
    for row in public_spaces:
        _require(type(row) is dict and type(row.get("id")) is str
                 and SPACE.fullmatch(row["id"]) is not None,
                 "INVALID_SPACE_ROW")
        key = row["id"].casefold()
        _require(key not in visible, "DUPLICATE_SPACE_ROW")
        # No private asset metadata is exported through this public crosswalk.
        _require(row.get("private") is False, "PRIVATE_OR_UNKNOWN_VISIBILITY")
        visible[key] = row
    bound = []
    seen = set()
    for body in bodies:
        _require(type(body) is dict, "INVALID_BODY")
        hub = body.get("hub_surface")
        backend = body.get("backend_source")
        _require(type(hub) is str and SPACE.fullmatch(hub) is not None
                 and hub.split("/", 1)[1] in canonical
                 and type(backend) is str and REPO.fullmatch(backend) is not None,
                 "INVALID_BODY_AUTHORITY")
        _require(hub.casefold() not in seen, "DUPLICATE_CANONICAL_OWNER")
        seen.add(hub.casefold())
        row = visible.get(hub.casefold())
        sha = row.get("sha") if row is not None else None
        revision = sha if type(sha) is str and SHA.fullmatch(sha) else None
        bound.append({
            "hub_surface": hub, "backend_source": backend,
            "presentation_source": body.get("presentation_source"),
            "publisher_workflow": body.get("publisher_workflow"),
            "binding_state": "GOVERNANCE_DECLARED_NOT_RUNTIME_PROVED"
                if revision is not None else "HF_REVISION_UNVERIFIED",
            "observed_hf_revision": revision,
            "source_parity_verified": False,
            "frontend_backend_verified": False,
            "release_authorized": False,
        })
    return {
        "schema": SCHEMA,
        "manifest_commit": manifest_commit,
        "manifest_blob": manifest_blob,
        "manifest_source_authenticated": False,
        "public_space_snapshot_complete": False,
        "canonical_bodies": len(bound),
        "release_authorized": False,
        "bindings": sorted(bound, key=lambda x: x["hub_surface"]),
    }
