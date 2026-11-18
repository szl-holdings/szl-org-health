#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only GitHub blob identity observer for the SZL Ouroboros DB braid.

Only fetches the exact commit/path allowlist in the reviewed policy. No source
content is written to evidence. No passwords, shell execution of repository
code, Hugging Face loaders, Lake writes or formal proof checks.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

try:
    from tools.database_catalog_admission import read_file, InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_catalog_admission import read_file, InputError

SCHEMA = "szl.database-ouroboros-source-readback/v1"
POLICY_SCHEMA = "szl.database-ouroboros-braid-policy/v1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SOURCE = re.compile(r"szl-holdings/[A-Za-z0-9_.-]{1,80}\Z")
PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
LABEL = re.compile(r"[a-z_]{3,50}\Z")
TIERS = frozenset({"CODE", "LEAN_CARRIER", "FORMULA_REGISTRY",
                   "HISTORICAL_LINEAGE", "RESEARCH_SCOPE"})
MAX_BODY_BYTES = 512_000
MAX_JSON_BYTES = 850_000
FIXED_DOCTRINE = "bounded, terminating, receipt-closed"


def refuse(code):
    raise InputError(code)


def require(condition, code):
    if not condition:
        refuse(code)


def validate_policy(policy):
    fields = {
        "schema", "doctrine", "max_steps", "source_owner", "source_refs",
        "source_refs_required", "khipu_conservation", "lambda_claim",
        "lean_proof_admission", "hatun_effect_authority",
        "lake_receipt_emission", "archaeological_data_rights",
        "external_effects",
    }
    require(type(policy) is dict and set(policy) == fields,
            "BRAID_POLICY_FIELDS_INVALID")
    require(policy["schema"] == POLICY_SCHEMA and
            policy["doctrine"] == FIXED_DOCTRINE and
            policy["source_owner"] == "szl-holdings/szl-org-health" and
            type(policy["max_steps"]) is int and policy["max_steps"] == 5,
            "BRAID_POLICY_INVALID")
    fixed = {
        "khipu_conservation": "ONE_UNIT_PER_PRESENT_PINNED_SOURCE",
        "lambda_claim": "UNCONDITIONAL_UNIQUENESS_DISPROVEN_AS_STATED",
        "lean_proof_admission": "NOT_EXECUTED_THIS_RUN",
        "hatun_effect_authority": "NOT_ATTACHED",
        "lake_receipt_emission": "NOT_EMITTED",
        "archaeological_data_rights": "NOT_GRANTED",
        "external_effects": "DENIED",
    }
    require(all(policy[k] == v for k, v in fixed.items()),
            "BRAID_AUTHORITY_CLAIM_REFUSED")
    refs = policy["source_refs"]
    require(type(refs) is list and 10 <= len(refs) <= 20 and
            type(policy["source_refs_required"]) is int and
            policy["source_refs_required"] == len(refs),
            "BRAID_SOURCE_COVERAGE_INVALID")
    ids = []
    for entry in refs:
        require(type(entry) is dict and set(entry) == {
            "id", "repository", "commit", "path", "blob_sha1", "tier"},
            "BRAID_SOURCE_FIELDS_INVALID")
        require(type(entry["id"]) is str and LABEL.fullmatch(entry["id"])
                and type(entry["repository"]) is str
                and SOURCE.fullmatch(entry["repository"]) is not None
                and type(entry["commit"]) is str
                and SHA40.fullmatch(entry["commit"]) is not None
                and type(entry["blob_sha1"]) is str
                and SHA40.fullmatch(entry["blob_sha1"]) is not None
                and type(entry["path"]) is str
                and PATH.fullmatch(entry["path"]) is not None
                and entry["tier"] in TIERS,
                "BRAID_SOURCE_PIN_INVALID")
        ids.append(entry["id"])
    require(ids == sorted(set(ids)), "BRAID_SOURCE_ORDER_OR_DUPLICATE")
    must_have = {
        "ouroboros_kernel", "hatun_governance", "hatun_loop",
        "khipu_loop", "khipu_math", "lake_pcgi", "lean_khipu",
        "lean_cross_component", "formula_reference", "formula_atlas",
        "invariants_kernel", "ancient_lineage", "lean_experimental_scope",
        "db_agent_planner",
    }
    require(set(ids) == must_have, "BRAID_SOURCE_FAMILY_INCOMPLETE")
    return refs


def _fetch_from_github(entry, *, timeout_seconds=18):
    repo_path = entry["repository"]
    path = entry["path"]
    sha = entry["commit"]
    url = f"repos/{repo_path}/contents/{path}?ref={sha}"
    proc = subprocess.run(
        ["gh", "api", url],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        timeout=timeout_seconds,
    )
    if proc.returncode != 0 or len(proc.stdout) > MAX_JSON_BYTES:
        raise RuntimeError("GITHUB_SOURCE_UNAVAILABLE")
    return json.loads(proc.stdout)


def inspect(entry, *, fetch=_fetch_from_github):
    row = {
        "id": entry["id"], "repository": entry["repository"],
        "commit": entry["commit"], "path": entry["path"],
        "blob_sha1": entry["blob_sha1"], "tier": entry["tier"],
        "status": "UNAVAILABLE", "byte_length": None,
        "content_sha256": None,
    }
    try:
        metadata = fetch(entry)
        if type(metadata) is not dict or metadata.get("type") != "file":
            return row
        if (metadata.get("sha") != entry["blob_sha1"] or
                metadata.get("encoding") != "base64"):
            row["status"] = "MISMATCH"
            return row
        encoded = metadata.get("content")
        if type(encoded) is not str or len(encoded) > MAX_JSON_BYTES:
            row["status"] = "MISMATCH"
            return row
        bytes_value = base64.b64decode(
            re.sub(r"\s+", "", encoded), validate=True)
        if not 0 < len(bytes_value) <= MAX_BODY_BYTES:
            row["status"] = "MISMATCH"
            return row
        # Git's historic SHA-1 blob ID is a source-object identifier, NOT
        # a signature, trusted authorization, or modern security digest.
        # An independent SHA-256 fingerprint is recorded separately.
        actual_git_sha = hashlib.sha1(
            b"blob " + str(len(bytes_value)).encode("ascii") +
            b"\0" + bytes_value, usedforsecurity=False).hexdigest()
        if actual_git_sha != entry["blob_sha1"]:
            row["status"] = "MISMATCH"
            return row
        row["status"] = "MATCHED"
        row["byte_length"] = len(bytes_value)
        row["content_sha256"] = hashlib.sha256(bytes_value).hexdigest()
    except (RuntimeError, ValueError, TypeError, OSError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        return row
    return row


def observe(policy, *, fetch=_fetch_from_github, at=None):
    refs = validate_policy(policy)
    values = [inspect(ref, fetch=fetch) for ref in refs]
    matched = sum(r["status"] == "MATCHED" for r in values)
    return {
        "schema": SCHEMA,
        "observed_at": (at or datetime.now(timezone.utc)).isoformat(),
        "state": "COMPLETE_BLOB_MATCH" if matched == len(refs) else "HOLD",
        "required_count": len(refs),
        "matched_count": matched,
        "entries": values,
        "github_commit_and_blob_pins_reported": True,
        "git_bytes_checked_by_this_collector": True,
        "runtime_sources_independently_verified": False,
        "lean_kernel_executed": False,
        "hatun_authority_present": False,
        "lake_canonical_receipt_emitted": False,
        "provider_writes": False,
        "secrets_recorded": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bounded, source-pinned GH blob readback")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        policy, _ = read_file(args.policy, max_bytes=65536)
        validate_policy(policy)
        output = args.output
        checkout = Path(__file__).resolve().parent.parent
        require(not output.exists() and not output.is_symlink()
                and output.parent.is_dir()
                and not output.resolve().is_relative_to(checkout),
                "BRAID_OUTPUT_DENIED")
        data = observe(policy)
        raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) +
               "\n").encode("utf-8")
        require(len(raw) <= 65536, "BRAID_OUTPUT_TOO_LARGE")
        with output.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"state": data["state"],
                          "matched": data["matched_count"],
                          "required": data["required_count"],
                          "provider_writes": False}))
        return 0 if data["state"] == "COMPLETE_BLOB_MATCH" else 2
    except (InputError, ValueError) as exc:
        err = exc.code if isinstance(exc, InputError) else "INVALID_INPUT"
    except Exception:
        err = "READBACK_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": err,
                      "provider_writes": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
