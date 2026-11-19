#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Wrap a braid v2 report in the estate's canonical Lake receipt, locally.

Runs the committed ``szl-lake`` adapter (``szl_lake_receipt.emit_lake_receipt``)
in a child interpreter that has the pinned ``szl-receipt-dsse`` library, binds
the braid report by digest (subject, input digest, stored-object digest,
policy id) and re-derives the receipt digest independently.

This tool never handles a private key, so the envelope it obtains is ALWAYS
the library's own ``UNSIGNED-honest`` form (``signed: false``). An unsigned
receipt is an identifier for content, never a signature and never a pass:
signing belongs to a keyless CI attestation or the estate signer, outside
this tool. Nothing is appended to any live Lake and no network is used. When
the receipt library is not installed the result is UNAVAILABLE; the canonical
shapes are never re-implemented here.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

try:
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, git_blob_sha1, read_json, require,
        sha256_hex, strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import list_tree
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, git_blob_sha1, read_json, require,
        sha256_hex, strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import list_tree
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-lake-wrap/v1"
BODY_SCHEMA = "szl.pcgi.receipt/szl-lake-anchor/v1"
POLICY_ID = re.compile(r"szl\.[a-z0-9./-]{3,120}\Z")
SUBJECT = re.compile(r"[a-z0-9][a-z0-9:._-]{7,120}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")
MAX_WRAP_BYTES = 65536
MAX_REPORT_BYTES = 4194304
CHILD_TIMEOUT_SECONDS = 120
_FALSE_FLAGS = ("signature_present", "signer_identity_established", "appended_to_live_lake",
                "network_used", "private_key_handled", "production_authorized")
_FIELDS = ("schema", "observed_at", "repository", "commit", "adapter_path", "adapter_blob_sha1",
           "adapter_matches_commit", "receipt_library", "subject", "input_digest",
           "stored_object_digest", "policy_id", "organ", "envelope", "body_digest_rederived",
           "digest_matches", "verify_detail", "state", *_FALSE_FLAGS)

DRIVER = r'''
import importlib.metadata as metadata, json, sys
sys.path.insert(0, sys.argv[1])
want = json.loads(sys.stdin.read())
out = {"python": "%d.%d.%d" % sys.version_info[:3]}
try:
    import szl_lake_receipt as lake
    out["library_version"] = metadata.version(want["distribution"])
    common = dict(anchor_id=want["subject"], input_digest=want["input_digest"],
                  stored_object_digest=want["stored_object_digest"],
                  policy_id=want["policy_id"], organ=want["organ"])
    # No key is ever passed: the library returns its own UNSIGNED-honest envelope.
    out["envelope"] = lake.emit_lake_receipt(private_key_pem=None, **common)
    out["rederived"] = lake.lake_receipt_body_digest(**common)
    ok, detail = lake.verify_lake_receipt(out["envelope"])
    out["verify_ok"], out["verify_detail"] = bool(ok), str(detail)
    out["state"] = "EMITTED"
except Exception as exc:
    # Includes the adapter's own LakeReceiptUnavailable when the library is absent.
    out["state"], out["reason"] = "UNAVAILABLE", type(exc).__name__
sys.stdout.write(json.dumps(out, sort_keys=True))
'''


def validate_policy(section) -> dict:
    """Validate the ``lake`` section of the braid v2 policy."""
    closed(section, ("repository", "adapter_path", "policy_id", "organ", "receipt_library",
                     "append_to_live_lake"), "LAKE_POLICY_FIELDS_INVALID")
    library = closed(section["receipt_library"], ("distribution", "version"),
                     "LAKE_POLICY_FIELDS_INVALID")
    require(type(section["repository"]) is str and REPOSITORY.fullmatch(section["repository"])
            and section["adapter_path"] == "szl_lake_receipt.py" and
            type(section["policy_id"]) is str and POLICY_ID.fullmatch(section["policy_id"]) and
            type(section["organ"]) is str and re.fullmatch(r"[a-z][a-z0-9-]{2,40}", section["organ"])
            and library["distribution"] == "szl-receipt-dsse" and
            type(library["version"]) is str and VERSION.fullmatch(library["version"]) and
            section["append_to_live_lake"] is False, "LAKE_POLICY_INVALID")
    return section


def adapter_identity(checkout: Path, adapter_path: str) -> tuple:
    """``(commit, blob_sha1)`` after proving the adapter file IS the committed blob."""
    commit, _shallow, rows = list_tree(checkout)
    pinned = [sha for mode, kind, sha, _size, path in rows if kind == "blob" and path == adapter_path]
    require(len(pinned) == 1, "LAKE_ADAPTER_MISSING")
    target = checkout / adapter_path
    require(target.is_file() and not target.is_symlink() and
            git_blob_sha1(target.read_bytes()) == pinned[0], "LAKE_WORKTREE_DIFFERS_FROM_COMMIT")
    return commit, pinned[0]


def run_child(checkout: Path, request: dict, *, python: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="braid-lake-") as scratch:
        driver = Path(scratch) / "driver.py"
        driver.write_text(DRIVER, encoding="utf-8")
        env = {"PATH": "/usr/bin:/bin", "HOME": scratch, "LANG": "C.UTF-8",
               "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": "*"}
        try:
            proc = subprocess.run([python, "-I", "-B", str(driver), str(checkout)],
                                  input=json.dumps(request).encode("utf-8"),
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  cwd=scratch, env=env, timeout=CHILD_TIMEOUT_SECONDS,
                                  check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise InputError("LAKE_CHILD_UNAVAILABLE") from None
    require(proc.returncode == 0 and 0 < len(proc.stdout) <= MAX_WRAP_BYTES, "LAKE_CHILD_FAILED")
    try:
        return json.loads(proc.stdout.decode("utf-8", "strict"))
    except (UnicodeError, ValueError):
        raise InputError("LAKE_CHILD_OUTPUT_INVALID") from None


def _body(envelope) -> dict:
    """Decode the receipt body carried in the envelope payload."""
    try:
        return strict_json(base64.b64decode(envelope["payload"], validate=True),
                           max_bytes=MAX_WRAP_BYTES)
    except (KeyError, TypeError, ValueError):
        raise InputError("LAKE_ENVELOPE_PAYLOAD_INVALID") from None


def assemble(section, commit, blob_sha1, request, raw, *, at=None) -> dict:
    validate_policy(section)
    require(type(raw) is dict, "LAKE_CHILD_OUTPUT_INVALID")
    emitted = raw.get("state") == "EMITTED" and type(raw.get("envelope")) is dict
    envelope = None
    rederived = None
    if emitted:
        source = raw["envelope"]
        # Keep exactly the fields the library defines; refuse anything that claims a signature.
        require(source.get("signed") is False and source.get("signature") == "" and
                source.get("algo") == "UNSIGNED", "LAKE_UNEXPECTED_SIGNATURE_CLAIM")
        envelope = {key: source.get(key) for key in (
            "payloadType", "payload", "signature", "signed", "organ", "keyid", "digest",
            "algo", "note")}
        rederived = raw.get("rederived")
    version = raw.get("library_version") if type(raw.get("library_version")) is str else None
    matches = bool(emitted and type(rederived) is str and envelope["digest"] == rederived)
    good = (matches and version == section["receipt_library"]["version"] and
            raw.get("verify_ok") is False and raw.get("verify_detail") == "unsigned-honest")
    wrap = {
        "schema": SCHEMA, "observed_at": (at or datetime.now(timezone.utc)).isoformat(),
        "repository": section["repository"], "commit": commit,
        "adapter_path": section["adapter_path"], "adapter_blob_sha1": blob_sha1,
        "adapter_matches_commit": True,
        "receipt_library": {"distribution": section["receipt_library"]["distribution"],
                            "version_required": section["receipt_library"]["version"],
                            "version_observed": version},
        "subject": request["subject"], "input_digest": request["input_digest"],
        "stored_object_digest": request["stored_object_digest"],
        "policy_id": section["policy_id"], "organ": section["organ"],
        "envelope": envelope, "body_digest_rederived": rederived if emitted else None,
        "digest_matches": matches,
        "verify_detail": raw.get("verify_detail") if emitted and type(
            raw.get("verify_detail")) is str and len(raw["verify_detail"]) <= 60 else None,
        "state": "CANONICAL_RECEIPT_EMITTED_UNSIGNED" if good else (
            "HOLD" if emitted else "UNAVAILABLE"),
    }
    wrap.update({flag: False for flag in _FALSE_FLAGS})
    validate_wrap(wrap, section)
    return wrap


def validate_wrap(value, section) -> bool:
    """Closed-schema check, including an independent decode of the receipt body."""
    validate_policy(section)
    closed(value, _FIELDS, "LAKE_WRAP_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and value["repository"] == section["repository"] and
            type(value["commit"]) is str and SHA40.fullmatch(value["commit"]) and
            value["adapter_path"] == section["adapter_path"] and
            type(value["adapter_blob_sha1"]) is str and SHA40.fullmatch(value["adapter_blob_sha1"])
            and value["adapter_matches_commit"] is True and
            value["policy_id"] == section["policy_id"] and value["organ"] == section["organ"],
            "LAKE_WRAP_BINDING_INVALID")
    require(all(value[flag] is False for flag in _FALSE_FLAGS), "LAKE_FALSE_AUTHORITY_CLAIM")
    require(type(value["subject"]) is str and SUBJECT.fullmatch(value["subject"]) and
            all(type(value[k]) is str and SHA64.fullmatch(value[k])
                for k in ("input_digest", "stored_object_digest")), "LAKE_WRAP_FIELDS_INVALID")
    library = closed(value["receipt_library"], ("distribution", "version_required",
                                                "version_observed"), "LAKE_WRAP_FIELDS_INVALID")
    require(library["version_required"] == section["receipt_library"]["version"],
            "LAKE_WRAP_BINDING_INVALID")
    require(value["state"] in ("CANONICAL_RECEIPT_EMITTED_UNSIGNED", "HOLD", "UNAVAILABLE"),
            "LAKE_STATE_INVALID")
    envelope = value["envelope"]
    if value["state"] == "UNAVAILABLE":
        require(envelope is None and value["body_digest_rederived"] is None and
                value["digest_matches"] is False, "LAKE_UNAVAILABLE_NOT_UNKNOWN")
        return True
    closed(envelope, ("payloadType", "payload", "signature", "signed", "organ", "keyid",
                      "digest", "algo", "note"), "LAKE_ENVELOPE_FIELDS_INVALID")
    require(envelope["signed"] is False and envelope["signature"] == "" and
            envelope["algo"] == "UNSIGNED" and envelope["keyid"] == "" and
            type(envelope["digest"]) is str and SHA64.fullmatch(envelope["digest"]),
            "LAKE_UNEXPECTED_SIGNATURE_CLAIM")
    body = _body(envelope)
    energy = body.get("energy") if type(body) is dict else None
    require(type(body) is dict and body.get("schema") == BODY_SCHEMA and
            body.get("subject") == value["subject"] and
            body.get("input_digest") == "sha256:" + value["input_digest"] and
            body.get("stored_object_digest") == "sha256:" + value["stored_object_digest"] and
            body.get("policy") == {"id": value["policy_id"]} and
            body.get("organ") == value["organ"] and type(energy) is dict and
            energy.get("status") == "UNAVAILABLE" and energy.get("joules") is None,
            "LAKE_BODY_BINDING_MISMATCH")
    good = (value["digest_matches"] is True and
            value["body_digest_rederived"] == envelope["digest"] and
            library["version_observed"] == library["version_required"] and
            value["verify_detail"] == "unsigned-honest")
    require(value["state"] == ("CANONICAL_RECEIPT_EMITTED_UNSIGNED" if good else "HOLD"),
            "LAKE_STATE_DRIFT")
    return True


def wrap_report(section, checkout: Path, *, subject: str, input_digest: str,
                stored_object_digest: str, python: str, at=None) -> dict:
    """Bind the adapter to its commit, emit the unsigned canonical receipt, re-derive it."""
    validate_policy(section)
    require(type(subject) is str and SUBJECT.fullmatch(subject) and
            all(type(d) is str and SHA64.fullmatch(d)
                for d in (input_digest, stored_object_digest)), "LAKE_REQUEST_INVALID")
    commit, blob_sha1 = adapter_identity(checkout, section["adapter_path"])
    request = {"subject": subject, "input_digest": input_digest,
               "stored_object_digest": stored_object_digest, "policy_id": section["policy_id"],
               "organ": section["organ"],
               "distribution": section["receipt_library"]["distribution"]}
    return assemble(section, commit, blob_sha1, request,
                    run_child(checkout, request, python=python), at=at)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Unsigned canonical Lake receipt for a braid report")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--lake-checkout", type=Path, required=True)
    ap.add_argument("--braid-report", type=Path, required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        policy, _ = read_json(args.policy, max_bytes=1048576)
        require(type(policy) is dict and "lake" in policy, "LAKE_POLICY_FIELDS_INVALID")
        require(os.path.isabs(args.python) and Path(args.python).is_file(),
                "LAKE_INTERPRETER_INVALID")
        report, _ = read_json(args.braid_report, max_bytes=MAX_REPORT_BYTES)
        require(type(report) is dict and type(report.get("turn_id")) is str and
                type(report.get("inputs_digest")) is str, "LAKE_REPORT_FIELDS_INVALID")
        # The stored object is the exact report file, bound by the digest of its bytes.
        stored = sha256_hex(args.braid_report.read_bytes())
        wrap = wrap_report(policy["lake"], args.lake_checkout, subject=report["turn_id"],
                           input_digest=report["inputs_digest"], stored_object_digest=stored,
                           python=args.python)
        write_exclusive(args.output, wrap, max_bytes=MAX_WRAP_BYTES, checkout=checkout_root())
        print(json.dumps({"state": wrap["state"], "signed": False,
                          "digest_matches": wrap["digest_matches"],
                          "appended_to_live_lake": False, "production_authorized": False}))
        return 0 if wrap["state"] == "CANONICAL_RECEIPT_EMITTED_UNSIGNED" else 2
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "LAKE_WRAP_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "signed": False,
                      "appended_to_live_lake": False, "production_authorized": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
