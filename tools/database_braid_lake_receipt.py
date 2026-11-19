#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Wrap a braid v2 report in the estate's canonical Lake receipt, locally.

Runs the committed ``szl-lake`` adapter (``szl_lake_receipt.emit_lake_receipt``)
from a fresh export of the checkout's HEAD commit, never from the working
tree, in a child started as ``python -I -B -X pycache_prefix=<new empty
directory> -c DRIVER``. The export is appended after the interpreter's own
paths, so the pinned ``szl-receipt-dsse`` library and its version come from
the given interpreter's site-packages (trusted, not verified here), and the
adapter must be the exported file or the wrap is refused. The braid report is
bound by digest (subject, input digest, stored-object digest, policy id).

This process checks the envelope itself: its ``payloadType`` must be the one
this library version emits, the base64 payload is decoded here, its SHA-256
must equal the envelope digest, and the decoded bytes are compared with the
braid's canonical JSON of the body (``canonical()``), which is a derivation
independent of the library. The adapter's own body-digest function is also
called, but in the same child process and the same library, so that match is
recorded as ``digest_rederived_by_adapter_same_process`` and is a consistency
check of one code path, not an independent derivation.

This tool never handles a private key, so the envelope it obtains is ALWAYS
the library's own ``UNSIGNED-honest`` form (``signed: false``). An unsigned
receipt is an identifier for content, never a signature and never a pass:
signing belongs to a keyless CI attestation or the estate signer, outside
this tool. Nothing is appended to any live Lake. The child runs under CPU,
address-space and file-size limits, a deadline and an output cap, and is
started in a new network namespace when the host allows one; the wrap records
the namespace that was observed. Only EMPTY_NETWORK_NAMESPACE blocks IP
traffic (filesystem UNIX sockets stay reachable); with
NOT_AVAILABLE_ON_THIS_HOST direct sockets were not blocked. When the receipt
library is not installed the result is UNAVAILABLE; the canonical shapes are
never re-implemented here.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile

try:
    from tools.database_braid_common import (
        NETNS_EMPTY, NETNS_UNAVAILABLE, REPOSITORY, SHA40, SHA64, bounded_run, canonical,
        checkout_root, closed, git_blob_sha1, natural, read_json, require, sha256_hex,
        strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        NETNS_EMPTY, NETNS_UNAVAILABLE, REPOSITORY, SHA40, SHA64, bounded_run, canonical,
        checkout_root, closed, git_blob_sha1, natural, read_json, require, sha256_hex,
        strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-lake-wrap/v2"
BODY_SCHEMA = "szl.pcgi.receipt/szl-lake-anchor/v1"
BODY_KIND = "szl-lake-anchor"
# szl_receipt.PAYLOAD_TYPE in szl-receipt-dsse 0.3.1, the value its sign_receipt emits.
RECEIPT_PAYLOAD_TYPE = "application/vnd.szl.receipt+json"
ADAPTER_PATH = "szl_lake_receipt.py"
DISTRIBUTION = "szl-receipt-dsse"
SOURCE_TREE = "FRESH_EXPORT_OF_COMMIT"
UNSIGNED_DETAIL = "unsigned-honest"
POLICY_ID = re.compile(r"szl\.[a-z0-9./-]{3,120}\Z")
SUBJECT = re.compile(r"[a-z0-9][a-z0-9:._-]{7,120}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")
ORGAN = re.compile(r"[a-z][a-z0-9-]{2,40}\Z")
OBSERVED_VERSION = re.compile(r"[0-9A-Za-z.+!_-]{1,40}\Z")
DETAIL = re.compile(r"[A-Za-z0-9 _.:-]{1,60}\Z")
FLAG = re.compile(r"[A-Za-z0-9_.=:-]{1,60}\Z")
LIBRARY_ORIGINS = ("INTERPRETER_PATH", "EXPORTED_TREE", "UNLOCATED", "NOT_IMPORTED")
INTERPRETER_FLAGS = ("-I", "-B", "-X", "pycache_prefix=FRESH_EMPTY_DIRECTORY")
STATES = ("CANONICAL_RECEIPT_EMITTED_UNSIGNED", "HOLD", "UNAVAILABLE")
MAX_WRAP_BYTES = 65536
MAX_REPORT_BYTES = 4194304
MAX_EXPORT_FILES = 200000
CHILD_TIMEOUT_SECONDS = 120
CHILD_CPU_SECONDS = 60
CHILD_ADDRESS_BYTES = 1073741824
CHILD_FILE_BYTES = 0
EXPORT_MAX_BLOB_BYTES = 16777216
EXPORT_MAX_TOTAL_BYTES = 134217728
_FALSE_FLAGS = ("signature_present", "signer_identity_established", "appended_to_live_lake",
                "private_key_handled", "production_authorized")
_ENVELOPE_FIELDS = ("payloadType", "payload", "signature", "signed", "organ", "keyid", "digest",
                    "algo", "note")
_LIBRARY_FIELDS = ("distribution", "version_required", "version_observed", "module_origin")
_CHILD_FIELDS = ("flags", "isolated_mode", "bytecode_writes_disabled",
                 "pycache_prefix_fresh_and_unused", "adapter_loaded_from_export", "limits")
_OBSERVED_FIELDS = ("network_namespace", "export_files", "export_skipped_entries",
                    "isolated_mode", "bytecode_writes_disabled",
                    "pycache_prefix_fresh_and_unused", "adapter_loaded_from_export")
_FIELDS = ("schema", "observed_at", "repository", "commit", "adapter_path", "adapter_blob_sha1",
           "source_tree", "export_files", "export_skipped_entries", "receipt_library",
           "subject", "input_digest", "stored_object_digest", "policy_id", "organ", "envelope",
           "digest_rehashed_by_parent", "payload_is_canonical_json_of_body",
           "digest_rederived_by_adapter_same_process", "adapter_rederivation_matches",
           "verify_ok", "verify_detail", "child", "network_namespace",
           "direct_network_egress_blocked", "state", *_FALSE_FLAGS)
_UNKNOWN_WHEN_UNAVAILABLE = ("payload_is_canonical_json_of_body",
                             "digest_rederived_by_adapter_same_process", "verify_ok",
                             "verify_detail")

DRIVER = r'''
import importlib.metadata as metadata, json, os, sys
root = os.path.realpath(sys.argv[1])
want = json.loads(sys.stdin.read())


def located(module):
    places = [getattr(module, "__file__", None), *(getattr(module, "__path__", None) or ())]
    places = [p for p in places if p]
    if not places:
        return "UNLOCATED"
    inside = [os.path.realpath(p).startswith(root + os.sep) for p in places]
    return "EXPORTED_TREE" if any(inside) else "INTERPRETER_PATH"


out = {"python": "%d.%d.%d" % sys.version_info[:3],
       "process": {"isolated": sys.flags.isolated == 1,
                   "dont_write_bytecode": sys.flags.dont_write_bytecode == 1,
                   "pycache_prefix": sys.pycache_prefix}}
try:
    # Read before the export joins sys.path, so no committed dist-info can answer.
    out["library_version"] = metadata.version(want["distribution"])
except Exception:
    out["library_version"] = None
sys.path.append(root)
try:
    import szl_lake_receipt as lake
    out["adapter_origin"] = located(lake)
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
library = sys.modules.get("szl_receipt")
out["library_origin"] = "NOT_IMPORTED" if library is None else located(library)
sys.stdout.write(json.dumps(out, sort_keys=True))
'''


def validate_policy(section) -> dict:
    """Validate the ``lake`` section of the braid v2 policy."""
    closed(section, ("repository", "adapter_path", "policy_id", "organ", "receipt_library",
                     "append_to_live_lake"), "LAKE_POLICY_FIELDS_INVALID")
    library = closed(section["receipt_library"], ("distribution", "version"),
                     "LAKE_POLICY_FIELDS_INVALID")
    require(type(section["repository"]) is str and REPOSITORY.fullmatch(section["repository"])
            and section["adapter_path"] == ADAPTER_PATH and
            type(section["policy_id"]) is str and POLICY_ID.fullmatch(section["policy_id"]) and
            type(section["organ"]) is str and ORGAN.fullmatch(section["organ"]) and
            library["distribution"] == DISTRIBUTION and
            type(library["version"]) is str and VERSION.fullmatch(library["version"]) and
            section["append_to_live_lake"] is False, "LAKE_POLICY_INVALID")
    return section


def adapter_identity(checkout: Path, adapter_path: str) -> tuple:
    """``(commit, blob_sha1)`` after proving the adapter file IS the committed blob.

    The child never runs this working file; it runs an export of the same commit.
    """
    commit, _shallow, rows = list_tree(checkout)
    pinned = [sha for _mode, kind, sha, _size, path in rows
              if kind == "blob" and path == adapter_path]
    require(len(pinned) == 1, "LAKE_ADAPTER_MISSING")
    target = checkout / adapter_path
    require(target.is_file() and not target.is_symlink() and
            git_blob_sha1(target.read_bytes()) == pinned[0], "LAKE_WORKTREE_DIFFERS_FROM_COMMIT")
    return commit, pinned[0]


def child_limits() -> dict:
    return {"timeout_seconds": CHILD_TIMEOUT_SECONDS, "cpu_seconds": CHILD_CPU_SECONDS,
            "address_space_bytes": CHILD_ADDRESS_BYTES, "file_size_bytes": CHILD_FILE_BYTES,
            "max_output_bytes": MAX_WRAP_BYTES}


def _child_environment(home: Path, temp: Path) -> dict:
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temp), "LANG": "C.UTF-8",
            "NO_PROXY": "*", "no_proxy": "*"}


def _interpreter_ok(python) -> bool:
    return (type(python) is str and os.path.isabs(python) and os.path.isfile(python) and
            os.access(python, os.X_OK))


def run_child(checkout: Path, request: dict, *, python: str, commit: str | None = None,
              blob_sha1: str | None = None) -> tuple:
    """Export ``commit`` of ``checkout`` and run the adapter driver over that export only.

    Returns ``(child_report, observed)``: the child's own JSON, and what this
    process observed about the run.
    """
    require(_interpreter_ok(python), "LAKE_CHILD_UNAVAILABLE")
    if commit is None or blob_sha1 is None:
        commit, blob_sha1 = adapter_identity(checkout, ADAPTER_PATH)
    with tempfile.TemporaryDirectory(prefix="braid-lake-") as scratch:
        base = Path(scratch)
        export, cache, home, temp, work = (base / name for name in
                                           ("export", "pycache", "home", "tmp", "work"))
        for directory in (export, cache, home, temp, work):
            directory.mkdir()
        counts = export_tree(checkout, commit, export, max_blob_bytes=EXPORT_MAX_BLOB_BYTES,
                             max_total_bytes=EXPORT_MAX_TOTAL_BYTES)
        adapter = export / ADAPTER_PATH
        require(adapter.is_file() and not adapter.is_symlink() and
                git_blob_sha1(adapter.read_bytes()) == blob_sha1, "LAKE_EXPORT_MISMATCH")
        prefix = os.path.realpath(cache)
        run = bounded_run([python, "-I", "-B", "-X", "pycache_prefix=" + prefix, "-c", DRIVER,
                           str(export)], cwd=work, env=_child_environment(home, temp),
                          timeout=CHILD_TIMEOUT_SECONDS, max_output=MAX_WRAP_BYTES,
                          stdin_bytes=json.dumps(request).encode("utf-8"),
                          isolate_network=True, cpu_seconds=CHILD_CPU_SECONDS,
                          file_bytes=CHILD_FILE_BYTES, address_bytes=CHILD_ADDRESS_BYTES,
                          merge_stderr=False)
        cache_unused = not any(cache.iterdir())
    require(not run["timed_out"], "LAKE_CHILD_TIMEOUT")
    require(not run["truncated"], "LAKE_CHILD_OUTPUT_TOO_LARGE")
    require(run["exit_code"] == 0 and len(run["output"]) > 0, "LAKE_CHILD_FAILED")
    try:
        raw = json.loads(run["output"].decode("utf-8", "strict"))
    except (UnicodeError, ValueError, RecursionError):
        raise InputError("LAKE_CHILD_OUTPUT_INVALID") from None
    require(type(raw) is dict, "LAKE_CHILD_OUTPUT_INVALID")
    process = raw.get("process") if type(raw.get("process")) is dict else {}
    seen_prefix = process.get("pycache_prefix")
    origin = raw.get("adapter_origin")
    observed = {"network_namespace": run["network_namespace"], "export_files": counts["files"],
                "export_skipped_entries": counts["skipped_entries"],
                "isolated_mode": process.get("isolated") is True,
                "bytecode_writes_disabled": process.get("dont_write_bytecode") is True,
                "pycache_prefix_fresh_and_unused":
                    cache_unused and type(seen_prefix) is str and
                    os.path.realpath(seen_prefix) == prefix,
                "adapter_loaded_from_export": None if origin is None
                else origin == "EXPORTED_TREE"}
    return raw, observed


def _check_envelope(envelope):
    """No signature, no key and a well-formed digest, in the library's own payload type."""
    require(envelope["signed"] is False and envelope["signature"] == "" and
            envelope["algo"] == "UNSIGNED" and envelope["keyid"] == "" and
            type(envelope["digest"]) is str and SHA64.fullmatch(envelope["digest"]),
            "LAKE_UNEXPECTED_SIGNATURE_CLAIM")
    require(envelope["payloadType"] == RECEIPT_PAYLOAD_TYPE, "LAKE_PAYLOAD_TYPE_UNEXPECTED")


def open_envelope(envelope) -> tuple:
    """``(body, payload_bytes)`` after re-hashing the decoded payload against its digest."""
    _check_envelope(envelope)
    text = envelope["payload"]
    require(type(text) is str and 0 < len(text) <= 2 * MAX_WRAP_BYTES,
            "LAKE_ENVELOPE_PAYLOAD_INVALID")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise InputError("LAKE_ENVELOPE_PAYLOAD_INVALID") from None
    require(sha256_hex(raw) == envelope["digest"], "LAKE_ENVELOPE_DIGEST_MISMATCH")
    try:
        body = strict_json(raw, max_bytes=MAX_WRAP_BYTES)
    except InputError:
        raise InputError("LAKE_ENVELOPE_PAYLOAD_INVALID") from None
    return body, raw


def _check_body(body, wrap):
    energy = body.get("energy") if type(body) is dict else None
    require(type(body) is dict and body.get("schema") == BODY_SCHEMA and
            body.get("kind") == BODY_KIND and body.get("subject") == wrap["subject"] and
            body.get("input_digest") == "sha256:" + wrap["input_digest"] and
            body.get("stored_object_digest") == "sha256:" + wrap["stored_object_digest"] and
            body.get("policy") == {"id": wrap["policy_id"]} and
            body.get("organ") == wrap["organ"] and type(energy) is dict and
            energy.get("status") == "UNAVAILABLE" and "joules" in energy and
            energy["joules"] is None, "LAKE_BODY_BINDING_MISMATCH")


def _wrap_state(wrap) -> str:
    if wrap["envelope"] is None:
        return STATES[2]
    library = wrap["receipt_library"]
    good = (wrap["adapter_rederivation_matches"] is True and
            wrap["payload_is_canonical_json_of_body"] is True and
            library["version_observed"] == library["version_required"] and
            library["module_origin"] == "INTERPRETER_PATH" and
            wrap["verify_ok"] is False and wrap["verify_detail"] == UNSIGNED_DETAIL)
    return STATES[0] if good else STATES[1]


def _child_record(observed, emitted) -> dict:
    closed(observed, _OBSERVED_FIELDS, "LAKE_OBSERVATION_INVALID")
    require(observed["network_namespace"] in (NETNS_EMPTY, NETNS_UNAVAILABLE),
            "LAKE_NETWORK_CLAIM_INVALID")
    natural(observed["export_files"], "LAKE_OBSERVATION_INVALID", maximum=MAX_EXPORT_FILES)
    natural(observed["export_skipped_entries"], "LAKE_OBSERVATION_INVALID",
            maximum=MAX_EXPORT_FILES)
    require(observed["export_files"] > 0, "LAKE_OBSERVATION_INVALID")
    require(observed["isolated_mode"] is True and observed["bytecode_writes_disabled"] is True
            and observed["pycache_prefix_fresh_and_unused"] is True, "LAKE_CHILD_NOT_ISOLATED")
    loaded = observed["adapter_loaded_from_export"]
    require(loaded is True or (loaded is None and not emitted), "LAKE_ADAPTER_NOT_FROM_EXPORT")
    return {"flags": list(INTERPRETER_FLAGS), "isolated_mode": True,
            "bytecode_writes_disabled": True, "pycache_prefix_fresh_and_unused": True,
            "adapter_loaded_from_export": loaded, "limits": child_limits()}


def assemble(section, commit, blob_sha1, request, raw, *, observed, at=None) -> dict:
    """Turn the child's report and the parent's own envelope checks into a closed wrap."""
    validate_policy(section)
    require(type(raw) is dict, "LAKE_CHILD_OUTPUT_INVALID")
    emitted = raw.get("state") == "EMITTED" and type(raw.get("envelope")) is dict
    child = _child_record(observed, emitted)
    envelope = rederived = canonical_form = verify_ok = detail = None
    matches = False
    if emitted:
        source = raw["envelope"]
        # Keep exactly the fields the library defines; refuse anything that claims a signature.
        require(source.get("signed") is False and source.get("signature") == "" and
                source.get("algo") == "UNSIGNED", "LAKE_UNEXPECTED_SIGNATURE_CLAIM")
        envelope = {key: source.get(key) for key in _ENVELOPE_FIELDS}
        body, payload = open_envelope(envelope)
        canonical_form = canonical(body) == payload
        given = raw.get("rederived")
        rederived = given if type(given) is str and SHA64.fullmatch(given) else None
        matches = rederived == envelope["digest"]
        verify_ok = raw.get("verify_ok") if type(raw.get("verify_ok")) is bool else None
        given = raw.get("verify_detail")
        detail = given if type(given) is str and DETAIL.fullmatch(given) else None
    version = raw.get("library_version")
    origin = raw.get("library_origin")
    namespace = observed["network_namespace"]
    wrap = {
        "schema": SCHEMA, "observed_at": (at or datetime.now(timezone.utc)).isoformat(),
        "repository": section["repository"], "commit": commit,
        "adapter_path": section["adapter_path"], "adapter_blob_sha1": blob_sha1,
        "source_tree": SOURCE_TREE, "export_files": observed["export_files"],
        "export_skipped_entries": observed["export_skipped_entries"],
        "receipt_library": {
            "distribution": section["receipt_library"]["distribution"],
            "version_required": section["receipt_library"]["version"],
            "version_observed": version if type(version) is str and
            OBSERVED_VERSION.fullmatch(version) else None,
            "module_origin": origin if origin in LIBRARY_ORIGINS else "UNLOCATED"},
        "subject": request["subject"], "input_digest": request["input_digest"],
        "stored_object_digest": request["stored_object_digest"],
        "policy_id": section["policy_id"], "organ": section["organ"],
        "envelope": envelope, "digest_rehashed_by_parent": envelope is not None,
        "payload_is_canonical_json_of_body": canonical_form,
        "digest_rederived_by_adapter_same_process": rederived,
        "adapter_rederivation_matches": matches, "verify_ok": verify_ok, "verify_detail": detail,
        "child": child, "network_namespace": namespace,
        "direct_network_egress_blocked": namespace == NETNS_EMPTY,
    }
    wrap.update({flag: False for flag in _FALSE_FLAGS})
    wrap["state"] = _wrap_state(wrap)
    validate_wrap(wrap, section)
    return wrap


def _timestamp_ok(value) -> bool:
    if type(value) is not str or len(value) > 48:
        return False
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return stamp.utcoffset() is not None


def _check_child(value, emitted, current):
    closed(value, _CHILD_FIELDS, "LAKE_CHILD_RECORD_INVALID")
    loaded = value["adapter_loaded_from_export"]
    limits = value["limits"]
    require(value["isolated_mode"] is True and value["bytecode_writes_disabled"] is True and
            value["pycache_prefix_fresh_and_unused"] is True and
            (loaded is True or (loaded is None and not emitted)) and
            type(value["flags"]) is list and len(value["flags"]) <= 8 and
            all(type(flag) is str and FLAG.fullmatch(flag) for flag in value["flags"]) and
            type(limits) is dict and set(limits) == set(child_limits()) and
            all(type(limit) is int and 0 <= limit <= 2 ** 40 for limit in limits.values()),
            "LAKE_CHILD_RECORD_INVALID")
    # Flags and limits belong to the tool version that ran; an older wrap may differ.
    require(not current or (value["flags"] == list(INTERPRETER_FLAGS) and
                            limits == child_limits()), "LAKE_CHILD_RECORD_INVALID")


def validate_wrap(value, section, *, require_current_pins=True) -> bool:
    """Closed-schema check that re-derives the receipt digest from the payload bytes.

    With ``require_current_pins`` false, a wrap made under older pins is checked
    against the repository, library version, policy id and organ it records,
    not against ``section``'s; comparing those pins is then the caller's job.
    """
    validate_policy(section)
    require(type(value) is dict, "LAKE_WRAP_FIELDS_INVALID")
    require(value.get("schema") == SCHEMA, "LAKE_WRAP_SCHEMA_UNSUPPORTED")
    closed(value, _FIELDS, "LAKE_WRAP_FIELDS_INVALID")
    library = closed(value["receipt_library"], _LIBRARY_FIELDS, "LAKE_WRAP_FIELDS_INVALID")
    require(type(value["repository"]) is str and REPOSITORY.fullmatch(value["repository"]) and
            type(value["commit"]) is str and SHA40.fullmatch(value["commit"]) and
            value["adapter_path"] == ADAPTER_PATH and
            type(value["adapter_blob_sha1"]) is str and SHA40.fullmatch(value["adapter_blob_sha1"])
            and value["source_tree"] == SOURCE_TREE and
            type(value["policy_id"]) is str and POLICY_ID.fullmatch(value["policy_id"]) and
            type(value["organ"]) is str and ORGAN.fullmatch(value["organ"]) and
            library["distribution"] == DISTRIBUTION and
            type(library["version_required"]) is str and
            VERSION.fullmatch(library["version_required"]), "LAKE_WRAP_BINDING_INVALID")
    if require_current_pins:
        require(value["repository"] == section["repository"] and
                value["adapter_path"] == section["adapter_path"] and
                value["policy_id"] == section["policy_id"] and
                value["organ"] == section["organ"] and
                library["distribution"] == section["receipt_library"]["distribution"] and
                library["version_required"] == section["receipt_library"]["version"],
                "LAKE_WRAP_PIN_MISMATCH")
    require(all(value[flag] is False for flag in _FALSE_FLAGS), "LAKE_FALSE_AUTHORITY_CLAIM")
    require(type(value["subject"]) is str and SUBJECT.fullmatch(value["subject"]) and
            all(type(value[k]) is str and SHA64.fullmatch(value[k])
                for k in ("input_digest", "stored_object_digest")) and
            (library["version_observed"] is None or
             (type(library["version_observed"]) is str and
              OBSERVED_VERSION.fullmatch(library["version_observed"]))) and
            library["module_origin"] in LIBRARY_ORIGINS, "LAKE_WRAP_FIELDS_INVALID")
    natural(value["export_files"], "LAKE_WRAP_FIELDS_INVALID", maximum=MAX_EXPORT_FILES)
    natural(value["export_skipped_entries"], "LAKE_WRAP_FIELDS_INVALID", maximum=MAX_EXPORT_FILES)
    require(value["export_files"] > 0, "LAKE_WRAP_FIELDS_INVALID")
    require(_timestamp_ok(value["observed_at"]), "LAKE_TIMESTAMP_INVALID")
    require(value["network_namespace"] in (NETNS_EMPTY, NETNS_UNAVAILABLE) and
            value["direct_network_egress_blocked"] is (value["network_namespace"] == NETNS_EMPTY),
            "LAKE_NETWORK_CLAIM_INVALID")
    require(value["state"] in STATES, "LAKE_STATE_INVALID")
    envelope = value["envelope"]
    if value["state"] == "UNAVAILABLE":
        require(envelope is None and value["digest_rehashed_by_parent"] is False and
                value["adapter_rederivation_matches"] is False and
                all(value[field] is None for field in _UNKNOWN_WHEN_UNAVAILABLE),
                "LAKE_UNAVAILABLE_NOT_UNKNOWN")
    _check_child(value["child"], envelope is not None, require_current_pins)
    if value["state"] == "UNAVAILABLE":
        return True
    closed(envelope, _ENVELOPE_FIELDS, "LAKE_ENVELOPE_FIELDS_INVALID")
    # Re-derived here from the payload bytes; the recorded digest is never taken on trust.
    body, payload = open_envelope(envelope)
    _check_body(body, value)
    rederived = value["digest_rederived_by_adapter_same_process"]
    require(value["digest_rehashed_by_parent"] is True and
            value["payload_is_canonical_json_of_body"] is (canonical(body) == payload) and
            (rederived is None or (type(rederived) is str and SHA64.fullmatch(rederived))) and
            value["adapter_rederivation_matches"] is (rederived == envelope["digest"]) and
            (value["verify_ok"] is None or type(value["verify_ok"]) is bool) and
            (value["verify_detail"] is None or (type(value["verify_detail"]) is str and
                                                DETAIL.fullmatch(value["verify_detail"]))),
            "LAKE_DERIVED_FIELD_MISMATCH")
    require(value["state"] == _wrap_state(value), "LAKE_STATE_DRIFT")
    return True


def wrap_report(section, checkout: Path, *, subject: str, input_digest: str,
                stored_object_digest: str, python: str, at=None) -> dict:
    """Bind the adapter to its commit, emit the unsigned canonical receipt from an export."""
    validate_policy(section)
    require(type(subject) is str and SUBJECT.fullmatch(subject) and
            all(type(d) is str and SHA64.fullmatch(d)
                for d in (input_digest, stored_object_digest)), "LAKE_REQUEST_INVALID")
    commit, blob_sha1 = adapter_identity(checkout, section["adapter_path"])
    request = {"subject": subject, "input_digest": input_digest,
               "stored_object_digest": stored_object_digest, "policy_id": section["policy_id"],
               "organ": section["organ"],
               "distribution": section["receipt_library"]["distribution"]}
    raw, observed = run_child(checkout, request, python=python, commit=commit,
                              blob_sha1=blob_sha1)
    return assemble(section, commit, blob_sha1, request, raw, observed=observed, at=at)


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
                          "digest_rehashed_by_parent": wrap["digest_rehashed_by_parent"],
                          "adapter_rederivation_matches": wrap["adapter_rederivation_matches"],
                          "network_namespace": wrap["network_namespace"],
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
