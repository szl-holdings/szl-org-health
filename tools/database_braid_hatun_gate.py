#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the pinned Hatun veto ladder locally for the SZL Ouroboros braid v2.

Only committed bytes run. The checkout's HEAD commit is exported from the git
object store into a new temporary directory, and the child can import Hatun
code from that export alone: an untracked or ignored file in the checkout (a
shadow package, a planted ``__pycache__`` file, a root-level module) is never
on its path. The child is ``python -I -B -X pycache_prefix=<new empty
directory> -c DRIVER``, so Python environment variables, the user site and the
current directory are ignored and no cached bytecode is read or written. The
export is appended after the interpreter's own paths and the child reports
where every loaded ``hatun_mcp`` module came from; a module from anywhere else
refuses the witness. Third-party dependencies (the MCP SDK, pydantic, httpx
and the rest) are the given interpreter's site-packages: they are trusted, not
verified here, and the distributions that were loaded are recorded with their
versions.

The child gets a temporary HOME, no proxy, no receipt sink and no signing key,
and its backend endpoints point at a closed local port. It runs under CPU,
address-space and file-size limits, a wall-clock deadline and an output cap
read as it arrives; its whole process group is killed when the deadline or the
cap is exceeded. It is started in a new network namespace when the host allows
one, and the witness records the namespace that was observed. Only with
EMPTY_NETWORK_NAMESPACE can no IP traffic leave the machine: the child sees
loopback alone (filesystem UNIX sockets stay reachable, since no mount
namespace is made). With NOT_AVAILABLE_ON_THIS_HOST the proxy and backend
endpoints were removed but direct sockets were not blocked.

Two tiers are attempted and reported separately:

* KERNEL: Hatun's bounded loop walks the braid's five phases and its gate
  primitives rule on reviewed probes (standard library only).
* MCP: the real Hatun server object answers genuine JSON-RPC (initialize,
  tools/list, tools/call) through the MCP SDK's in-memory session, and its
  ``governed()`` ladder must decline exactly the probes the reviewed policy
  says it must decline. Reported UNAVAILABLE when the SDK is not installed.

What a pass means: this committed code, run here, vetoed what the policy
expected it to veto. What it does NOT mean: no deployed Hatun runtime was
contacted; the caller context is set through hatun-mcp's own test hooks, so
the API-key authentication path itself was not exercised and the caller is a
local demo context, not an identity; the signer is a labelled placeholder; no
second approver exists (and is never claimed); and Hatun does not understand
action text: the braid classifies effects itself and treats every database
work order as state-changing. Hatun can veto and receipt; nothing here
attaches effect authority. ``validate_witness`` re-derives every match, count
and state from the recorded observations and the reviewed policy.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile

try:
    from tools.database_braid_common import (
        NETNS_EMPTY, NETNS_UNAVAILABLE, REPOSITORY, SHA40, SHA64, bounded_run, checkout_root,
        closed, digest, git_blob_sha1, natural, read_json, require, strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        NETNS_EMPTY, NETNS_UNAVAILABLE, REPOSITORY, SHA40, SHA64, bounded_run, checkout_root,
        closed, digest, git_blob_sha1, natural, read_json, require, strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-hatun-witness/v2"
PROBE_ID = re.compile(r"[a-z][a-z0-9_]{2,47}\Z")
TOOL = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")
CODE = re.compile(r"[A-Za-z0-9_.() -]{0,80}\Z")
DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
DISTRIBUTION_VERSION = re.compile(r"[A-Za-z0-9.+!_-]{1,40}\Z")
MAX_PROBES = 24
MAX_DISTRIBUTIONS = 128
MAX_COUNT = 1000000
MAX_EXPORT_FILES = 200000
MAX_WITNESS_BYTES = 262144
CHILD_TIMEOUT_SECONDS = 180
CHILD_CPU_SECONDS = 120
CHILD_ADDRESS_BYTES = 2147483648
CHILD_FILE_BYTES = 0
EXPORT_MAX_BLOB_BYTES = 16777216
EXPORT_MAX_TOTAL_BYTES = 134217728
DEAD_ENDPOINT = "http://127.0.0.1:9"
SOURCE_TREE = "FRESH_EXPORT_OF_COMMIT"
CALLER_IDENTITY = "LOCAL_DEMO_CONTEXT_NOT_AN_IDENTITY"
CALLER_CONTEXT = "SET_THROUGH_HATUN_TEST_HOOKS"
SITE_PACKAGES = "INTERPRETER_SITE_PACKAGES_TRUSTED_NOT_VERIFIED"
INTERPRETER_FLAGS = ("-I", "-B", "-X", "pycache_prefix=FRESH_EMPTY_DIRECTORY")
TRANSPORT = "MCP_SDK_IN_MEMORY_JSON_RPC"
SERVER_INSTANCE = "LOCAL_PROCESS_EXPORTED_COMMIT"
STATES = ("VETO_LADDER_CONFORMS", "HOLD")
_BACKEND_VARS = ("SZL_A11OY_URL", "SZL_LLM_URL", "SZL_IMMUNE_URL", "SZL_KILLINCHU_URL",
                 "SZL_COMPANION_URL", "SZL_LEAN_URL", "SZL_ANATOMY_URL", "SZL_SECOND_BRAIN_URL",
                 "HATUN_MCP_AXLE_URL")
_FALSE_FLAGS = ("deployed_runtime_contacted", "signer_identity_established",
                "two_person_approval_claimed", "external_effects_performed",
                "production_authorized")
_WITNESS_FIELDS = (
    "schema", "observed_at", "repository", "commit", "source_modules_digest", "source_tree",
    "export_files", "export_skipped_entries", "interpreter", "child", "kernel", "mcp",
    "probes_expected", "probes_matched", "state", "effect_authority", "caller_identity",
    "caller_context", "api_key_authentication_path_exercised",
    "backend_endpoints_disabled_by_environment", "network_namespace",
    "direct_network_egress_blocked", "policy_section_sha256", *_FALSE_FLAGS,
)
_INTERPRETER_FIELDS = ("python", "site_packages", "loaded_distributions")
_CHILD_FIELDS = ("flags", "isolated_mode", "bytecode_writes_disabled",
                 "pycache_prefix_fresh_and_unused", "hatun_modules_loaded",
                 "hatun_modules_outside_export", "limits")
_OBSERVED_FIELDS = ("network_namespace", "export_files", "export_skipped_entries",
                    "isolated_mode", "bytecode_writes_disabled",
                    "pycache_prefix_fresh_and_unused", "hatun_modules_loaded",
                    "hatun_modules_outside_export")
_LOOP_FIELDS = ("loop_exit", "loop_steps", "loop_max_budget", "loop_doctrine",
                "loop_walked_all_phases", "chain_verified", "signer_mode")
_KERNEL_FIELDS = ("state", "reason", *_LOOP_FIELDS, "primitives")
_KERNEL_ROW_FIELDS = ("id", "state_changing", "authenticated_declared", "yuyay_passed",
                      "tripwire", "factor_text", "vetoed", "expect_vetoed", "matches_expected")
_SERVER_FIELDS = ("transport", "server_instance", "sdk_version", "server_name",
                  "server_version", "protocol_version", "tool_count", "chain_depth",
                  "chain_verified")
_MCP_FIELDS = ("state", "reason", *_SERVER_FIELDS, "probes")
_MCP_ROW_FIELDS = ("id", "tool", "context", "status", "decline_reason", "owasp_class",
                   "tripwire", "backend_started", "backend_endpoint", "signer_mode",
                   "signature_count", "expect_status", "expect_reason", "matches_expected")
# Longest child-reported text kept for each field; anything else becomes null.
_KERNEL_TEXT = {"loop_exit": 24, "loop_doctrine": 80, "signer_mode": 24}
_KERNEL_ROW_TEXT = {"tripwire": 8, "factor_text": 24}
_MCP_TEXT = {"sdk_version": 24, "server_name": 40, "server_version": 24,
             "protocol_version": 24}
_MCP_ROW_TEXT = {"status": 16, "decline_reason": 80, "owasp_class": 16, "tripwire": 8,
                 "backend_endpoint": 80, "signer_mode": 24}

# Runs inside the child interpreter, whose only Hatun source is the exported commit.
DRIVER = r'''
import asyncio, importlib.metadata as metadata, importlib.util, json, os, sys
root = os.path.realpath(sys.argv[1])
spec = json.loads(sys.stdin.read())
os.environ["HATUN_MCP_DISABLE_DYNAMIC"] = "true"
for name in ("SZL_RECEIPT_SINK", "HATUN_MCP_SIGNING_KEY", "HATUN_MCP_SIGNING_KEY_PATH"):
    os.environ.pop(name, None)


def version(name):
    try:
        return metadata.version(name)
    except Exception:
        return None


def inside(path):
    return bool(path) and os.path.realpath(path).startswith(root + os.sep)


def from_export(module):
    places = [getattr(module, "__file__", None), *(getattr(module, "__path__", None) or ())]
    places = [p for p in places if p]
    return bool(places) and all(inside(p) for p in places)


# Read before the export joins sys.path, so no committed dist-info can answer for the SDK.
sdk_version = version("mcp")
sys.path.append(root)
out = {"python": "%d.%d.%d" % sys.version_info[:3], "kernel": None, "mcp": None,
       "process": {"isolated": sys.flags.isolated == 1,
                   "dont_write_bytecode": sys.flags.dont_write_bytecode == 1,
                   "pycache_prefix": sys.pycache_prefix}}


def text(value):
    return None if value is None else repr(value) if isinstance(value, float) else str(value)

try:
    from hatun_mcp.governance import (DsseSigner, KhipuChain, hatun_mcp_factor, hukla_check,
                                      puriq_utility, yuyay_gate)
    from hatun_mcp.loop import run_bounded_loop
    chain, signer = KhipuChain(), DsseSigner()

    async def step(idx, item, trace):
        trace.add("action", "phase " + item)
        return item

    walked, trace = asyncio.run(run_bounded_loop(list(spec["loop_phases"]), step,
                                                 max_steps=spec["loop_max_steps"]))
    shown = trace.to_dict()
    rows = []
    for probe in spec["primitive_probes"]:
        gate = yuyay_gate(probe["text"])
        factor = hatun_mcp_factor(authenticated=probe["authenticated"], scope_ok=probe["scope_ok"],
                                  reputation=0.7, state_changing=probe["state_changing"],
                                  two_person=False)
        ok = chain.verify()
        trip = hukla_check(chain_ok=ok, yuyay=gate, latency_s=0.0, latency_budget_s=5.0,
                           action_space=1)
        score = puriq_utility(lam=1.0, yuyay=gate, hukla_tripwire=trip, khipu_chain_ok=ok,
                              hatun_factor=factor)
        rows.append({"id": probe["id"], "yuyay_passed": bool(gate.passed),
                     "blocked_axis": gate.blocked_axis, "tripwire": trip,
                     "factor_text": text(factor), "utility_text": text(score),
                     "vetoed": not (score > 0.0)})
    out["kernel"] = {"state": "EXECUTED", "loop": {"exit": shown["exit"], "steps": shown["steps"],
                     "max_budget": shown["maxBudget"], "doctrine": shown["doctrine"],
                     "walked": walked}, "chain_verified": bool(chain.verify()),
                     "signer_mode": signer.mode, "primitives": rows}
except Exception as exc:
    out["kernel"] = {"state": "UNAVAILABLE", "reason": type(exc).__name__}

async def exchange():
    found = importlib.util.find_spec("mcp")
    if found is None or sdk_version is None or inside(found.origin):
        raise ModuleNotFoundError("mcp is not installed in this interpreter")
    from mcp import Client as connect
    from hatun_mcp import server as S
    result = {"state": "EXECUTED", "reason": None, "sdk_version": sdk_version, "probes": []}
    for probe in spec["mcp_probes"]:
        # hatun-mcp's own test hooks set the caller; the API-key path is not exercised.
        if probe["context"] == "ANONYMOUS":
            S._set_test_context(client_id="braid-anonymous", scope="read")
            S._ctx_client.set(None)
        else:
            S._set_test_context(client_id="braid-local-demo", scope="admin")
        async with connect(S.mcp) as client:
            result["server_name"] = client.server_info.name
            result["server_version"] = client.server_info.version
            result["protocol_version"] = str(client.protocol_version)
            result["tool_count"] = len((await client.list_tools()).tools)
            reply = await client.call_tool(probe["tool"], probe["arguments"])
            body = json.loads(reply.content[0].text)
        declined = body.get("gate_transparency") or {}
        receipt = body.get("khipu_receipt") or {}
        envelope = body.get("dsse") or {}
        result["probes"].append({
            "id": probe["id"], "tool": probe["tool"], "status": body.get("status"),
            "decline_reason": declined.get("reason"), "owasp_class": declined.get("owasp_class"),
            "tripwire": receipt.get("tripwire"), "chain_verified": receipt.get("chain_verified"),
            "backend_started": body.get("backend") is not None,
            "backend_endpoint": (body.get("backend") or {}).get("endpoint"),
            "signer_mode": envelope.get("_mode"),
            "signature_count": len(envelope.get("signatures") or [])})
    result["chain_depth"] = S.KHIPU.depth()
    result["chain_verified"] = bool(S.KHIPU.verify())
    return result

try:
    out["mcp"] = asyncio.run(exchange())
except ImportError as exc:
    out["mcp"] = {"state": "UNAVAILABLE", "reason": "IMPORT_" + type(exc).__name__}
except Exception as exc:
    out["mcp"] = {"state": "UNAVAILABLE", "reason": type(exc).__name__}
loaded = [m for n, m in list(sys.modules.items()) if n == "hatun_mcp" or n.startswith("hatun_mcp.")]
out["process"]["hatun_modules_loaded"] = len(loaded)
out["process"]["hatun_modules_outside_export"] = sum(not from_export(m) for m in loaded)
try:
    owners = metadata.packages_distributions()
    tops = {name.split(".")[0] for name in list(sys.modules)}
    out["distributions"] = [[d, version(d)] for d in sorted({d for t in tops
                                                              for d in owners.get(t, ())})]
except Exception:
    out["distributions"] = None
sys.stdout.write(json.dumps(out, sort_keys=True))
'''


def validate_policy(section) -> dict:
    """Validate the ``hatun`` section of the braid v2 policy."""
    closed(section, ("repository", "source_glob", "loop_phases", "loop_max_steps",
                     "primitive_probes", "mcp_probes"), "HATUN_POLICY_FIELDS_INVALID")
    require(type(section["repository"]) is str and REPOSITORY.fullmatch(section["repository"])
            and section["source_glob"] == "hatun_mcp/" and
            type(section["loop_phases"]) is list and len(section["loop_phases"]) == 5 and
            all(type(p) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{2,47}", p)
                for p in section["loop_phases"]) and
            type(section["loop_max_steps"]) is int and section["loop_max_steps"] == 5,
            "HATUN_POLICY_INVALID")
    ids = []
    primitives = section["primitive_probes"]
    require(type(primitives) is list and 0 < len(primitives) <= MAX_PROBES,
            "HATUN_POLICY_INVALID")
    for probe in primitives:
        closed(probe, ("id", "text", "authenticated", "scope_ok", "state_changing",
                       "expect_vetoed"), "HATUN_PROBE_FIELDS_INVALID")
        require(type(probe["id"]) is str and PROBE_ID.fullmatch(probe["id"]) and
                type(probe["text"]) is str and 0 < len(probe["text"]) <= 400 and
                all(type(probe[k]) is bool for k in ("authenticated", "scope_ok",
                                                     "state_changing", "expect_vetoed")),
                "HATUN_PROBE_FIELDS_INVALID")
        ids.append(probe["id"])
    exchanges = section["mcp_probes"]
    require(type(exchanges) is list and 0 < len(exchanges) <= MAX_PROBES, "HATUN_POLICY_INVALID")
    for probe in exchanges:
        closed(probe, ("id", "tool", "arguments", "context", "expect_status", "expect_reason"),
               "HATUN_PROBE_FIELDS_INVALID")
        require(type(probe["id"]) is str and PROBE_ID.fullmatch(probe["id"]) and
                type(probe["tool"]) is str and TOOL.fullmatch(probe["tool"]) and
                type(probe["arguments"]) is dict and len(json.dumps(probe["arguments"])) <= 800
                and probe["context"] in ("LOCAL_DEMO", "ANONYMOUS") and
                probe["expect_status"] in ("success", "declined") and
                (probe["expect_reason"] is None) == (probe["expect_status"] == "success") and
                (probe["expect_reason"] is None or
                 (type(probe["expect_reason"]) is str and CODE.fullmatch(probe["expect_reason"]))),
                "HATUN_PROBE_FIELDS_INVALID")
        ids.append(probe["id"])
    require(len(ids) == len(set(ids)), "HATUN_PROBE_DUPLICATE")
    return section


def source_identity(checkout: Path) -> tuple:
    """``(commit, digest)`` after proving the working files ARE the committed blobs.

    The digest names the committed ``hatun_mcp/*.py`` set. The child never runs
    these working files; it runs an export of the same commit.
    """
    commit, _shallow, rows = list_tree(checkout)
    pinned = sorted((path, sha) for mode, kind, sha, _size, path in rows
                    if kind == "blob" and path.startswith("hatun_mcp/") and path.endswith(".py"))
    require(len(pinned) > 0, "HATUN_SOURCE_MISSING")
    for path, sha in pinned:
        target = checkout / path
        require(target.is_file() and not target.is_symlink(), "HATUN_SOURCE_MISSING")
        # A checkout whose files differ from HEAD is refused, so no one mistakes what was run.
        require(git_blob_sha1(target.read_bytes()) == sha, "HATUN_WORKTREE_DIFFERS_FROM_COMMIT")
    return commit, digest([[path, sha] for path, sha in pinned])


def exported_modules_digest(root: Path) -> str:
    """The same digest as ``source_identity``, recomputed from the exported bytes."""
    pinned = []
    for path in (root / "hatun_mcp").rglob("*.py"):
        require(path.is_file() and not path.is_symlink(), "HATUN_EXPORT_MISMATCH")
        pinned.append([path.relative_to(root).as_posix(), git_blob_sha1(path.read_bytes())])
    return digest(sorted(pinned))


def child_limits() -> dict:
    return {"timeout_seconds": CHILD_TIMEOUT_SECONDS, "cpu_seconds": CHILD_CPU_SECONDS,
            "address_space_bytes": CHILD_ADDRESS_BYTES, "file_size_bytes": CHILD_FILE_BYTES,
            "max_output_bytes": MAX_WITNESS_BYTES}


def _child_environment(home: Path, temp: Path) -> dict:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temp), "LANG": "C.UTF-8",
           "HATUN_MCP_DISABLE_DYNAMIC": "true", "HATUN_MCP_LOCAL_AUTH": "true",
           "NO_PROXY": "*", "no_proxy": "*"}
    env.update({name: DEAD_ENDPOINT for name in _BACKEND_VARS})
    return env


def _interpreter_ok(python) -> bool:
    return (type(python) is str and os.path.isabs(python) and os.path.isfile(python) and
            os.access(python, os.X_OK))


def _same_path(seen, expected: str) -> bool:
    return type(seen) is str and os.path.realpath(seen) == expected


def _count(value):
    return value if type(value) is int and 0 <= value <= MAX_COUNT else None


def run_child(checkout: Path, section: dict, *, python: str, commit: str | None = None,
              modules_digest: str | None = None) -> tuple:
    """Export ``commit`` of ``checkout`` and run the driver over that export only.

    Returns ``(child_report, observed)``: the child's own JSON, and what this
    process observed about the run (namespace, export, interpreter mode, where
    the loaded Hatun modules came from).
    """
    require(_interpreter_ok(python), "HATUN_CHILD_UNAVAILABLE")
    if commit is None or modules_digest is None:
        commit, modules_digest = source_identity(checkout)
    request = {"loop_phases": section["loop_phases"], "loop_max_steps": section["loop_max_steps"],
               "primitive_probes": [{k: p[k] for k in ("id", "text", "authenticated", "scope_ok",
                                                        "state_changing")}
                                    for p in section["primitive_probes"]],
               "mcp_probes": [{k: p[k] for k in ("id", "tool", "arguments", "context")}
                              for p in section["mcp_probes"]]}
    with tempfile.TemporaryDirectory(prefix="braid-hatun-") as scratch:
        base = Path(scratch)
        export, cache, home, temp, work = (base / name for name in
                                           ("export", "pycache", "home", "tmp", "work"))
        for directory in (export, cache, home, temp, work):
            directory.mkdir()
        counts = export_tree(checkout, commit, export, max_blob_bytes=EXPORT_MAX_BLOB_BYTES,
                             max_total_bytes=EXPORT_MAX_TOTAL_BYTES)
        require(exported_modules_digest(export) == modules_digest, "HATUN_EXPORT_MISMATCH")
        prefix = os.path.realpath(cache)
        run = bounded_run([python, "-I", "-B", "-X", "pycache_prefix=" + prefix, "-c", DRIVER,
                           str(export)], cwd=work, env=_child_environment(home, temp),
                          timeout=CHILD_TIMEOUT_SECONDS, max_output=MAX_WITNESS_BYTES,
                          stdin_bytes=json.dumps(request).encode("utf-8"),
                          isolate_network=True, cpu_seconds=CHILD_CPU_SECONDS,
                          file_bytes=CHILD_FILE_BYTES, address_bytes=CHILD_ADDRESS_BYTES,
                          merge_stderr=False)
        cache_unused = not any(cache.iterdir())
    require(not run["timed_out"], "HATUN_CHILD_TIMEOUT")
    require(not run["truncated"], "HATUN_CHILD_OUTPUT_TOO_LARGE")
    require(run["exit_code"] == 0 and len(run["output"]) > 0, "HATUN_CHILD_FAILED")
    try:
        raw = json.loads(run["output"].decode("utf-8", "strict"))
    except (UnicodeError, ValueError, RecursionError):
        raise InputError("HATUN_CHILD_OUTPUT_INVALID") from None
    require(type(raw) is dict, "HATUN_CHILD_OUTPUT_INVALID")
    process = raw.get("process") if type(raw.get("process")) is dict else {}
    observed = {"network_namespace": run["network_namespace"], "export_files": counts["files"],
                "export_skipped_entries": counts["skipped_entries"],
                "isolated_mode": process.get("isolated") is True,
                "bytecode_writes_disabled": process.get("dont_write_bytecode") is True,
                "pycache_prefix_fresh_and_unused":
                    cache_unused and _same_path(process.get("pycache_prefix"), prefix),
                "hatun_modules_loaded": _count(process.get("hatun_modules_loaded")),
                "hatun_modules_outside_export":
                    _count(process.get("hatun_modules_outside_export"))}
    return raw, observed


def _text(value, limit=80):
    return value if type(value) is str and len(value) <= limit and CODE.fullmatch(value) else None


def _text_ok(value, limit) -> bool:
    return value is None or _text(value, limit) == value


def _kernel_matches(row, probe) -> bool:
    return row["vetoed"] is probe["expect_vetoed"]


def _mcp_matches(row, probe) -> bool:
    # A decline only counts when Hatun refused BEFORE starting any backend call.
    return (row["status"] == probe["expect_status"] and
            row["decline_reason"] == probe["expect_reason"] and
            (probe["expect_status"] == "success" or row["backend_started"] is False))


def _ladder_state(kernel, mcp, matched, expected) -> str:
    conforms = (kernel["state"] == "EXECUTED" and mcp["state"] == "EXECUTED" and
                matched == expected and kernel["loop_exit"] == "converged" and
                kernel["loop_walked_all_phases"] is True and kernel["chain_verified"] is True and
                mcp["chain_verified"] is True)
    return STATES[0] if conforms else STATES[1]


def _rows_by_id(value) -> dict:
    rows = [r for r in value if type(r) is dict] if type(value) is list else []
    ids = [r.get("id") for r in rows]
    # A probe the child reported twice is treated as not observed at all.
    return {r["id"]: r for r in rows if type(r.get("id")) is str and ids.count(r["id"]) == 1}


def _boolean(value):
    return value if type(value) is bool else None


def _optional_bool(value) -> bool:
    return value is None or type(value) is bool


def _kernel_tier(section, value) -> dict:
    raw = value if type(value) is dict else {}
    if raw.get("state") != "EXECUTED":
        return {"state": "UNAVAILABLE", "reason": _text(raw.get("reason")),
                **{field: None for field in _LOOP_FIELDS}, "primitives": []}
    loop = raw.get("loop") if type(raw.get("loop")) is dict else {}
    seen = _rows_by_id(raw.get("primitives"))
    rows = []
    for probe in section["primitive_probes"]:
        got = seen.get(probe["id"], {})
        row = {"id": probe["id"], "state_changing": probe["state_changing"],
               "authenticated_declared": probe["authenticated"],
               "yuyay_passed": _boolean(got.get("yuyay_passed")),
               "tripwire": _text(got.get("tripwire"), 8),
               "factor_text": _text(got.get("factor_text"), 24),
               "vetoed": _boolean(got.get("vetoed")), "expect_vetoed": probe["expect_vetoed"]}
        row["matches_expected"] = _kernel_matches(row, probe)
        rows.append(row)
    return {"state": "EXECUTED", "reason": None, "loop_exit": _text(loop.get("exit"), 24),
            "loop_steps": _count(loop.get("steps")),
            "loop_max_budget": _count(loop.get("max_budget")),
            "loop_doctrine": _text(loop.get("doctrine")),
            "loop_walked_all_phases": loop.get("walked") == section["loop_phases"],
            "chain_verified": raw.get("chain_verified") is True,
            "signer_mode": _text(raw.get("signer_mode"), 24), "primitives": rows}


def _mcp_tier(section, value) -> dict:
    raw = value if type(value) is dict else {}
    if raw.get("state") != "EXECUTED":
        return {"state": "UNAVAILABLE", "reason": _text(raw.get("reason")),
                **{field: None for field in _SERVER_FIELDS}, "probes": []}
    seen = _rows_by_id(raw.get("probes"))
    rows = []
    for probe in section["mcp_probes"]:
        got = seen.get(probe["id"], {})
        row = {"id": probe["id"], "tool": probe["tool"], "context": probe["context"],
               **{field: _text(got.get(field), limit) for field, limit in _MCP_ROW_TEXT.items()},
               "backend_started": _boolean(got.get("backend_started")),
               "signature_count": _count(got.get("signature_count")),
               "expect_status": probe["expect_status"], "expect_reason": probe["expect_reason"]}
        row["matches_expected"] = _mcp_matches(row, probe)
        rows.append({field: row[field] for field in _MCP_ROW_FIELDS})
    return {"state": "EXECUTED", "reason": None, "transport": TRANSPORT,
            "server_instance": SERVER_INSTANCE,
            **{field: _text(raw.get(field), limit) for field, limit in _MCP_TEXT.items()},
            "tool_count": _count(raw.get("tool_count")),
            "chain_depth": _count(raw.get("chain_depth")),
            "chain_verified": raw.get("chain_verified") is True, "probes": rows}


def _distributions(value):
    """Sorted ``[name, version]`` pairs, or ``None`` when the child's list is not clean."""
    if type(value) is not list or len(value) > MAX_DISTRIBUTIONS:
        return None
    pairs = []
    for item in value:
        if not (type(item) is list and len(item) == 2 and type(item[0]) is str and
                DISTRIBUTION.fullmatch(item[0]) and
                (item[1] is None or (type(item[1]) is str and
                                     DISTRIBUTION_VERSION.fullmatch(item[1])))):
            return None
        pairs.append([item[0], item[1]])
    names = [name for name, _version in pairs]
    return sorted(pairs) if len(names) == len(set(names)) else None


def _child_record(observed) -> dict:
    closed(observed, _OBSERVED_FIELDS, "HATUN_OBSERVATION_INVALID")
    require(observed["network_namespace"] in (NETNS_EMPTY, NETNS_UNAVAILABLE),
            "HATUN_NETWORK_CLAIM_INVALID")
    natural(observed["export_files"], "HATUN_OBSERVATION_INVALID", maximum=MAX_EXPORT_FILES)
    natural(observed["export_skipped_entries"], "HATUN_OBSERVATION_INVALID",
            maximum=MAX_EXPORT_FILES)
    require(observed["export_files"] > 0, "HATUN_OBSERVATION_INVALID")
    require(observed["isolated_mode"] is True and observed["bytecode_writes_disabled"] is True
            and observed["pycache_prefix_fresh_and_unused"] is True, "HATUN_CHILD_NOT_ISOLATED")
    require(_count(observed["hatun_modules_loaded"]) is not None and
            observed["hatun_modules_outside_export"] == 0 and
            type(observed["hatun_modules_outside_export"]) is int,
            "HATUN_SOURCE_NOT_FROM_EXPORT")
    return {"flags": list(INTERPRETER_FLAGS), "isolated_mode": True,
            "bytecode_writes_disabled": True, "pycache_prefix_fresh_and_unused": True,
            "hatun_modules_loaded": observed["hatun_modules_loaded"],
            "hatun_modules_outside_export": 0, "limits": child_limits()}


def assemble(section, commit, modules_digest, raw, *, observed, at=None) -> dict:
    """Turn the child's report and the parent's observations into a closed witness."""
    validate_policy(section)
    require(type(raw) is dict, "HATUN_CHILD_OUTPUT_INVALID")
    child = _child_record(observed)
    kernel = _kernel_tier(section, raw.get("kernel"))
    mcp = _mcp_tier(section, raw.get("mcp"))
    expected = len(section["primitive_probes"]) + len(section["mcp_probes"])
    matched = (sum(r["matches_expected"] for r in kernel["primitives"]) +
               sum(r["matches_expected"] for r in mcp["probes"]))
    namespace = observed["network_namespace"]
    witness = {
        "schema": SCHEMA, "observed_at": (at or datetime.now(timezone.utc)).isoformat(),
        "repository": section["repository"], "commit": commit,
        "source_modules_digest": modules_digest, "source_tree": SOURCE_TREE,
        "export_files": observed["export_files"],
        "export_skipped_entries": observed["export_skipped_entries"],
        "interpreter": {"python": _text(raw.get("python"), 16), "site_packages": SITE_PACKAGES,
                        "loaded_distributions": _distributions(raw.get("distributions"))},
        "child": child, "kernel": kernel, "mcp": mcp,
        "probes_expected": expected, "probes_matched": matched,
        "state": _ladder_state(kernel, mcp, matched, expected),
        "effect_authority": "NOT_ATTACHED", "caller_identity": CALLER_IDENTITY,
        "caller_context": CALLER_CONTEXT, "api_key_authentication_path_exercised": False,
        "backend_endpoints_disabled_by_environment": True, "network_namespace": namespace,
        "direct_network_egress_blocked": namespace == NETNS_EMPTY,
        "policy_section_sha256": digest(section),
    }
    witness.update({flag: False for flag in _FALSE_FLAGS})
    validate_witness(witness, section)
    return witness


def _timestamp_ok(value) -> bool:
    if type(value) is not str or len(value) > 48:
        return False
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return stamp.utcoffset() is not None


def _check_rows(rows, probes, fields, policy_fields, texts, observed_ok):
    """Shape, policy binding and observed-value types of one tier's rows."""
    require(type(rows) is list, "HATUN_WITNESS_FIELDS_INVALID")
    for row in rows:
        closed(row, fields, "HATUN_WITNESS_ROW_FIELDS_INVALID")
    require([row["id"] for row in rows] == [probe["id"] for probe in probes] and
            all(row[mine] == probe[theirs] and type(row[mine]) is type(probe[theirs])
                for row, probe in zip(rows, probes) for mine, theirs in policy_fields),
            "HATUN_WITNESS_ROWS_NOT_POLICY")
    require(all(_text_ok(row[field], limit) for row in rows for field, limit in texts.items())
            and all(observed_ok(row) for row in rows), "HATUN_WITNESS_ROW_FIELDS_INVALID")


def _check_kernel(kernel, section) -> int:
    closed(kernel, _KERNEL_FIELDS, "HATUN_WITNESS_FIELDS_INVALID")
    require(kernel["state"] in ("EXECUTED", "UNAVAILABLE") and
            type(kernel["primitives"]) is list, "HATUN_WITNESS_FIELDS_INVALID")
    if kernel["state"] == "UNAVAILABLE":
        require(_text_ok(kernel["reason"], 80) and kernel["primitives"] == [] and
                all(kernel[field] is None for field in _LOOP_FIELDS),
                "HATUN_UNAVAILABLE_NOT_UNKNOWN")
        return 0
    require(kernel["reason"] is None and
            all(_text_ok(kernel[field], limit) for field, limit in _KERNEL_TEXT.items()) and
            all(kernel[field] is None or _count(kernel[field]) is not None
                for field in ("loop_steps", "loop_max_budget")) and
            type(kernel["loop_walked_all_phases"]) is bool and
            type(kernel["chain_verified"]) is bool, "HATUN_WITNESS_FIELDS_INVALID")
    probes = section["primitive_probes"]
    _check_rows(kernel["primitives"], probes, _KERNEL_ROW_FIELDS,
                (("state_changing", "state_changing"), ("authenticated_declared", "authenticated"),
                 ("expect_vetoed", "expect_vetoed")), _KERNEL_ROW_TEXT,
                lambda row: _optional_bool(row["vetoed"]) and _optional_bool(row["yuyay_passed"])
                and type(row["matches_expected"]) is bool)
    require(all(row["matches_expected"] is _kernel_matches(row, probe)
                for row, probe in zip(kernel["primitives"], probes)), "HATUN_MATCH_NOT_DERIVED")
    return sum(row["matches_expected"] for row in kernel["primitives"])


def _check_mcp(mcp, section) -> int:
    closed(mcp, _MCP_FIELDS, "HATUN_WITNESS_FIELDS_INVALID")
    require(mcp["state"] in ("EXECUTED", "UNAVAILABLE") and type(mcp["probes"]) is list,
            "HATUN_WITNESS_FIELDS_INVALID")
    if mcp["state"] == "UNAVAILABLE":
        require(_text_ok(mcp["reason"], 80) and mcp["probes"] == [] and
                all(mcp[field] is None for field in _SERVER_FIELDS),
                "HATUN_UNAVAILABLE_NOT_UNKNOWN")
        return 0
    require(mcp["reason"] is None and mcp["transport"] == TRANSPORT and
            mcp["server_instance"] == SERVER_INSTANCE and
            all(_text_ok(mcp[field], limit) for field, limit in _MCP_TEXT.items()) and
            all(mcp[field] is None or _count(mcp[field]) is not None
                for field in ("tool_count", "chain_depth")) and
            type(mcp["chain_verified"]) is bool, "HATUN_WITNESS_FIELDS_INVALID")
    probes = section["mcp_probes"]
    _check_rows(mcp["probes"], probes, _MCP_ROW_FIELDS,
                (("tool", "tool"), ("context", "context"), ("expect_status", "expect_status"),
                 ("expect_reason", "expect_reason")), _MCP_ROW_TEXT,
                lambda row: _optional_bool(row["backend_started"]) and
                (row["signature_count"] is None or _count(row["signature_count"]) is not None)
                and type(row["matches_expected"]) is bool)
    require(all(row["matches_expected"] is _mcp_matches(row, probe)
                for row, probe in zip(mcp["probes"], probes)), "HATUN_MATCH_NOT_DERIVED")
    return sum(row["matches_expected"] for row in mcp["probes"])


def _check_interpreter(value):
    closed(value, _INTERPRETER_FIELDS, "HATUN_WITNESS_FIELDS_INVALID")
    loaded = value["loaded_distributions"]
    require(_text_ok(value["python"], 16) and value["site_packages"] == SITE_PACKAGES and
            (loaded is None or _distributions(loaded) == loaded), "HATUN_WITNESS_FIELDS_INVALID")


def _check_child(value):
    closed(value, _CHILD_FIELDS, "HATUN_CHILD_RECORD_INVALID")
    require(value["flags"] == list(INTERPRETER_FLAGS) and value["isolated_mode"] is True and
            value["bytecode_writes_disabled"] is True and
            value["pycache_prefix_fresh_and_unused"] is True and
            _count(value["hatun_modules_loaded"]) is not None and
            value["hatun_modules_outside_export"] == 0 and
            type(value["hatun_modules_outside_export"]) is int and
            value["limits"] == child_limits(), "HATUN_CHILD_RECORD_INVALID")


def validate_witness(value, section) -> bool:
    """Closed-schema check that re-derives every match, count and state from the record."""
    validate_policy(section)
    closed(value, _WITNESS_FIELDS, "HATUN_WITNESS_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and value["repository"] == section["repository"] and
            type(value["commit"]) is str and SHA40.fullmatch(value["commit"]) and
            type(value["source_modules_digest"]) is str and
            SHA64.fullmatch(value["source_modules_digest"]) and
            value["source_tree"] == SOURCE_TREE and
            value["policy_section_sha256"] == digest(section), "HATUN_WITNESS_BINDING_INVALID")
    natural(value["export_files"], "HATUN_WITNESS_FIELDS_INVALID", maximum=MAX_EXPORT_FILES)
    natural(value["export_skipped_entries"], "HATUN_WITNESS_FIELDS_INVALID",
            maximum=MAX_EXPORT_FILES)
    require(value["export_files"] > 0, "HATUN_WITNESS_FIELDS_INVALID")
    require(_timestamp_ok(value["observed_at"]), "HATUN_TIMESTAMP_INVALID")
    require(all(value[flag] is False for flag in _FALSE_FLAGS) and
            value["effect_authority"] == "NOT_ATTACHED" and
            value["caller_identity"] == CALLER_IDENTITY and
            value["caller_context"] == CALLER_CONTEXT and
            value["api_key_authentication_path_exercised"] is False and
            value["backend_endpoints_disabled_by_environment"] is True,
            "HATUN_FALSE_AUTHORITY_CLAIM")
    # Isolation is claimed only for an observed empty namespace, never otherwise.
    require(value["network_namespace"] in (NETNS_EMPTY, NETNS_UNAVAILABLE) and
            value["direct_network_egress_blocked"] is (value["network_namespace"] == NETNS_EMPTY),
            "HATUN_NETWORK_CLAIM_INVALID")
    _check_interpreter(value["interpreter"])
    _check_child(value["child"])
    natural(value["probes_expected"], "HATUN_WITNESS_FIELDS_INVALID", maximum=2 * MAX_PROBES)
    natural(value["probes_matched"], "HATUN_WITNESS_FIELDS_INVALID", maximum=2 * MAX_PROBES)
    require(type(value["kernel"]) is dict and type(value["mcp"]) is dict,
            "HATUN_WITNESS_FIELDS_INVALID")
    matched = _check_kernel(value["kernel"], section) + _check_mcp(value["mcp"], section)
    expected = len(section["primitive_probes"]) + len(section["mcp_probes"])
    require(value["probes_expected"] == expected and value["probes_matched"] == matched,
            "HATUN_PROBE_COUNT_MISMATCH")
    require(value["state"] == _ladder_state(value["kernel"], value["mcp"], matched, expected),
            "HATUN_STATE_DRIFT")
    return True


def observe(section, checkout: Path, *, python: str, at=None) -> dict:
    """Bind the source to its commit, run the ladder over an export of it, return the witness."""
    validate_policy(section)
    commit, modules_digest = source_identity(checkout)
    raw, observed = run_child(checkout, section, python=python, commit=commit,
                              modules_digest=modules_digest)
    return assemble(section, commit, modules_digest, raw, observed=observed, at=at)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local Hatun veto-ladder conformance, committed code")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--hatun-checkout", type=Path, required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        policy, _ = read_json(args.policy, max_bytes=1048576)
        require(type(policy) is dict and "hatun" in policy, "HATUN_POLICY_FIELDS_INVALID")
        require(os.path.isabs(args.python) and Path(args.python).is_file(),
                "HATUN_INTERPRETER_INVALID")
        witness = observe(policy["hatun"], args.hatun_checkout, python=args.python)
        strict_json(json.dumps(witness).encode("utf-8"), max_bytes=MAX_WITNESS_BYTES)
        write_exclusive(args.output, witness, max_bytes=MAX_WITNESS_BYTES,
                        checkout=checkout_root())
        print(json.dumps({"state": witness["state"], "kernel": witness["kernel"]["state"],
                          "mcp": witness["mcp"]["state"],
                          "probes_matched": witness["probes_matched"],
                          "probes_expected": witness["probes_expected"],
                          "network_namespace": witness["network_namespace"],
                          "effect_authority": "NOT_ATTACHED",
                          "external_effects_performed": False}))
        return 0 if witness["state"] == "VETO_LADDER_CONFORMS" else 2
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "HATUN_GATE_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "effect_authority": "NOT_ATTACHED",
                      "external_effects_performed": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
