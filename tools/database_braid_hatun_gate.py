#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the pinned Hatun veto ladder locally for the SZL Ouroboros braid v2.

Runs committed ``hatun-mcp`` source in a child interpreter whose environment
carries no proxy, no receipt sink and no signing key, so nothing can leave the
machine. Two tiers are attempted and reported separately:

* KERNEL: Hatun's bounded loop walks the braid's five phases and its gate
  primitives rule on reviewed probes (standard library only).
* MCP: the real Hatun server object answers genuine JSON-RPC (initialize,
  tools/list, tools/call) through the MCP SDK's in-memory session, and its
  ``governed()`` ladder must decline exactly the probes the reviewed policy
  says it must decline. Reported UNAVAILABLE when the SDK is not installed.

What a pass means: this committed code, run here, vetoed what the policy
expected it to veto. What it does NOT mean: no deployed Hatun runtime was
contacted, the caller is a local demo context and not an identity, the signer
is a labelled placeholder, no second approver exists (and is never claimed),
and Hatun does not understand action text: the braid classifies effects
itself and treats every database work order as state-changing. Hatun can veto
and receipt; nothing here attaches effect authority.
"""
from __future__ import annotations

import argparse
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
        REPOSITORY, SHA40, SHA64, checkout_root, closed, digest, git_blob_sha1, natural,
        read_json, require, strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import list_tree
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, digest, git_blob_sha1, natural,
        read_json, require, strict_json, write_exclusive,
    )
    from tools.database_braid_source_census import list_tree
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-hatun-witness/v1"
PROBE_ID = re.compile(r"[a-z][a-z0-9_]{2,47}\Z")
TOOL = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")
CODE = re.compile(r"[A-Za-z0-9_.() -]{0,80}\Z")
MAX_PROBES = 24
MAX_WITNESS_BYTES = 262144
CHILD_TIMEOUT_SECONDS = 180
DEAD_ENDPOINT = "http://127.0.0.1:9"
_BACKEND_VARS = ("SZL_A11OY_URL", "SZL_LLM_URL", "SZL_IMMUNE_URL", "SZL_KILLINCHU_URL",
                 "SZL_COMPANION_URL", "SZL_LEAN_URL", "SZL_ANATOMY_URL", "SZL_SECOND_BRAIN_URL",
                 "HATUN_MCP_AXLE_URL")
_FALSE_FLAGS = ("deployed_runtime_contacted", "signer_identity_established",
                "two_person_approval_claimed", "external_effects_performed",
                "production_authorized")
_WITNESS_FIELDS = (
    "schema", "observed_at", "repository", "commit", "source_modules_digest",
    "source_tree_matches_commit", "interpreter", "kernel", "mcp", "probes_expected",
    "probes_matched", "state", "effect_authority", "caller_identity",
    "network_isolated_by_environment", "policy_section_sha256", *_FALSE_FLAGS,
)

# Runs inside the child interpreter. It only ever sees committed Hatun source.
DRIVER = r'''
import asyncio, json, os, sys
root = sys.argv[1]
spec = json.loads(sys.stdin.read())
os.environ["HATUN_MCP_DISABLE_DYNAMIC"] = "true"
for name in ("SZL_RECEIPT_SINK", "HATUN_MCP_SIGNING_KEY", "HATUN_MCP_SIGNING_KEY_PATH"):
    os.environ.pop(name, None)
sys.path.insert(0, root)
out = {"python": "%d.%d.%d" % sys.version_info[:3], "kernel": None, "mcp": None}

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
    from mcp import Client as connect
    from hatun_mcp import server as S
    import importlib.metadata as metadata
    result = {"state": "EXECUTED", "reason": None, "sdk_version": metadata.version("mcp"),
              "probes": []}
    for probe in spec["mcp_probes"]:
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
    """``(commit, digest)`` after proving the working files ARE the committed blobs."""
    commit, _shallow, rows = list_tree(checkout)
    pinned = sorted((path, sha) for mode, kind, sha, _size, path in rows
                    if kind == "blob" and path.startswith("hatun_mcp/") and path.endswith(".py"))
    require(len(pinned) > 0, "HATUN_SOURCE_MISSING")
    for path, sha in pinned:
        target = checkout / path
        require(target.is_file() and not target.is_symlink(), "HATUN_SOURCE_MISSING")
        # The code about to run must be byte-identical to the committed object.
        require(git_blob_sha1(target.read_bytes()) == sha, "HATUN_WORKTREE_DIFFERS_FROM_COMMIT")
    return commit, digest([[path, sha] for path, sha in pinned])


def _child_environment(home: Path) -> dict:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8",
           "HATUN_MCP_DISABLE_DYNAMIC": "true", "HATUN_MCP_LOCAL_AUTH": "true",
           "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": "*"}
    env.update({name: DEAD_ENDPOINT for name in _BACKEND_VARS})
    return env


def run_child(checkout: Path, section: dict, *, python: str) -> dict:
    """Run the driver under ``python`` with a secret-free, proxy-free environment."""
    request = {"loop_phases": section["loop_phases"], "loop_max_steps": section["loop_max_steps"],
               "primitive_probes": [{k: p[k] for k in ("id", "text", "authenticated", "scope_ok",
                                                        "state_changing")}
                                    for p in section["primitive_probes"]],
               "mcp_probes": [{k: p[k] for k in ("id", "tool", "arguments", "context")}
                              for p in section["mcp_probes"]]}
    with tempfile.TemporaryDirectory(prefix="braid-hatun-") as scratch:
        driver = Path(scratch) / "driver.py"
        driver.write_text(DRIVER, encoding="utf-8")
        try:
            proc = subprocess.run(
                [python, "-I", "-B", str(driver), str(checkout)],
                input=json.dumps(request).encode("utf-8"), stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, cwd=scratch, env=_child_environment(Path(scratch)),
                timeout=CHILD_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise InputError("HATUN_CHILD_UNAVAILABLE") from None
    require(proc.returncode == 0 and 0 < len(proc.stdout) <= MAX_WITNESS_BYTES,
            "HATUN_CHILD_FAILED")
    try:
        return json.loads(proc.stdout.decode("utf-8", "strict"))
    except (UnicodeError, ValueError):
        raise InputError("HATUN_CHILD_OUTPUT_INVALID") from None


def _text(value, limit=80):
    return value if type(value) is str and len(value) <= limit and CODE.fullmatch(value) else None


def assemble(section, commit, modules_digest, raw, *, at=None) -> dict:
    """Turn the child's report into a closed witness and score it against the policy."""
    validate_policy(section)
    require(type(raw) is dict, "HATUN_CHILD_OUTPUT_INVALID")
    expected, matched = 0, 0
    kernel_raw = raw.get("kernel") if type(raw.get("kernel")) is dict else {}
    if kernel_raw.get("state") == "EXECUTED":
        loop = kernel_raw.get("loop") if type(kernel_raw.get("loop")) is dict else {}
        got = {r.get("id"): r for r in kernel_raw.get("primitives", []) if type(r) is dict}
        rows = []
        for probe in section["primitive_probes"]:
            seen = got.get(probe["id"], {})
            vetoed = seen.get("vetoed") if type(seen.get("vetoed")) is bool else None
            expected += 1
            matched += vetoed is probe["expect_vetoed"]
            rows.append({"id": probe["id"], "state_changing": probe["state_changing"],
                         "authenticated_declared": probe["authenticated"],
                         "yuyay_passed": seen.get("yuyay_passed")
                         if type(seen.get("yuyay_passed")) is bool else None,
                         "tripwire": _text(seen.get("tripwire"), 8),
                         "factor_text": _text(seen.get("factor_text"), 24),
                         "vetoed": vetoed, "expect_vetoed": probe["expect_vetoed"],
                         "matches_expected": vetoed is probe["expect_vetoed"]})
        walked = loop.get("walked")
        kernel = {"state": "EXECUTED", "reason": None,
                  "loop_exit": _text(loop.get("exit"), 24),
                  "loop_steps": loop.get("steps") if type(loop.get("steps")) is int else None,
                  "loop_max_budget": loop.get("max_budget")
                  if type(loop.get("max_budget")) is int else None,
                  "loop_doctrine": _text(loop.get("doctrine")),
                  "loop_walked_all_phases": walked == section["loop_phases"],
                  "chain_verified": kernel_raw.get("chain_verified") is True,
                  "signer_mode": _text(kernel_raw.get("signer_mode"), 24), "primitives": rows}
    else:
        expected += len(section["primitive_probes"])
        kernel = {"state": "UNAVAILABLE", "reason": _text(kernel_raw.get("reason")),
                  "loop_exit": None, "loop_steps": None, "loop_max_budget": None,
                  "loop_doctrine": None, "loop_walked_all_phases": None, "chain_verified": None,
                  "signer_mode": None, "primitives": []}
    mcp_raw = raw.get("mcp") if type(raw.get("mcp")) is dict else {}
    if mcp_raw.get("state") == "EXECUTED":
        got = {r.get("id"): r for r in mcp_raw.get("probes", []) if type(r) is dict}
        rows = []
        for probe in section["mcp_probes"]:
            seen = got.get(probe["id"], {})
            status, reason = _text(seen.get("status"), 16), _text(seen.get("decline_reason"))
            started = seen.get("backend_started") if type(seen.get("backend_started")) is bool else None
            # A decline only counts when Hatun refused BEFORE starting any backend call.
            ok = (status == probe["expect_status"] and reason == probe["expect_reason"] and
                  (probe["expect_status"] == "success" or started is False))
            expected += 1
            matched += ok
            rows.append({"id": probe["id"], "tool": probe["tool"], "context": probe["context"],
                         "status": status, "decline_reason": reason,
                         "owasp_class": _text(seen.get("owasp_class"), 16),
                         "tripwire": _text(seen.get("tripwire"), 8),
                         "backend_started": started,
                         "backend_endpoint": _text(seen.get("backend_endpoint")),
                         "signer_mode": _text(seen.get("signer_mode"), 24),
                         "signature_count": seen.get("signature_count")
                         if type(seen.get("signature_count")) is int else None,
                         "expect_status": probe["expect_status"],
                         "expect_reason": probe["expect_reason"], "matches_expected": ok})
        mcp = {"state": "EXECUTED", "reason": None,
               "transport": "MCP_SDK_IN_MEMORY_JSON_RPC",
               "server_instance": "LOCAL_PROCESS_COMMITTED_SOURCE",
               "sdk_version": _text(mcp_raw.get("sdk_version"), 24),
               "server_name": _text(mcp_raw.get("server_name"), 40),
               "server_version": _text(mcp_raw.get("server_version"), 24),
               "protocol_version": _text(mcp_raw.get("protocol_version"), 24),
               "tool_count": mcp_raw.get("tool_count")
               if type(mcp_raw.get("tool_count")) is int else None,
               "chain_depth": mcp_raw.get("chain_depth")
               if type(mcp_raw.get("chain_depth")) is int else None,
               "chain_verified": mcp_raw.get("chain_verified") is True, "probes": rows}
    else:
        expected += len(section["mcp_probes"])
        mcp = {"state": "UNAVAILABLE", "reason": _text(mcp_raw.get("reason")),
               "transport": None, "server_instance": None, "sdk_version": None,
               "server_name": None, "server_version": None, "protocol_version": None,
               "tool_count": None, "chain_depth": None, "chain_verified": None, "probes": []}
    both = kernel["state"] == "EXECUTED" and mcp["state"] == "EXECUTED"
    witness = {
        "schema": SCHEMA, "observed_at": (at or datetime.now(timezone.utc)).isoformat(),
        "repository": section["repository"], "commit": commit,
        "source_modules_digest": modules_digest, "source_tree_matches_commit": True,
        "interpreter": {"python": _text(raw.get("python"), 16)},
        "kernel": kernel, "mcp": mcp,
        "probes_expected": expected, "probes_matched": matched,
        "state": "VETO_LADDER_CONFORMS" if both and matched == expected else "HOLD",
        "effect_authority": "NOT_ATTACHED",
        "caller_identity": "LOCAL_DEMO_CONTEXT_NOT_AN_IDENTITY",
        "network_isolated_by_environment": True,
        "policy_section_sha256": digest(section),
    }
    witness.update({flag: False for flag in _FALSE_FLAGS})
    validate_witness(witness, section)
    return witness


def validate_witness(value, section) -> bool:
    """Closed-schema check of a witness against the reviewed policy section."""
    validate_policy(section)
    closed(value, _WITNESS_FIELDS, "HATUN_WITNESS_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and value["repository"] == section["repository"] and
            type(value["commit"]) is str and SHA40.fullmatch(value["commit"]) and
            type(value["source_modules_digest"]) is str and
            SHA64.fullmatch(value["source_modules_digest"]) and
            value["source_tree_matches_commit"] is True and
            value["policy_section_sha256"] == digest(section), "HATUN_WITNESS_BINDING_INVALID")
    require(all(value[flag] is False for flag in _FALSE_FLAGS) and
            value["effect_authority"] == "NOT_ATTACHED" and
            value["caller_identity"] == "LOCAL_DEMO_CONTEXT_NOT_AN_IDENTITY" and
            value["network_isolated_by_environment"] is True, "HATUN_FALSE_AUTHORITY_CLAIM")
    natural(value["probes_expected"], "HATUN_WITNESS_FIELDS_INVALID", maximum=2 * MAX_PROBES)
    natural(value["probes_matched"], "HATUN_WITNESS_FIELDS_INVALID", maximum=2 * MAX_PROBES)
    kernel, mcp = value["kernel"], value["mcp"]
    require(type(kernel) is dict and type(mcp) is dict and
            kernel.get("state") in ("EXECUTED", "UNAVAILABLE") and
            mcp.get("state") in ("EXECUTED", "UNAVAILABLE") and
            type(kernel.get("primitives")) is list and type(mcp.get("probes")) is list,
            "HATUN_WITNESS_FIELDS_INVALID")
    counted = sum(1 for r in kernel["primitives"] if r.get("matches_expected") is True)
    counted += sum(1 for r in mcp["probes"] if r.get("matches_expected") is True)
    require(value["probes_expected"] == len(section["primitive_probes"]) +
            len(section["mcp_probes"]) and value["probes_matched"] == counted and
            counted <= value["probes_expected"], "HATUN_PROBE_COUNT_MISMATCH")
    conforms = (kernel["state"] == "EXECUTED" and mcp["state"] == "EXECUTED" and
                counted == value["probes_expected"] and
                kernel.get("loop_exit") == "converged" and
                kernel.get("loop_walked_all_phases") is True and
                kernel.get("chain_verified") is True and mcp.get("chain_verified") is True)
    require(value["state"] == ("VETO_LADDER_CONFORMS" if conforms else "HOLD"),
            "HATUN_STATE_DRIFT")
    return True


def observe(section, checkout: Path, *, python: str, at=None) -> dict:
    """Bind the source to its commit, execute the ladder, and return the witness."""
    validate_policy(section)
    commit, modules_digest = source_identity(checkout)
    return assemble(section, commit, modules_digest,
                    run_child(checkout, section, python=python), at=at)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local Hatun veto-ladder conformance (no network)")
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
