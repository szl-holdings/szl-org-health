#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one complete SZL Ouroboros braid v2 turn and leave its evidence in one directory.

Order: source census, Lean kernel witness, known answers, Hatun veto ladder,
the five-phase braid turn (consuming the previous turn when one is given), then
the unsigned canonical Lake receipt that wraps the turn. Each stage is optional
except the census: a stage that cannot run is simply absent, and the braid then
records it as UNAVAILABLE and refuses the aggregate. Nothing is ever skipped
silently and nothing is substituted. Evidence this runner produces itself is
labelled MEASURED in the turn; everything else is REPORTED.

Every external step runs from a fresh export of the committed tree (see the
witness tools), in an empty network namespace when the host allows one; each
witness records what was actually observed. The runner itself opens no network
connection.

Output is staged in a sibling directory and moved into ``--out-dir`` only after
the turn has closed, re-verified from the written files and replayed byte for
byte from them. ``--out-dir`` must be new or empty and lie outside the braid
checkout and every ``--checkout``. A refused attempt leaves ``--out-dir`` empty
and its partial files in ``<out-dir>.refused`` next to a REFUSED.json, so a
partial directory can never be mistaken for a turn.

It cannot authorize anything. Exit 0 means only that the turn closed and
re-verified, whether it closed on HOLD or on EVIDENCE_THRESHOLD_MET_NO_AUTHORITY
(the single-turn orchestrator returns 2 for the same outcome); exit 3 means a
refusal. Read ``turn.json`` for which.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

try:
    from tools import database_braid_codex_kat as kat
    from tools import database_braid_hatun_gate as hatun
    from tools import database_braid_lake_receipt as lake
    from tools import database_braid_lean_witness as lean
    from tools import database_braid_source_census as census_tool
    from tools import database_ouroboros_braid_v2 as braid
    from tools.database_braid_common import (
        REPOSITORY, checkout_root, network_namespace_state, read_json, require, sha256_hex,
        write_exclusive,
    )
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools import database_braid_codex_kat as kat
    from tools import database_braid_hatun_gate as hatun
    from tools import database_braid_lake_receipt as lake
    from tools import database_braid_lean_witness as lean
    from tools import database_braid_source_census as census_tool
    from tools import database_ouroboros_braid_v2 as braid
    from tools.database_braid_common import (
        REPOSITORY, checkout_root, network_namespace_state, read_json, require, sha256_hex,
        write_exclusive,
    )
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-turn-manifest/v2"
FILES = ("census.json", "lean_witness.json", "known_answers.json", "hatun_witness.json",
         "khipu_tree.json", "turn.json", "lake_wrap.json")
LEAN_LOGS = "lean_logs"
_DIGEST_KEYS = {"census.json": "census", "lean_witness.json": "lean_witness",
                "known_answers.json": "known_answers", "hatun_witness.json": "hatun_witness"}


def _outside(path: Path, roots) -> bool:
    resolved = path.resolve()
    return not any(resolved == r.resolve() or resolved.is_relative_to(r.resolve()) for r in roots)


def _checkouts(items) -> dict:
    checkouts = {}
    for item in items:
        name, sep, directory = item.partition("=")
        require(sep == "=" and REPOSITORY.fullmatch(name) and directory and
                name not in checkouts, "TURN_CHECKOUT_ARGUMENT_INVALID")
        checkouts[name] = Path(directory)
    return checkouts


def _stage(args, staging: Path, checkouts: dict) -> dict:
    root = checkout_root()
    policy, policy_sha = read_json(args.policy, max_bytes=braid.MAX_POLICY_BYTES)
    braid.validate_policy(policy)
    digests, stages, produced = {"policy": policy_sha}, {}, ["census"]

    def keep(name, value, limit):
        sha = write_exclusive(staging / name, value, max_bytes=limit, checkout=root)
        if name in _DIGEST_KEYS:
            digests[_DIGEST_KEYS[name]] = sha
        return sha

    family_map, map_sha = None, None
    if args.family_map is not None:
        raw_map, map_sha = read_json(args.family_map, max_bytes=census_tool.MAX_MAP_BYTES)
        family_map = census_tool.validate_family_map(raw_map)
    census = census_tool.observe(policy["census"], checkouts, family_map=family_map,
                                 policy_sha256=policy_sha, family_map_sha256=map_sha)
    keep("census.json", census, census_tool.MAX_CENSUS_BYTES)
    stages["census"] = census["state"]

    lean_witness = None
    lean_checkout = checkouts.get(policy["lean"]["repository"])
    if args.lean_toolchain_bin is not None and lean_checkout is not None:
        require(args.lean_toolchain_bin.is_absolute(), "TURN_TOOLCHAIN_PATH_INVALID")
        options = {}
        if args.lean_packages_dir is not None:
            require(args.lean_packages_dir.is_absolute(), "TURN_PACKAGES_PATH_INVALID")
            options["packages_dir"] = args.lean_packages_dir
        logs = staging / LEAN_LOGS
        logs.mkdir()
        lean_witness = lean.observe(policy["lean"], lean_checkout,
                                    toolchain_bin=args.lean_toolchain_bin, log_dir=logs,
                                    **options)
        keep("lean_witness.json", lean_witness, lean.MAX_WITNESS_BYTES)
        produced.append("lean_witness")
    stages["lean_witness"] = lean_witness["state"] if lean_witness else "NOT_RUN"

    answers = None
    if args.answers is not None:
        answer_set, set_sha = read_json(args.answers, max_bytes=kat.MAX_SET_BYTES)

        def read_current(repository, blob_sha1):
            directory = checkouts.get(repository)
            if directory is None:
                return None
            return census_tool.read_blobs(directory, [blob_sha1],
                                          max_bytes=kat.MAX_BLOB_BYTES).get(blob_sha1)

        answers = kat.check(answer_set, census, read_current=read_current, set_sha256=set_sha,
                            census_sha256=digests["census"])
        keep("known_answers.json", answers, kat.MAX_REPORT_BYTES)
        produced.append("known_answers")
    stages["known_answers"] = (f"{answers['passed']}/{answers['answers']}" if answers
                               else "NOT_RUN")

    hatun_witness = None
    hatun_checkout = checkouts.get(policy["hatun"]["repository"])
    if hatun_checkout is not None and args.python is not None:
        require(Path(args.python).is_absolute() and Path(args.python).is_file(),
                "TURN_INTERPRETER_INVALID")
        hatun_witness = hatun.observe(policy["hatun"], hatun_checkout, python=args.python)
        keep("hatun_witness.json", hatun_witness, hatun.MAX_WITNESS_BYTES)
        produced.append("hatun_witness")
    stages["hatun_witness"] = hatun_witness["state"] if hatun_witness else "NOT_RUN"

    plan = action_policy = source_policy = None
    if args.db_plan is not None:
        require(args.db_action_policy is not None and args.source_policy is not None,
                "BRAID_PLAN_POLICIES_REQUIRED")
        plan, digests["database_plan"] = read_json(args.db_plan, max_bytes=65536)
        action_policy, _ = read_json(args.db_action_policy, max_bytes=65536)
        source_policy, _ = read_json(args.source_policy, max_bytes=65536)

    previous = previous_tree = previous_wrap = None
    if args.previous_dir is not None:
        previous, digests["previous_turn"] = read_json(args.previous_dir / "turn.json",
                                                       max_bytes=braid.MAX_TURN_BYTES)
        previous_tree, digests["previous_khipu_tree"] = read_json(
            args.previous_dir / "khipu_tree.json", max_bytes=braid.MAX_TREE_BYTES)
        wrap_path = args.previous_dir / "lake_wrap.json"
        if wrap_path.is_file():
            previous_wrap, digests["previous_lake_wrap"] = read_json(wrap_path, max_bytes=65536)

    evidence = dict(lean_witness=lean_witness, hatun_witness=hatun_witness, kat_report=answers,
                    db_plan=plan, action_policy=action_policy, source_policy=source_policy,
                    previous_turn=previous, previous_tree=previous_tree,
                    previous_lake_wrap=previous_wrap,
                    previous_turn_sha256=digests.get("previous_turn"),
                    family_map=family_map, family_map_sha256=map_sha)
    report, tree = braid.turn(policy, census, input_digests=digests, produced=produced,
                              **evidence)
    keep("khipu_tree.json", tree, braid.MAX_TREE_BYTES)
    turn_sha = keep("turn.json", report, braid.MAX_TURN_BYTES)
    stages["turn"] = report["state"]

    wrap, wrap_binds = None, None
    lake_checkout = checkouts.get(policy["lake"]["repository"])
    if lake_checkout is not None and args.python is not None:
        wrap = lake.wrap_report(policy["lake"], lake_checkout, subject=report["turn_id"],
                                input_digest=report["inputs_digest"],
                                stored_object_digest=turn_sha, python=args.python)
        keep("lake_wrap.json", wrap, lake.MAX_WRAP_BYTES)
        # The next turn refuses a wrap whose adapter commit is not the one this census saw.
        row = next(r for r in census["repositories"]
                   if r["repository"] == policy["lake"]["repository"])
        wrap_binds = row["state"] == "OBSERVED" and wrap["commit"] == row["commit"]
    stages["lake_wrap"] = wrap["state"] if wrap else "NOT_RUN"

    # Read back what was written: verify it from the files alone, then replay the whole turn
    # from those same files and require identical bytes.
    def again(name, limit):
        path = staging / name
        return read_json(path, max_bytes=limit)[0] if path.is_file() else None

    turn_again = again("turn.json", braid.MAX_TURN_BYTES)
    tree_again = again("khipu_tree.json", braid.MAX_TREE_BYTES)
    consumed = previous if turn_again["previous_turn_rejected"] is None else None
    braid.verify_turn(turn_again, policy_for_shape=policy, tree=tree_again, previous=consumed)
    braid.replay_turn(
        turn_again, policy, again("census.json", census_tool.MAX_CENSUS_BYTES),
        input_digests=digests,
        **dict(evidence, lean_witness=again("lean_witness.json", lean.MAX_WITNESS_BYTES),
               hatun_witness=again("hatun_witness.json", hatun.MAX_WITNESS_BYTES),
               kat_report=again("known_answers.json", kat.MAX_REPORT_BYTES)))
    logs = staging / LEAN_LOGS
    manifest = {
        "schema": SCHEMA, "turn_id": report["turn_id"], "ordinal": report["ordinal"],
        "state": report["state"], "refusal_path": report["decision"]["refusal_path"],
        "sub_reasons": report["decision"]["sub_reasons"], "stages": stages,
        "previous_turn_rejected": report["previous_turn_rejected"],
        "evidence_produced_in_invocation": report["evidence_produced_in_invocation"],
        "host_network_namespace": network_namespace_state(),
        "verified_from_written_files": True, "replayed_byte_identical": True,
        "lake_wrap_adapter_commit_matches_census": wrap_binds,
        "files": {name: sha256_hex((staging / name).read_bytes())
                  for name in FILES if (staging / name).is_file()},
        "lean_logs": {path.name: sha256_hex(path.read_bytes())
                      for path in sorted(logs.iterdir())} if logs.is_dir() else {},
        "signed": False, "production_authorized": False, "external_effects_performed": False,
    }
    write_exclusive(staging / "manifest.json", manifest, max_bytes=262144, checkout=root)
    return manifest


def run(args) -> dict:
    checkouts = _checkouts(args.checkout)
    out = args.out_dir
    refused = out.parent / (out.name + ".refused")
    staging = out.parent / (out.name + ".staging")
    require(_outside(out, [checkout_root(), *checkouts.values()]) and not out.is_symlink() and
            (not out.exists() or (out.is_dir() and not any(out.iterdir()))) and
            not staging.exists() and not refused.exists(), "TURN_OUTPUT_DIRECTORY_DENIED")
    staging.mkdir()
    try:
        manifest = _stage(args, staging, checkouts)
    except BaseException as exc:
        code = exc.code if isinstance(exc, InputError) else "TURN_UNAVAILABLE"
        write_exclusive(staging / "REFUSED.json",
                        {"state": "REFUSED", "code": code, "is_a_turn": False,
                         "signed": False, "production_authorized": False},
                        max_bytes=4096, checkout=checkout_root())
        staging.rename(refused)
        raise
    out.mkdir(exist_ok=True)
    for path in sorted(staging.iterdir()):
        shutil.move(str(path), str(out / path.name))
    staging.rmdir()
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description="One complete, no-effect braid v2 turn")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--family-map", type=Path)
    ap.add_argument("--answers", type=Path)
    ap.add_argument("--checkout", action="append", default=[], metavar="REPOSITORY=DIRECTORY")
    ap.add_argument("--lean-toolchain-bin", "--toolchain-bin", dest="lean_toolchain_bin",
                    type=Path)
    ap.add_argument("--lean-packages-dir", "--packages-dir", dest="lean_packages_dir", type=Path,
                    help="Lake dependency cache (default: the Lean checkout's .lake/packages)")
    ap.add_argument("--python",
                    help="absolute interpreter that has the Hatun and receipt libraries")
    ap.add_argument("--db-plan", type=Path)
    ap.add_argument("--db-action-policy", type=Path)
    ap.add_argument("--source-policy", type=Path)
    ap.add_argument("--previous-dir", type=Path)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        manifest = run(args)
        print(json.dumps(manifest, sort_keys=True))
        return 0
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "TURN_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "signed": False,
                      "production_authorized": False, "external_effects_performed": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
