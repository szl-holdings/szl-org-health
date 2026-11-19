#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one complete SZL Ouroboros braid v2 turn and leave its evidence in one directory.

Order: source census, Lean kernel witness, known answers, Hatun veto ladder,
the five-phase braid turn (consuming the previous turn when one is given), then
the unsigned canonical Lake receipt that wraps the turn. Each stage is optional
except the census: a stage that cannot run is simply absent, and the braid then
records it as UNAVAILABLE and refuses the aggregate. Nothing is ever skipped
silently and nothing is substituted.

All output goes to a NEW directory outside every source tree. No network is
used by this runner. It cannot authorize anything: exit 0 means only that the
turn closed and re-verified, whether it closed on HOLD or on
EVIDENCE_THRESHOLD_MET_NO_AUTHORITY. Read ``turn.json`` for which.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

try:
    from tools import database_braid_codex_kat as kat
    from tools import database_braid_hatun_gate as hatun
    from tools import database_braid_lake_receipt as lake
    from tools import database_braid_lean_witness as lean
    from tools import database_braid_source_census as census_tool
    from tools import database_ouroboros_braid_v2 as braid
    from tools.database_braid_common import (
        REPOSITORY, checkout_root, read_json, require, sha256_hex, write_exclusive,
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
        REPOSITORY, checkout_root, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-turn-manifest/v1"
FILES = ("census.json", "lean_witness.json", "known_answers.json", "hatun_witness.json",
         "khipu_tree.json", "turn.json", "lake_wrap.json")


def run(args) -> dict:
    root = checkout_root()
    out = args.out_dir
    require(out.is_dir() and not out.is_symlink() and not any(out.iterdir()) and
            not out.resolve().is_relative_to(root), "TURN_OUTPUT_DIRECTORY_DENIED")
    policy, policy_sha = read_json(args.policy, max_bytes=braid.MAX_POLICY_BYTES)
    braid.validate_policy(policy)
    checkouts = {}
    for item in args.checkout:
        name, sep, directory = item.partition("=")
        require(sep == "=" and REPOSITORY.fullmatch(name) and directory and
                name not in checkouts, "TURN_CHECKOUT_ARGUMENT_INVALID")
        checkouts[name] = Path(directory)
    digests, stages = {"policy": policy_sha}, {}

    def keep(name, value, limit):
        digests_key = {"census.json": "census", "lean_witness.json": "lean_witness",
                       "known_answers.json": "known_answers",
                       "hatun_witness.json": "hatun_witness"}.get(name)
        sha = write_exclusive(out / name, value, max_bytes=limit, checkout=root)
        if digests_key:
            digests[digests_key] = sha
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
        lean_witness = lean.observe(policy["lean"], lean_checkout,
                                    toolchain_bin=args.lean_toolchain_bin)
        keep("lean_witness.json", lean_witness, lean.MAX_WITNESS_BYTES)
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
    stages["known_answers"] = (f"{answers['passed']}/{answers['evaluated']}" if answers
                               else "NOT_RUN")

    hatun_witness = None
    hatun_checkout = checkouts.get(policy["hatun"]["repository"])
    if hatun_checkout is not None and args.python is not None:
        require(Path(args.python).is_absolute() and Path(args.python).is_file(),
                "TURN_INTERPRETER_INVALID")
        hatun_witness = hatun.observe(policy["hatun"], hatun_checkout, python=args.python)
        keep("hatun_witness.json", hatun_witness, hatun.MAX_WITNESS_BYTES)
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

    report, tree = braid.turn(
        policy, census, lean_witness=lean_witness, hatun_witness=hatun_witness,
        kat_report=answers, db_plan=plan, action_policy=action_policy,
        source_policy=source_policy, previous_turn=previous, previous_tree=previous_tree,
        previous_lake_wrap=previous_wrap, previous_turn_sha256=digests.get("previous_turn"),
        input_digests=digests)
    keep("khipu_tree.json", tree, braid.MAX_TREE_BYTES)
    turn_sha = keep("turn.json", report, braid.MAX_TURN_BYTES)
    stages["turn"] = report["state"]

    wrap = None
    lake_checkout = checkouts.get(policy["lake"]["repository"])
    if lake_checkout is not None and args.python is not None:
        wrap = lake.wrap_report(policy["lake"], lake_checkout, subject=report["turn_id"],
                                input_digest=report["inputs_digest"],
                                stored_object_digest=turn_sha, python=args.python)
        keep("lake_wrap.json", wrap, lake.MAX_WRAP_BYTES)
    stages["lake_wrap"] = wrap["state"] if wrap else "NOT_RUN"

    # Re-read what was written and verify it once more from the files alone.
    again, _ = read_json(out / "turn.json", max_bytes=braid.MAX_TURN_BYTES)
    tree_again, _ = read_json(out / "khipu_tree.json", max_bytes=braid.MAX_TREE_BYTES)
    braid.verify_turn(again, policy_for_shape=policy, tree=tree_again)
    manifest = {
        "schema": SCHEMA, "turn_id": report["turn_id"], "ordinal": report["ordinal"],
        "state": report["state"], "refusal_path": report["decision"]["refusal_path"],
        "sub_reasons": report["decision"]["sub_reasons"], "stages": stages,
        "files": {name: sha256_hex((out / name).read_bytes())
                  for name in FILES if (out / name).is_file()},
        "signed": False, "production_authorized": False, "external_effects_performed": False,
    }
    write_exclusive(out / "manifest.json", manifest, max_bytes=65536, checkout=root)
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description="One complete, no-effect braid v2 turn")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--family-map", type=Path)
    ap.add_argument("--answers", type=Path)
    ap.add_argument("--checkout", action="append", default=[], metavar="REPOSITORY=DIRECTORY")
    ap.add_argument("--lean-toolchain-bin", type=Path)
    ap.add_argument("--python", help="absolute interpreter that has the Hatun and receipt libraries")
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
