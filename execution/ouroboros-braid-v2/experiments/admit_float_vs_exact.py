#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Differential check: a11oy's float admit() against an exact integer decision.

For inputs with two decimal places, x_i = a_i / 100, and tau = T / 100, the
admit rule ``GM >= tau and min(x) > 0`` with equal weights is decided exactly by
``prod(a_i) >= T**n`` (the factor 100**n cancels on both sides). This script
counts every grid point where a11oy's floating-point ``admit`` disagrees with
that integer comparison, then enumerates every multiset whose geometric mean is
EXACTLY tau (the only places where rounding could flip a small-integer verdict)
and asks the float implementation about each one, unweighted and with integer
weights formed by merging repeated values.

It reads one file, ``szl_verify_nine.py`` from an a11oy checkout, records that
file's git blob id and the checkout's commit, and writes one JSON document. A
result of zero disagreements is a negative result on these grids only; it is
not a proof about other inputs, other thresholds or other implementations.
"""
import argparse
import hashlib
import importlib.util
import itertools
import json
import math
from pathlib import Path
import subprocess


def blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


def load(path: Path):
    spec = importlib.util.spec_from_file_location("szl_verify_nine", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def grid(module, tau_int=80):
    by_n = {}
    for n in (1, 2, 3, 4):
        low, high = (1, 100) if n <= 3 else (60, 100)  # n = 4 is bounded to stay finite
        tested = boundary = refuse = admit = 0
        for ints in itertools.combinations_with_replacement(range(low, high + 1), n):
            tested += 1
            exact = min(ints) > 0 and math.prod(ints) >= tau_int ** n
            floating = module.admit([i / 100 for i in ints], tau_int / 100)["admit"]
            boundary += math.prod(ints) == tau_int ** n
            if exact and not floating:
                refuse += 1
            elif floating and not exact:
                admit += 1
        by_n[str(n)] = {"range": [f"{low}/100", f"{high}/100"], "multisets_tested": tested,
                        "exactly_on_boundary": boundary,
                        "float_refuses_but_exact_admits": refuse,
                        "float_admits_but_exact_refuses": admit}
    return {"tau": f"{tau_int}/100", "grid_step": "1/100", "by_n": by_n,
            "multisets_tested": sum(v["multisets_tested"] for v in by_n.values()),
            "disagreements": sum(v["float_refuses_but_exact_admits"] +
                                 v["float_admits_but_exact_refuses"] for v in by_n.values())}


def _smooth(tau_int):
    primes, m, p = set(), tau_int, 2
    while p * p <= m:
        while m % p == 0:
            primes.add(p)
            m //= p
        p += 1
    if m > 1:
        primes.add(m)
    out = []
    for a in range(1, 101):
        rest = a
        for p in primes:
            while rest % p == 0:
                rest //= p
        if rest == 1:
            out.append(a)
    return out


def ties(tau_int, n):
    candidates, target, found = _smooth(tau_int), tau_int ** n, []

    def walk(start, left, prod, acc):
        if left == 0:
            if prod == target:
                found.append(tuple(acc))
            return
        for i in range(start, len(candidates)):
            value = candidates[i]
            nxt = prod * value
            if nxt > target:
                break
            if target % nxt or nxt * 100 ** (left - 1) < target:
                continue
            acc.append(value)
            walk(i, left - 1, nxt, acc)
            acc.pop()

    walk(0, n, 1, [])
    return found


def exact_ties(module):
    report = {}
    for tau_int in (80, 70):
        tau = tau_int / 100
        unweighted = weighted = refused_u = refused_w = 0
        for n in range(1, 10):
            for tie in ties(tau_int, n):
                unweighted += 1
                refused_u += not module.admit([a / 100 for a in tie], tau)["admit"]
                values = sorted(set(tie))
                if n >= 2 and len(values) < len(tie):
                    weighted += 1
                    refused_w += not module.admit([v / 100 for v in values], tau,
                                                  [float(tie.count(v)) for v in values])["admit"]
        report[f"{tau_int}/100"] = {"exact_ties_unweighted": unweighted,
                                    "float_refuses_unweighted": refused_u,
                                    "exact_ties_weighted": weighted,
                                    "float_refuses_weighted": refused_w}
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--a11oy-checkout", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    source = args.a11oy_checkout / "szl_verify_nine.py"
    raw = source.read_bytes()
    commit = subprocess.run(["git", "-C", str(args.a11oy_checkout), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    module = load(source)
    result = {
        "schema": "szl.braid-experiment/admit-float-vs-exact/v1",
        "subject": {"repository": "szl-holdings/a11oy", "commit": commit,
                    "path": "szl_verify_nine.py", "blob_sha1": blob_sha1(raw)},
        "grid": grid(module),
        "exact_ties": exact_ties(module),
        "scope": "TWO_DECIMAL_GRIDS_AND_EXACT_TIES_ONLY_NOT_A_PROOF",
    }
    args.output.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    print(json.dumps({"disagreements": result["grid"]["disagreements"],
                      "multisets_tested": result["grid"]["multisets_tested"]}))


if __name__ == "__main__":
    main()
