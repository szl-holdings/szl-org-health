"""Offline comparison of two GitHub repository discovery credentials.

Does not connect to GitHub, publish repo names, authorize changes, or infer
organization completeness from equality of two potentially restricted views.
Inputs are saved privately on the operator workstation.

Manifest schema:
  {"source":"github_cli", "observed_at_utc":"2026-11-20T07:00:00+00:00",
   "repositories":[{"name":"repo", "visibility":"private", "archived":false}]}

"private": true/false may be used instead of "visibility".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCHEMA = "szl.github-credential-scope-comparison/v0"
MAX_SKEW_SECONDS = 300
MAX_AGE_SECONDS = 900
MAX_FUTURE_SECONDS = 60
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class InvalidManifest(ValueError):
    pass


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidManifest("duplicate JSON property")
        result[key] = value
    return result


def _time(value):
    if not isinstance(value, str):
        raise InvalidManifest("missing observed_at_utc")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise InvalidManifest("invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise InvalidManifest("timestamp must be UTC timezone aware")
    return parsed


def _normalize(manifest):
    if not isinstance(manifest, dict):
        raise InvalidManifest("manifest must be an object")
    source = manifest.get("source")
    if source not in ("github_cli", "github_app"):
        raise InvalidManifest("unrecognized authenticated source")
    observed_at = _time(manifest.get("observed_at_utc"))
    rows = manifest.get("repositories")
    if not isinstance(rows, list) or not (1 <= len(rows) <= 2000):
        raise InvalidManifest("missing or unbounded repositories list")
    normalized = {}
    for row in rows:
        if not isinstance(row, dict):
            raise InvalidManifest("invalid repository object")
        name = row.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise InvalidManifest("invalid repository name")
        if name in normalized:
            raise InvalidManifest("duplicate repository name")
        archived = row.get("archived")
        if not isinstance(archived, bool):
            raise InvalidManifest("archived flag missing or invalid")
        private = row.get("private")
        visibility = row.get("visibility")
        if isinstance(private, bool):
            inferred = "private" if private else "public"
            if visibility is not None and visibility != inferred:
                raise InvalidManifest("private and visibility disagree")
            visibility = inferred
        if visibility not in ("public", "private"):
            raise InvalidManifest("visibility not observed")
        normalized[name] = (visibility, archived)
    return source, observed_at, normalized


def compare(left, right, max_skew_seconds=MAX_SKEW_SECONDS, max_age_seconds=MAX_AGE_SECONDS, as_of=None):
    """Diagnostic report contains counts ONLY, never repository names.

    Require both source observations to be recent, not merely close together.
    An explicit as_of is for deterministic tests and offline forensic replay;
    it cannot authorize production, and is never emitted as a readiness claim.
    """
    if not isinstance(max_skew_seconds, int) or isinstance(max_skew_seconds, bool) or max_skew_seconds < 0:
        raise ValueError("invalid skew threshold")
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds < 0:
        raise ValueError("invalid snapshot age threshold")
    now = as_of if as_of is not None else datetime.now(UTC)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("as_of must be UTC aware")
    source_l, time_l, repos_l = _normalize(left)
    source_r, time_r, repos_r = _normalize(right)
    if source_l == source_r:
        raise InvalidManifest("two distinct credential sources required")

    names_l = set(repos_l)
    names_r = set(repos_r)
    only_l = names_l - names_r
    only_r = names_r - names_l
    intersection = names_l & names_r
    metadata_diff = {n for n in intersection if repos_l[n] != repos_r[n]}
    skew = abs(int((time_l - time_r).total_seconds()))
    ages = {source_l: int((now - time_l).total_seconds()), source_r: int((now - time_r).total_seconds())}
    freshness_invalid = any(age > max_age_seconds or age < -MAX_FUTURE_SECONDS for age in ages.values())

    def counts(mapping):
        return {
            "repositories": len(mapping),
            "public": sum(v[0] == "public" for v in mapping.values()),
            "private": sum(v[0] == "private" for v in mapping.values()),
            "archived": sum(v[1] for v in mapping.values()),
        }

    def diff_counts(diff, mapping):
        return {
            "count": len(diff),
            "public": sum(mapping[n][0] == "public" for n in diff),
            "private": sum(mapping[n][0] == "private" for n in diff),
        }

    if skew > max_skew_seconds or freshness_invalid:
        state = "STALE_SNAPSHOT_UNAVAILABLE"
    elif only_l or only_r or metadata_diff:
        state = "SCOPE_OR_INVENTORY_DIVERGENCE"
    else:
        state = "CONSISTENT_VISIBLE_SETS_NOT_ORG_COMPLETENESS"

    return {
        "schema": SCHEMA,
        "state": state,
        "enforcement_authorized": False,
        "organization_complete": None,
        "explanation": (
            "Two credential-visible sets are not proof of full organization"
            " coverage; missing repos may reflect access scopes or temporal drift."
        ),
        "snapshot_skew_seconds": skew,
        "max_allowed_skew_seconds": max_skew_seconds,
        "max_allowed_age_seconds": max_age_seconds,
        "max_future_clock_skew_seconds": MAX_FUTURE_SECONDS,
        "observation_age_seconds": ages,
        "sources": {source_l: counts(repos_l), source_r: counts(repos_r)},
        "left_only": diff_counts(only_l, repos_l),
        "right_only": diff_counts(only_r, repos_r),
        "shared_metadata_mismatch": len(metadata_diff),
        "compared_names": len(intersection),
        "private_repo_names_disclosed": False,
    }


def read_manifest(path):
    payload = Path(path).read_bytes()
    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda x: (_ for _ in ()).throw(InvalidManifest("non-finite JSON")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidManifest("invalid manifest JSON") from exc
    return parsed, hashlib.sha256(payload).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, help="local private CLI manifest")
    parser.add_argument("--app", required=True, help="local private GitHub App manifest")
    parser.add_argument("--output", required=True, help="redacted diagnostic report")
    parser.add_argument("--max-skew-seconds", type=int, default=MAX_SKEW_SECONDS)
    parser.add_argument("--max-age-seconds", type=int, default=MAX_AGE_SECONDS)
    args = parser.parse_args(argv)
    try:
        cli, cli_hash = read_manifest(args.cli)
        app, app_hash = read_manifest(args.app)
        report = compare(cli, app, max_skew_seconds=args.max_skew_seconds, max_age_seconds=args.max_age_seconds)
        report["input_digests_sha256"] = {"github_cli": cli_hash, "github_app": app_hash}
    except (InvalidManifest, ValueError, OSError) as exc:
        report = {
            "schema": SCHEMA,
            "state": "UNAVAILABLE",
            "error_class": type(exc).__name__,
            "enforcement_authorized": False,
            "organization_complete": None,
        }
    # Never overwrite private input evidence or an earlier receipt. Exclusive
    # creation also rejects existing symlinks, including dangling symlinks.
    output = Path(args.output)
    if output.resolve() in (Path(args.cli).resolve(), Path(args.app).resolve()):
        write_error = "REPORT_ALIASES_PRIVATE_INPUT"
    else:
        try:
            with output.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
            write_error = None
        except FileExistsError:
            write_error = "REPORT_ALREADY_EXISTS"
        except OSError:
            write_error = "REPORT_WRITE_UNAVAILABLE"
    if write_error:
        print(json.dumps({
            "schema": SCHEMA, "state": "UNAVAILABLE",
            "error_class": write_error, "enforcement_authorized": False,
            "organization_complete": None,
        }, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["state"] == "CONSISTENT_VISIBLE_SETS_NOT_ORG_COMPLETENESS" else 1


if __name__ == "__main__":
    sys.exit(main())
