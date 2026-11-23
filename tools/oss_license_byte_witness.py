"""Read-only exact-commit public GitHub LICENSE byte witness.

Separate caller assertions from independently fetched provider responses.
This observes HTTPS bytes; it cannot determine license rights, signer trust,
transitive obligations or authorize any adoption, training, merge or deploy.
No credentials, subprocesses, source execution, filesystem writes or retries.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime

from tools import open_source_frontier_gate as gate

SCHEMA = "szl.oss_license_byte_witness.v1"
API_ORIGIN = "https://api.github.com"
MAX_RESPONSE_BYTES = 196_608
MAX_LICENSE_BYTES = 65_536
SHA1 = re.compile(r"[a-f0-9]{40}\Z")
_GET = Callable[[str], object]


class WitnessError(ValueError):
    """An exact-revision readback was not independently observed."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_public_json(url: str) -> object:
    """Two bounded calls per candidate, only to preconstructed GitHub API URLs."""
    if not (
        url.startswith(f"{API_ORIGIN}/repos/")
        and "@" not in url
        and "#" not in url
        and "\r" not in url
        and "\n" not in url
    ):
        raise WitnessError("REQUEST_ORIGIN_INVALID")
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "szl-oss-license-byte-witness",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=8) as response:
            if response.geturl() != url or response.status != 200:
                raise WitnessError("PROVIDER_RESPONSE_IDENTITY_INVALID")
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise WitnessError("PROVIDER_RESPONSE_OVERSIZE")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        raise WitnessError("PROVIDER_UNAVAILABLE") from None
    try:
        return json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=gate._strict_object,
            parse_constant=gate._reject_constant,
            parse_float=gate._reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError):
        raise WitnessError("PROVIDER_JSON_INVALID") from None


def _base_result(stamp: str) -> dict[str, object]:
    """Complete result schema with all fail-closed defaults; every path returns this shape."""
    return {
        "schema": SCHEMA,
        "state": "HOLD",
        "reason": "UNOBSERVED",
        "observed_at_utc": stamp,
        "license_sha256": None,
        "license_git_blob_sha": None,
        "provider_commit_resolved": False,
        "provider_license_bytes_observed": False,
        "bytes_match_declared_digest": False,
        "rights_review_completed": False,
        "dependency_rights_verified": False,
        "signer_authenticated": False,
        "code_copy_authorized": False,
        "training_authorized": False,
        "merge_authorized": False,
        "deployment_authorized": False,
        "source_url": None,
    }


def observe(candidate: object, *, get: _GET = fetch_public_json, now: datetime | None = None) -> dict[str, object]:
    """Observe exact GitHub commit and LICENSE bytes without upgrading rights."""
    stamp = (now or datetime.now(UTC)).isoformat().replace("+00:00", "Z")
    base = _base_result(stamp)
    try:
        verdict = gate.evaluate(candidate, now=now)
    except (ValueError, TypeError):
        base["reason"] = "INVALID_CANDIDATE"
        return base
    if verdict["classification"] != "RESEARCH_CANDIDATE_ONLY":
        base["reason"] = "DECLARATION_HOLD"
        return base
    info = candidate["upstream"]
    repo = gate._repo_url(info["repo_url"])
    if repo is None:
        base["reason"] = "INVALID_REPOSITORY"
        return base
    owner, name = repo
    commit = info["commit_sha"]
    license_path = info["license_path"]
    # All three URL components were strictly validated by the offline gate.
    commit_url = f"{API_ORIGIN}/repos/{owner}/{name}/git/commits/{commit}"
    blob_url = f"{API_ORIGIN}/repos/{owner}/{name}/contents/{license_path}?ref={commit}"
    base["source_url"] = f"https://github.com/{owner}/{name}/blob/{commit}/{license_path}"
    try:
        resolved = get(commit_url)
        if not isinstance(resolved, dict) or resolved.get("sha") != commit:
            raise WitnessError("COMMIT_PIN_MISMATCH")
        base["provider_commit_resolved"] = True
        obj = get(blob_url)
        if not isinstance(obj, dict) or obj.get("type") != "file" or obj.get("path") != license_path:
            raise WitnessError("LICENSE_OBJECT_INVALID")
        size = obj.get("size")
        if type(size) is not int or not 0 < size <= MAX_LICENSE_BYTES:
            raise WitnessError("LICENSE_SIZE_INVALID")
        if obj.get("encoding") != "base64" or type(obj.get("content")) is not str:
            raise WitnessError("LICENSE_ENCODING_INVALID")
        if len(obj["content"]) > MAX_RESPONSE_BYTES:
            raise WitnessError("LICENSE_ENCODED_SIZE_INVALID")
        clean = obj["content"].replace("\r", "").replace("\n", "")
        try:
            data = base64.b64decode(clean, validate=True)
        except (binascii.Error, ValueError):
            raise WitnessError("LICENSE_BASE64_INVALID") from None
        if len(data) != size:
            raise WitnessError("LICENSE_LENGTH_MISMATCH")
        git_blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if not (type(obj.get("sha")) is str and SHA1.fullmatch(obj["sha"]) and obj["sha"] == git_blob):
            raise WitnessError("GIT_BLOB_MISMATCH")
        digest = hashlib.sha256(data).hexdigest()
        base["license_sha256"] = digest
        base["license_git_blob_sha"] = git_blob
        base["provider_license_bytes_observed"] = True
        if digest != info["license_sha256"]:
            raise WitnessError("DECLARED_DIGEST_MISMATCH")
        base["bytes_match_declared_digest"] = True
        base["state"] = "EXACT_COMMIT_LICENSE_BYTES_MATCH_REVIEW_ONLY"
        base["reason"] = "RIGHTS_REVIEW_AND_DEPENDENCY_SCAN_REQUIRED"
    except WitnessError as exc:
        base["reason"] = str(exc)
    except Exception:  # noqa: BLE001 - fail closed for arbitrary injected transport failures
        # No exception message is emitted: it could embed provider/private details.
        base["reason"] = "PROVIDER_UNAVAILABLE"
    return base


def main() -> int:
    raw = sys.stdin.buffer.read(gate.MAX_BYTES + 1)
    try:
        candidate = gate.parse(raw)
        result = observe(candidate)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        result = _base_result(datetime.now(UTC).isoformat().replace("+00:00", "Z"))
        result["reason"] = "INVALID_INPUT"
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["state"] == "EXACT_COMMIT_LICENSE_BYTES_MATCH_REVIEW_ONLY" else 78


if __name__ == "__main__":
    raise SystemExit(main())
