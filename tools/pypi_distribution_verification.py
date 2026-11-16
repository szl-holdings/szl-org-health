"""Verify the exact already-observed PyPI release; never consume a PASS report.

The optional pypi-attestations dependency is imported only on explicit execution.
Downloaded archives are streamed into hashes, never extracted, installed or run.
The upstream GitHubPublisher policy does not check the deployment environment.
After verification, require Fulcio's signed deployment-environment extension on
that same certificate for every attestation; metadata alone cannot satisfy it.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

PUBLISH_PREDICATE = "https://docs.pypi.org/attestations/publish/v1"
SOURCE_DIGEST_OID = "1.3.6.1.4.1.57264.1.13"
DEPLOYMENT_ENVIRONMENT_OID = "1.3.6.1.4.1.57264.1.23"
ENVIRONMENT_EVIDENCE = "FULCIO_CERTIFICATE_DEPLOYMENT_ENVIRONMENT"
MAX_ENVIRONMENT_UTF8_BYTES = 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_RELEASE_FILES = 32


class RejectedEvidence(ValueError):
    """Observed evidence violates the declared verification contract."""


class UnavailableEvidence(RuntimeError):
    """An observation could not be completed; never a successful verification."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UnavailableEvidence("distribution redirect refused")


def distribution_digest(url: str, filename: str) -> tuple[str, int]:
    """Bounded unauthenticated download from the exact PyPI artifact host."""
    try:
        parsed = urllib.parse.urlsplit(url)
        path = urllib.parse.unquote(parsed.path)
        valid = (
            isinstance(filename, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,255}", filename)
            and parsed.scheme == "https"
            and parsed.netloc == "files.pythonhosted.org"
            and not parsed.query and not parsed.fragment
            and path.startswith("/packages/")
            and not any(p in (".", "..", "") for p in path.split("/")[1:])
            and path.rsplit("/", 1)[-1] == filename
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise RejectedEvidence("invalid distribution URL or filename")
    request = urllib.request.Request(url, headers={
        "User-Agent": "szl-pypi-distribution-verification/1",
        "Accept-Encoding": "identity",
    })
    opener = urllib.request.build_opener(NoRedirect())
    digest, count = hashlib.sha256(), 0
    deadline = time.monotonic() + 60
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200 or response.geturl() != url:
                raise UnavailableEvidence("distribution response identity changed")
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise RejectedEvidence("encoded distribution response refused")
            length = response.headers.get("Content-Length")
            if length is not None:
                if not re.fullmatch(r"[0-9]+", length) or not 0 < int(length) <= MAX_FILE_BYTES:
                    raise RejectedEvidence("distribution length invalid or exceeds bound")
            while True:
                if time.monotonic() > deadline:
                    raise UnavailableEvidence("distribution deadline exceeded")
                chunk = response.read1(min(1 << 16, MAX_FILE_BYTES - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                if count > MAX_FILE_BYTES:
                    raise RejectedEvidence("distribution exceeds byte bound")
                digest.update(chunk)
            if not count or (length is not None and count != int(length)):
                raise UnavailableEvidence("empty or truncated distribution response")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UnavailableEvidence(type(exc).__name__) from exc
    return digest.hexdigest(), count


@dataclass(frozen=True)
class VerifiedAttestation:
    source_digest: str
    publisher_environment: str


def _decode_environment_der(value: object) -> str:
    """Decode one complete canonical DER UTF8String, with no trailing data."""
    if not isinstance(value, bytes) or not 2 <= len(value) <= MAX_ENVIRONMENT_UTF8_BYTES + 4 or value[0] != 0x0C:
        raise UnavailableEvidence("verified certificate deployment environment malformed")
    length, offset = value[1], 2
    if length & 0x80:
        width = length & 0x7F
        if not 1 <= width <= 2 or len(value) < 2 + width or value[2] == 0:
            raise UnavailableEvidence("verified certificate deployment environment malformed")
        length = int.from_bytes(value[2:2 + width], "big")
        offset += width
        if length < 128 or (width > 1 and length < 256):
            raise UnavailableEvidence("verified certificate deployment environment malformed")
    if not 0 < length <= MAX_ENVIRONMENT_UTF8_BYTES or len(value) != offset + length:
        raise UnavailableEvidence("verified certificate deployment environment malformed")
    try:
        environment = value[offset:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnavailableEvidence("verified certificate deployment environment malformed") from exc
    if len(environment) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in environment):
        raise UnavailableEvidence("verified certificate deployment environment malformed")
    return environment


def _verified_certificate_environment(attestation: object) -> str:
    # certificate_claims in pypi-attestations 0.0.31 exposes only OIDs .8-.22.
    # Read .23 from the exact certificate bytes used by Attestation.verify.
    from cryptography import x509

    certificate = x509.load_der_x509_certificate(attestation.verification_material.certificate)
    try:
        extension = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(DEPLOYMENT_ENVIRONMENT_OID))
    except x509.ExtensionNotFound as exc:
        raise UnavailableEvidence("verified certificate deployment environment missing") from exc
    return _decode_environment_der(getattr(extension.value, "value", None))


def _verify_attestation(raw: dict, filename: str, digest: str, expected: tuple[str, ...]) -> VerifiedAttestation:
    # Production trust roots and online TUF refresh remain the library defaults.
    # There is deliberately no custom-root, offline, staging, or skip-verify flag.
    from pypi_attestations import Attestation, Distribution, GitHubPublisher, VerificationError

    try:
        attestation = Attestation.model_validate(raw)
        publisher = GitHubPublisher(repository=expected[1], workflow=expected[2], environment=expected[3])
        predicate_type, predicate = attestation.verify(publisher, Distribution(name=filename, digest=digest))
        if predicate_type != PUBLISH_PREDICATE or predicate not in ({}, None):
            raise RejectedEvidence("verified statement is not an empty PyPI publish predicate")
        # Read certificate claims ONLY after cryptographic verification succeeded.
        source = attestation.certificate_claims.get(SOURCE_DIGEST_OID)
        if not isinstance(source, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", source):
            raise UnavailableEvidence("verified certificate lacks an immutable source digest")
        environment = _verified_certificate_environment(attestation)
        if environment != expected[3]:
            raise RejectedEvidence("verified certificate deployment environment differs from declared publisher")
        return VerifiedAttestation(source.lower(), environment)
    except VerificationError as exc:
        raise RejectedEvidence("signature, subject, trust chain, transparency, or publisher verification failed") from exc


def _check_filename(filename: str, package: str, version: str) -> None:
    """Use the packaging parser; missing optional tooling stays UNKNOWN."""
    from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
    from packaging.version import Version

    parsed = parse_wheel_filename(filename) if filename.endswith(".whl") else parse_sdist_filename(filename)
    if parsed[0] != canonicalize_name(package) or parsed[1] != Version(version):
        raise RejectedEvidence("distribution filename names a different project or version")


def verify_release(package: str, version: str, files: dict, provenances: dict,
                   expected_publisher: tuple[str, ...]) -> dict:
    """Bind every file in one observation to verified bytes and source identity.

    This function never fetches mutable latest-version metadata, consults a prior
    report, resolves GitHub tags, changes cloud state, or receives a GitHub token.
    """
    result = {
        "schema": "szl.pypi-live-distribution-verification/v1",
        "package": package, "version": version, "status": "UNKNOWN", "files": {},
        "source_digests": [], "publisher_environment_cryptographically_verified": False,
        "publisher_environment": None, "publisher_environment_evidence": "UNAVAILABLE",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "archives_installed_or_executed": False,
    }
    try:
        for dependency in ("pypi-attestations", "sigstore"):
            result.setdefault("verifier_versions", {})[dependency] = importlib.metadata.version(dependency)
        if (not isinstance(files, dict) or not 0 < len(files) <= MAX_RELEASE_FILES
                or not isinstance(provenances, dict) or set(files) != set(provenances)):
            raise RejectedEvidence("release file/provenance coverage is empty, excessive, or unequal")
        if (not isinstance(expected_publisher, tuple) or len(expected_publisher) != 4
                or expected_publisher[0] != "GitHub"
                or not all(isinstance(x, str) and x for x in expected_publisher)):
            raise RejectedEvidence("expected publisher identity incomplete")
        if not any(n.endswith(".whl") for n in files) or not any(n.endswith((".tar.gz", ".zip")) for n in files):
            raise RejectedEvidence("release must include both wheel and sdist")
        total_bytes, sources = 0, set()
        for filename, metadata in sorted(files.items()):
            _check_filename(filename, package, version)
            if not isinstance(metadata, dict) or metadata.get("filename") != filename:
                raise RejectedEvidence("distribution metadata identity mismatch")
            expected_hash = (metadata.get("digests") or {}).get("sha256")
            if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
                raise RejectedEvidence("distribution metadata lacks SHA-256")
            provenance = provenances[filename]
            bundles = provenance.get("attestation_bundles") if isinstance(provenance, dict) else None
            if not isinstance(bundles, list) or not 0 < len(bundles) <= 8:
                raise RejectedEvidence("attestation bundle coverage invalid")
            digest, size = distribution_digest(metadata.get("url"), filename)
            total_bytes += size
            if total_bytes > MAX_RELEASE_BYTES:
                raise RejectedEvidence("release exceeds byte budget")
            if digest != expected_hash.lower():
                raise RejectedEvidence("downloaded artifact SHA-256 differs from observed release")
            file_sources, attestations_verified = set(), 0
            for bundle in bundles:
                publisher = bundle.get("publisher") if isinstance(bundle, dict) else None
                if not isinstance(publisher, dict):
                    raise RejectedEvidence("publisher metadata missing")
                observed = tuple(publisher.get(k) for k in ("kind", "repository", "workflow", "environment"))
                if observed != expected_publisher:
                    raise RejectedEvidence("publisher metadata differs from declared publisher")
                attestations = bundle.get("attestations")
                if not isinstance(attestations, list) or not 0 < len(attestations) <= 8:
                    raise RejectedEvidence("empty or excessive attestation set")
                for raw in attestations:
                    verified = _verify_attestation(raw, filename, digest, expected_publisher)
                    if (
                        not isinstance(verified, VerifiedAttestation)
                        or not isinstance(verified.source_digest, str)
                        or not re.fullmatch(r"[0-9a-f]{40}", verified.source_digest)
                        or verified.publisher_environment != expected_publisher[3]
                    ):
                        raise RejectedEvidence("verifier returned incomplete source or environment identity")
                    file_sources.add(verified.source_digest)
                    attestations_verified += 1
            if len(file_sources) != 1:
                raise RejectedEvidence("file attestations disagree about source commit")
            sources.update(file_sources)
            result["files"][filename] = {
                "sha256": digest, "bytes": size, "attestations_verified": attestations_verified,
                "source_digest": next(iter(file_sources)), "status": "VERIFIED",
                "publisher_environment": expected_publisher[3],
                "publisher_environment_evidence": ENVIRONMENT_EVIDENCE,
            }
        if len(sources) != 1 or set(result["files"]) != set(files):
            raise RejectedEvidence("release artifacts disagree about source or coverage")
        result.update(
            status="VERIFIED", source_digests=sorted(sources),
            publisher_environment=expected_publisher[3],
            publisher_environment_cryptographically_verified=True,
            publisher_environment_evidence=ENVIRONMENT_EVIDENCE,
            detail="all observed release bytes and publish attestations verified; repository/workflow identity and signed certificate deployment environment verified",
        )
    except RejectedEvidence as exc:
        result.update(status="FAILED", detail=str(exc))
    except UnavailableEvidence as exc:
        result.update(status="UNKNOWN", detail=str(exc))
    except Exception as exc:  # unavailable dependencies/network/trust material never imply validity
        result.update(status="UNKNOWN", detail="verification unavailable: " + type(exc).__name__)
    return result
