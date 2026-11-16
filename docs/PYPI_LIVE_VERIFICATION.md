# Exact live release verification

The release-path audit supports an explicit cryptographic path:

```sh
python -m pip install 'sigstore==4.5.1' 'pypi-attestations==0.0.31'
python tools/pypi_release_path_audit.py --verify-attestations \
  --only szl-evidence-mandate --report release-evidence.json \
  --summary release-evidence.md
```

Without the flag, the audit remains a stdlib-only metadata inspection. With it,
the verifier consumes the exact file and provenance set already observed by the
audit. No saved PASS report, check badge, filename, or cross-run status is accepted
as a substitute for current verification.

## Artifact and source binding

Both a wheel and source distribution are required. Every file must name the
expected project/version, have complete provenance, match the observed SHA-256,
and bind to the same source commit. Downloads are streamed from the exact
files.pythonhosted.org host, without GitHub credentials, extraction, installation,
or execution. Redirects, alternate hosts, encoded responses, empty coverage,
changed hashes, and conflicting commits cannot qualify. File count, bytes and
download time are bounded.

The pinned pypi-attestations library verifies the publish statement, artifact
subject, signature, production trust chain, transparency evidence, and expected
GitHub repository/workflow policy. Certificate claims are consulted only after
that verification succeeds. The main audit independently resolves the release
tag and compares it with the source digest from every verified artifact.

## Signed deployment-environment binding

The library's GitHubPublisher policy does not itself enforce the environment
field. PyPI's publisher metadata therefore cannot establish this claim on its
own. Fulcio defines a signed Deployment Environment certificate extension at
OID 1.3.6.1.4.1.57264.1.23, mapped from GitHub's OIDC environment claim.

After cryptographically verifying each attestation and its certificate, the
shared verifier reads that extension from the same verified certificate and
requires an exact match to the manifest's environment. Every attestation on every
release file must supply that evidence. Missing or malformed extension evidence
remains UNKNOWN; a different environment fails. Metadata-only or boolean-only
reports cannot upgrade the check.

A successful result records:

- publisher_environment_cryptographically_verified: true
- publisher_environment_evidence: FULCIO_CERTIFICATE_DEPLOYMENT_ENVIRONMENT
- The exact publisher_environment value at release and file scope.
- Each file's SHA-256, byte size, source commit and verified attestation count.

The main audit promotes full publisher identity only with complete signed
environment coverage. The repository/workflow check also remains independently
visible. This proves the environment asserted at signing time, not the current
contents of its protection rules; those remain separately inspected controls.

## Authority and reporting

Tag protection remains UNKNOWN when the audit cannot see bypass actors. Private
repository markers require an authorized read at the resolved immutable commit.
No repository rule, reviewer gate, visibility setting, or credential scope is
changed by these checks. Any FAIL or UNKNOWN keeps the aggregate audit failed.
An empty audit and unknown package selection cannot produce a successful result.

The standalone pypi_sigstore_verify.py command uses the same exact-release
verifier. Its additive v1 report retains package/version/tag/source fields and
records the full per-file proof and explicit verification scope. It also refuses
empty or duplicate file sets, incomplete signed environments, unresolved
annotated tags, and recorded tag exceptions as successful source identity.
GitHub JSON reads are bounded and refuse redirects; authorization is sent only
to the exact api.github.com host. The standalone report remains a subset
observation and does not establish aggregate production readiness.

## Validation

The PyPI tests exercise complete coverage and rejection cases for artifact
hashes, signatures, source conflicts, missing or wrong signed environments,
transport bounds, redirects, credential isolation, empty selection, private
reads and remaining ruleset holds. Synthetic fixtures are never live receipts.
Real validation uses the pinned libraries and preserved public metadata. A
signature-tampered local copy must fail while the unchanged original verifies.
The original public provenance is never overwritten.

Primary references:

- https://docs.pypi.org/attestations/consuming-attestations/
- https://pypi.github.io/pypi-attestations/pypi_attestations.html
- https://docs.pypi.org/attestations/security-model/
- https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
