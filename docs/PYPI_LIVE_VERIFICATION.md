# Live release evidence: metadata, signatures, and authority are separate

The release-path audit previously inspected attestation metadata and correctly
returned UNKNOWN for unverified signatures. A separate Sigstore job could pass,
but no exact-release cryptographic observation reached the main audit.

The audit now supports an explicit live path:

```sh
python -m pip install 'sigstore==4.5.1' 'pypi-attestations==0.0.31'
python tools/pypi_release_path_audit.py --verify-attestations \
  --only szl-evidence-mandate --report release-evidence.json \
  --summary release-evidence.md
```

The scheduled workflow opts into that path. Without the flag, the original
stdlib-only metadata behavior remains. No prior PASS report, artifact filename,
check badge, or external JSON status is accepted as a verification substitute.

## Exact-release binding

The audit passes the already-observed release file set and provenance objects to
the verifier. The verifier does not refetch a mutable latest-version alias. It
requires both wheel and source distribution, exact package/version filenames,
complete per-file provenance, and the declared publisher metadata. It streams
artifact bytes from files.pythonhosted.org into SHA-256; it never installs,
extracts, or executes them. Redirects, credentials in URLs, alternate hosts,
encoded responses, missing coverage, changed hashes, and conflicting source
commits cannot qualify. Downloads have byte and time bounds. No GitHub credential
is passed to the artifact downloader.

Each attestation is verified with pypi-attestations' production Sigstore trust
policy. Certificate source claims are read only after verification. Every file
must bind to the same exact source commit. The main audit compares that source
against the release tag it actually reads. This is publish provenance, not a
reproducible-build result, vulnerability scan, or production readiness claim.

## Environment and ruleset boundary

In pypi-attestations 0.0.31, GitHubPublisher._as_policy() verifies repository and
workflow identity; its environment field is not part of that policy. Therefore:

- `pypi:provenance` may become PASS after every exact release artifact verifies.
- `pypi:publisher-repository-workflow` records that narrower verified identity.
- `github:release-tag` may become PASS only when it matches verified source.
- `pypi:publisher-identity` remains UNKNOWN for the environment claim. Matching
  PyPI environment metadata is not promoted into a signed certificate claim.
- `github:tag-ruleset` stays UNKNOWN when bypass actors are not visible. A
  content-read-only Actions token does not establish admin-only bypass policy.

No check is waived, no branch/tag rule is weakened, and the aggregate still
fails on UNKNOWN. Independent environment execution evidence and authorized,
read-only inspection of opaque rulesets remain separate requirements. A zero-row
audit fails; an unknown --only package is rejected rather than producing green.

## Validation

`python -m unittest discover -s tests -p 'test_pypi*'` covers metadata behavior and
negative controls for per-file coverage, hashes, publisher identity, signatures,
source conflicts, bounds, redirects, missing dependencies, and remaining holds.
Synthetic fixtures are explicitly not live verification evidence. Live validation
must preserve the downloaded metadata, provenance, source hashes and observed
results separately. Mutating a local copy's signature is a useful rejection
control; never overwrite the public provenance or original evidence.

Primary references:

- https://docs.pypi.org/attestations/consuming-attestations/
- https://pypi.github.io/pypi-attestations/pypi_attestations.html
- https://docs.pypi.org/attestations/security-model/
