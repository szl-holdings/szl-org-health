# System Design Research → SZL Implementation Boundaries

**Status:** Python source / review candidate. This is not a production-readiness certificate.

## Verified external reference — November 17, 2026

Kirk Borne's [X post](https://x.com/KirkDBorne/status/2122490501828059535)
links to [Coder-World04/Complete-System-Design](https://github.com/Coder-World04/Complete-System-Design),
not to a deployable database or software framework.

Exact Git commit: **b92daa9595f23974e64e55d8ad0a942d75a64d56**.
README SHA-256: **88b2fb2c7274c23658547b287a6e86ff6a4a095136cf850d877d183c717fccc5**.
The tracked tree contains **only README.md and LICENSE (MIT)**. Topics include
scaling, load balancing, queues, caching, indexing, networking, CDNs,
database sharding and consistency, concurrency, performance and ML system
design. The visible case-study table has **41 rows / 31 distinct labels**.
The README contains 144 inline links (93 unique destinations), many to
third-party Medium/Substack articles or shortened URLs. It does **not**
include Python implementations, test suites, production deployments,
frontend/backend applications or release workflows. Its advertised 100+/200+
external studies are not 100+ implemented audited programs in this repo.

**Copyright:** only the ideas behind general system-design concepts are
referenced. SZL independently implements its own review obligations. No
third-party articles, case-study texts or diagrams have been copied. The
repository's MIT license does not license linked third-party publications.

## Owner-consistent implementation

Introduce **no competing database, policy engine, credential pipeline,
inference router or autonomous provider mutation**.

Use the existing [szl-org-health](https://github.com/szl-holdings/szl-org-health)
Python HTTP service and its already-minimized public source projection:

- **census/system_design.py:** pure Python, reference-pinned schema and
  explanatory design controls. No requests, credentials, state-changing
  imports, model inference, payment, receipts, hidden tenant data or signing.
- **GET /api/system-design:** JSON map, served from the existing 60-second
  public-census response cache. No provider call on the HTTP handler.
- **GET /system-design:** original Python server-rendered HTML with accessible
  comparison cards and release dependencies; no browser JavaScript, forms,
  remote resources, or arbitrary user-provided links. Script-disabled CSP.
- **Docker:** exact-file module COPY and installed import-closure tests.
- The existing root dashboard, health, portal and proof-graph routes retain
  their independent owners. A failed optional design map cannot poison those
  previously qualified routes.

The control map contains eleven *non-admission* topics: ten inspired by the
external educational catalog and one clearly labeled SZL release-provenance
extension. Every item names a candidate source owner, a falsifiable test
criterion and qualification **NOT_EVALUATED**. No system is upgraded merely
because a name, URL, HTTP status or artifact is present.

## Public evidence scope and the missing claims

| Surface | Allowed observation | Unproved dimension |
| --- | --- | --- |
| GitHub szl-holdings | Existing public-repository subset if fresh | Whole private estate, CI conclusions, source approval |
| Hugging Face SZLHOLDINGS | Existing public asset subsets if fresh | Model quality, runtime inference and exact source equality |
| Product a-11-oy.com | Existing HTTP transport status | Backend and frontend production readiness |
| Proof a11oy.net | Existing HTTP transport status | Independent signature and anti-rollback proof |
| Cloudflare | Static official reference link only | Live account setup, origin JWT and paid settlement |
| PyPI | Static organization link only | OIDC Trusted Publisher, installed artifact attestations |

An unavailable snapshot returns HTTP 503. A 200 on a public page never
proves full-stack readiness. Every authorized state-changing action must
recheck its separate existing owner and current proof; display data does not
grant permissions.

## Proposed cross-platform release checks — no auto-promotion

1. Protected GitHub main SHA equals immutable Hugging Face deployed revision.
2. Hugging Face service revision equals product runtime revision and checks.
3. Product and independent proof site agree on signed, non-stale source bytes.
4. Cloudflare x402 challenge **and** origin PAYMENT-CONTEXT JWT verification
   **and** separately reconciled paid settlement; a 402 alone is not revenue.
5. GitHub release **and** PyPI Trusted Publisher OIDC **and** exact installed
   wheel provenance; listing a project is not a completed release attestation.

Next falsifiable experiment: replay controlled source drift, stale receipt,
unavailable provider, cross-tenant access, broken package provenance, and
bad x402 authorization fixtures, then compare coverage and false-positive
admissions before any live promotion. Do not treat an agent's self-report
as external evidence.

## Normative implementation references

- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- [Hugging Face Docker Spaces](https://huggingface.co/docs/hub/spaces-sdks-docker)
- [Cloudflare x402](https://developers.cloudflare.com/monetization-gateway/x402/)
- [PyPI OIDC Trusted Publishing](https://docs.pypi.org/trusted-publishers/)

A deploy window, source parity, credential authorization, verified model
evaluation, tenant isolation, origin signature validation and rollback are
separate gates. This change does not claim any such gate passed.
