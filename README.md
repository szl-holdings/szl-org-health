# szl-org-health

<!-- szl:header v1 -->
<!-- Native identity: szl-brand@4309f6fce89179331b0b3ed8c99494e76c5be256; Orbit v2 icon. -->
<p>
  <a href="https://github.com/szl-holdings">
    <img src="https://raw.githubusercontent.com/szl-holdings/szl-brand/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/logos/orbit-v2/suite/szl-icon-32.svg" alt="SZL Holdings — Orbit v2" width="32" height="32" />
  </a>
</p>

**Control before action. Evidence after.**

[Product](https://a-11-oy.com) · [Proof](https://a11oy.net) · [GitHub organization](https://github.com/szl-holdings)
<!-- /szl:header -->

Live, fail-closed census and health dashboard for the SZL Holdings GitHub and Hugging Face estates.

Every displayed value is either a reading collected during the current request or an explicit `UNKNOWN`. Authorization failures, timeouts, incomplete pagination, and unavailable APIs are never converted into zero, healthy, protected, or operational states.

## What it inventories

| Source | Dynamically discovered evidence |
|---|---|
| GitHub (`szl-holdings`) | All repositories visible to the runtime credential, archive/visibility/default-branch metadata, preliminary role classification, latest **run per workflow** on the default branch, branch-protection readability, open PRs/issues, and organization security-alert counts |
| Hugging Face (`SZLHOLDINGS`) | Models, datasets, Spaces, collections, and buckets; exact repository SHAs and modification dates; declared model contract shape plus observed tensor, GGUF, estimator, and embedding artifacts; revision-bound operational-payload manifest size and SHA-256 verification; Space SDK, hardware/runtime stage, live root probe, and governed `/healthz` probes for the flagships |
| Sites and DNS | Reachability, security response headers, SPF, and DMARC posture |
| Series-A diligence | A deterministic, network-free artifact compiled from one supplied public census, with exact compiler-source binding, the five-plus-one public-Space policy, governed-agent-bench evidence, corrections, overclaim boundaries, and explicit gaps |

The GitHub collector follows pagination instead of maintaining a hand-written repository subset. The Hugging Face collector uses bounded Hub APIs and isolates every asset class: for example, an unreadable direct bucket API remains `UNKNOWN` while independently verified Spaces and datasets remain available. Models, datasets, Spaces, and Kernels require an `id` plus an exact repository SHA. Collections use a slug and explicit detail-completeness evidence. Buckets require direct-listing identity and tree-read evidence; collection-visible bucket references remain separate partial evidence in the internal collector and never become successful direct bucket inventory.

## Honesty contract

- Repository CI is calculated from the latest default-branch push run **for each workflow**. A newer unrelated green workflow cannot conceal a failing guard.
- Tensor/GGUF weights, serialized estimators, and embedding indexes are reported separately. A kernel may satisfy its declared contract without a weight file. Operational payloads satisfy their artifact expectation only when every revision-bound manifest entry is present and matches its declared byte size and SHA-256. Neither classification claims that inference or deployment was executed.
- Space `RUNNING` state and HTTP reachability are separate readings. Neither substitutes for the other.
- Direct bucket discovery may require an authenticated Hugging Face token. Without it, bucket count remains `UNKNOWN`; collection-visible bucket references are labeled as partial discovery in the internal collector. The closed public projection currently omits those references.
- Every Hugging Face asset class has an independent subinventory state. A collection or bucket failure cannot erase valid repository-backed evidence, and it cannot be relabeled as a complete collection or direct bucket census. Governed-agent-bench state is derived from its dataset and Space substates, not from a caller-supplied aggregate label.
- A 403/404 from GitHub branch-protection endpoints remains `UNKNOWN` because an unprotected branch and an under-scoped credential can be indistinguishable.
- Preliminary repository classifications are deterministic and visible. Anything not proven by the current policy is `unclassified`, not guessed.
- No credential values are returned by the API or rendered by the interface.

### Bounded GitHub CI coverage

For each active repository, the collector reads default-branch `push` runs in
pages of 100, stopping at ten pages (1,000 runs). Requests retain the same query
filters and lock redirects to the GitHub API origin and run-list path. Existing
transport timeouts and retry limits still apply to each request.

`ci_coverage: COMPLETE` means the returned unique run IDs match a stable API
`total_count` within that bound. It covers retained runs for this query, not a
catalog of every workflow, deleted history, other trigger events, or proof that
CI passed for the current branch head. `run_window_observed` and
`default_branch_push_runs_total` retain the observed denominator and provider
total; the collection timestamps retain the observation window. An empty
complete query remains CI `unknown`.
**Nonexecuted workflow guard (2026-11-17).** A terminal `skipped` or
`neutral` run is retained internally in `nonexecuted_workflows`, not counted
as a measured success. If every observed workflow is skipped/neutral, CI is
`unknown`, not `success`. When there is an executed success plus an optional
skipped workflow, the skipped workflow remains nonblocking; a real current
failure still wins. This is a bounded **push-run evidence** classification,
not a required-check enumeration, enabled/disabled workflow-definition count,
exact protected-main SHA attestation, or production-readiness result.


A page-cap limit is `INCOMPLETE`; a first-page total above 1,000 stops further
requests because those requests could not establish completeness within budget.
An API error, changed total, overlapping page,
or malformed/short page is `UNAVAILABLE`. Either condition prevents green CI
and a `GH-ACTIVE-CI` pass. Already observed workflow failures remain failures.
The public projection retains only controlled coverage labels and counts; it
never copies raw provider errors, run IDs, workflow names, or URLs. Historical
green rows without coverage evidence become `unknown` on projection.

A normal later collection can recover after a transient API failure or a
moving pagination window stabilizes, and collections with 101–1,000 retained
runs now read the remaining pages automatically. Histories above the cap stay
incomplete: resolving those requires a separately reviewed bounded collection
strategy or budget change, not deleting history or treating a truncated view
as complete. No workflow rerun, configuration change, or new credential is
performed by this reader.

### Space source-binding evidence

Source binding is a separate reading from reachability. A v1 claim requires both
runtime evidence and an immutable deployment manifest. Matching v1 metadata and
a verified signed source commit plus successful deployment run still remain
`UNKNOWN`: the claimed artifact digest has not been independently bound to that
build. Such metadata cannot promote a Space to `OPERATIONAL_SOURCE_BOUND`.
Contradictory evidence remains `INVALID`. The v2 reader recognizes
three exact document families: `szl.hf-deploy-manifest/v2`,
`szl.source-attestation/v2`, and `szl.build-info/v2`. All three must agree on the
source and artifact count; the manifest and runtime source must also agree on
the destination and workflow run, attempt, and ref.

The v2 reader checks equal Hub repository and running revisions, independently
fetches and hashes manifest-listed bytes at that immutable Hub revision, and
authenticates a GitHub-verified signed source commit plus a successful deployment
workflow run for the same repository, commit, ref, and exact historical attempt.
Artifact reads are bounded to 128 files, 4 MiB per file, and 16 MiB total.
Missing credentials or unreadable evidence remain `UNKNOWN`; contradictory
evidence is `INVALID`. Even when those checks agree, v2 remains `UNKNOWN` because
the artifact map has not been cryptographically bound to the claimed GitHub run.
It cannot promote a Space to `OPERATIONAL_SOURCE_BOUND`. An attestation reference
in `szl.deployment-source/v3` likewise remains `UNKNOWN` until cryptographic
verification is implemented.

This is a narrow cross-source observation, not a cryptographic release receipt,
proof of whole-repository parity, inference quality, training completion, or a
safe writable-storage boundary. A runtime's self-reported integrity result is
not sufficient on its own. Private evidence still passes through the closed
public-projection allowlist below.

### Scoped Space readiness projection

Four public, documented Space contracts have an additional bounded GET witness:
`a11oy` (`/readyz` plus `/api/a11oy/v1/honest`), `immune-lattice`
(`/readyz`), `szl-frontier` (`/api/ready` plus `/api/source`), and
`szl-brand-campaign` (the static root page). All other Spaces say
`NOT_EVALUATED`; private Spaces are never probed by this layer. The projection
records a controlled state, scope, route, HTTP status, and selected declared
flags. It never publishes raw response bodies or arbitrary provider messages.

`a11oy` remains `TRANSITIONING` while the Hub head and provider runtime SHA
disagree, even if the old runtime answers HTTP 200. A matching readiness
response is only `SCOPED_READY_SOURCE_UNVERIFIED` unless the separate source
binding is observed and agrees with the served Git SHA. `immune-lattice` HTTP
503 stays `NOT_READY`; `szl-frontier` operator readiness can coexist with
`PRODUCTION_HOLD` and a *declared* source drift; the stock static campaign is
`PLACEHOLDER` despite HTTP 200. None of these statuses independently proves
production authorization, source parity, or scientific quality.

## Public and internal evidence boundary

The collectors may use read-only credentials to evaluate evidence that is not public. That evidence is never returned directly by `/api/health`, written to `static/data.json`, printed by `refresh_snapshot.py --stdout`, or uploaded as a workflow artifact.

The public report is constructed from a closed, versioned allowlist. Unknown fields are dropped. GitHub repositories must be explicitly public, Hugging Face assets must have `private` set to the literal boolean `false`, collection membership is removed, credential posture is reduced to a public scope marker, and governance is recomputed from the projected evidence. Raw errors, paths, principals, grants, private identifiers, revisions, filenames, runtime URLs, and private-derived counts stay internal.

A scheduled refresh creates `census-internal.json` only as an ephemeral, gitignored input to the fail-closed receipt gate. The workflow artifact contains only the public projection and the sanitized receipt; it never contains the internal census.

### Public repository file-audit projection

`szl.repository-file-audit-public/v3` admits a repository only when its retained
provider metadata has literal `private: false` and coherent `visibility: public`.
Historical visibility-only rows remain unadmitted; a label cannot replace the
missing boolean. The internal collector retains that boolean on complete and
incomplete results.

Public totals, finding severities, inspection counts and repository digests are
recomputed from the closed public records. Internal population reconciliation,
private counts and states, collector principals, raw error messages, finding
details and unknown nested extensions are excluded. Public reconciliation stays
unverified: a public subset cannot prove complete enumeration of the private
estate. An empty subset or an unknown/error-bearing public state remains
`INCOMPLETE`. Public omission does not change internal enforcement or its exit
policy. Automated pattern findings require source triage; they are not verified
vulnerabilities.

Each new collection carries its original start/completion times, per-source
observation windows, a unique collection ID, the exact source-data digest, and
the collecting GitHub source/run/attempt. Cached reads preserve those fields.
The public projection exposes only the collection ID and collection times.
These fields establish consistency; they do not authenticate a signature or
prove organization-wide coverage.

The scheduled receipt step verifies that binding and recomputes the closed
public projection before staging `census-public.json` for upload. A failed
collector, old fallback, different run attempt, changed source bytes, or
different public projection withholds the snapshot. The failure receipt still
survives. `static/data.json` remains the dated website fallback and is never
uploaded merely because a new scheduled run occurred. Missing collection
metadata in historical snapshots remains unverified. A fresh partial collection
can be retained as diagnostic evidence while the overall census gate fails.

The scheduled census deliberately deletes `census-internal.json` before uploading
the public snapshot and sanitized receipt. Do not retain that internal census to
close a traceability gap: it contains private estate details. The receipt instead
includes `observations.governance_controls` and
`observations.governance_recomputed_controls`, each containing only the 15 fixed
policy control IDs and their statuses. The first describes the embedded evaluation;
the second describes source-data recomputation. A structurally invalid evaluation
produces `null`, not inferred passing controls. Each valid list reconciles with its
corresponding summary. No evidence text, repository names or arbitrary control IDs
are copied into these lists, and all existing fail-closed checks remain in force.

`snapshot.sha256` identifies the exact original input bytes. Its
`sha256_verification=REQUIRES_ORIGINAL_INPUT_BYTES` explicitly limits verification:
the scheduled census does not retain those private bytes, so that digest cannot
be independently checked from the retained public projection. Verify the retained
`census-public.json` bytes against `public_snapshot.sha256` instead. Neither that
public-byte match nor the control lists establish a signature, a governance pass,
or operational readiness.

## Solo-maintainer change control

The governed operating model is intentionally `solo-maintainer`. It does not claim or require a second human, and it does not use DCO as the primary security control. Releases instead require:

- a cryptographically verified signed commit;
- protected exact-head CI and resolved review threads;
- least-privilege workflow permissions and credentials;
- provider-fixed, schedule-only execution for jobs that receive organization secrets;
- immutable provenance and artifact digests;
- an auditable, fail-closed merge receipt.

## Run

```bash
python -m pip install --require-hashes -r requirements.txt
PORT=7860 python3 app.py
# open http://localhost:7860/
```

Optional credentials expand the internal evidence scope without expanding the public response surface:

- `GITHUB_TOKEN`, `GH_TOKEN`, or `SZL_GITHUB_TOKEN` for private GitHub metadata, protection, and alert APIs.
- `HF_TOKEN` or `HUGGING_FACE_HUB_TOKEN` for private Hugging Face repositories and buckets. Use a fine-grained, organization-scoped read credential with no global or write grants.

Supplying a credential does not establish organization-complete visibility. The
admin settings repository export (`GET
/api/organizations/SZLHOLDINGS/settings/repositories`) is read twice around the
per-type census. Only unique typed model, dataset, Space, kernel, and bucket IDs
that agree across both exports and all five detail listings receive a
`RECONCILED` repository-export state and a deterministic typed-ID digest. The
credential identity and organization admin role must be observed; a legacy token
still fails the separate fine-grained, no-global-grants least-privilege gate.
The export does not enumerate collections or non-repository organization assets,
so the overall HF inventory and scheduled receipt remain `UNKNOWN` /
`FAIL_CLOSED` without separate authoritative collection visibility. Internal
repository IDs and the export digest are excluded from the public projection.

Endpoints:

- `GET /` — responsive estate dashboard.
- `GET /api/health` — cached, versioned public projection; never the credential-derived internal census.
- `GET /api/proof-graph` — read-only public source/asset topology with an explicit UNSIGNED checksum, dashed UNKNOWN cross-provider edges, and no private repositories or execution authority. The interactive `/proof-graph` viewer projects a 3D layout in a self-hosted canvas; its positions are illustrative, not real-world spatial coordinates. It consumes the existing bounded cache and performs no additional provider reads.
- `GET /api/portal` — a small public-only investor/developer index derived from the same cached projection. It labels collection age and HTTP transport separately from source parity, runtime readiness, evaluation, and release authority; a missing or older-than-24-hour collection leaves current observations `UNKNOWN`.
- `GET /healthz` — service liveness and schema version.

Public API requests never run or wait for provider collection. A cold or expired
response schedules at most one background refresh shared by `/api/health`,
`/api/portal`, and `/api/proof-graph`; until that refresh succeeds, all three return HTTP 503 with
`{"error":"UNAVAILABLE"}` and `Retry-After: 60`. The refresh precomputes all three
public response bodies when the graph is admissible. A graph-only projection
failure leaves the existing health and portal readbacks available while the
graph endpoint returns bounded HTTP 503; it never leaks error details or serves
an expired graph. Successful responses are cached for 60 seconds from
completion. A failed refresh backs off for 60 seconds and never serves expired
data as a current observation. Provider timestamps, coverage states, public
projection and governance rules are unchanged. `/healthz` remains a liveness
check and does not trigger collection or assert estate readiness.

The HTTP server admits at most eight request handlers, with a five-second socket
inactivity timeout. Overflow connections are closed before allocating another
handler; no waiting request queue or per-client refresh job is created. These
are per-process bounds: multiple service processes each have their own cache
and background collector. They do not claim a wall-clock deadline for the
background census; the existing bounded provider reads still govern that work.

## Static snapshot mode

When no live backend is available, the frontend falls back to the allowlisted public projection in `static/data.json` and labels the page `SNAPSHOT`. Regenerate it with the same collectors used by the live service:

```bash
python3 refresh_snapshot.py            # writes static/data.json and the gitignored census-internal.json
python3 refresh_snapshot.py --stdout   # same writes, then also prints the public projection
```

Both forms overwrite the tracked `static/data.json`, so run them only when you
intend to replace the dated fallback. The deadline defaults to 120 seconds
(`REFRESH_DEADLINE_S`). The printed `sources_ok` line describes the internal
collection. The public projection always reports the GitHub source as
`ok: false` (`PUBLIC_SUBSET` or `SOURCE_UNAVAILABLE`) because it omits private
repositories and organization-wide alert totals.

The snapshot refresh has a hard deadline, derives public output from the exact in-memory internal report, and replaces files atomically. If collection or projection cannot finish, it does not publish a partial file as a fresh complete census.

## Generated Series-A diligence

`build_series_a_diligence.py` transforms the allowlisted public `static/data.json` census into canonical JSON and Markdown without making network calls. It binds the census digest, locked target policy, and exact compiler Git revision only when every source-bound file is a regular tracked blob whose executing bytes match that revision. Dirty, untracked, missing, hidden-index, symlinked, hard-linked, CRLF-drifted, or caller-invented source bytes fail closed.

The CLI accepts only a public-projection-shaped census and rejects explicit internal/private repository or asset entries before writing an investor artifact. This guards against accidentally passing the internal collector report; labels in a caller-supplied JSON file are not independent proof that its contents were publicly visible. Use the governed collector and sanitized receipt for provenance, and keep private inventory out of public inputs.

`--receipt /path/to/census-receipt.json` optionally checks the **raw supplied public census bytes** against a sanitized receipt from the same collection. The strict, size-bounded parser requires the public projection schema, exposure, schema version, and collection ID, plus the receipt schema, `public_snapshot.state=FRESH_COLLECTION_BOUND`, exact public-byte SHA-256, and matching collection ID. A valid pair marks only `public_snapshot_receipt` as `MEASURED`; absent receipt remains an `UNAVAILABLE` gap, while a requested malformed or mismatched receipt is `DIVERGENT` and the CLI exits 6 without publishing outputs. Historical byte checks remain reproducible without a receipt. The repository does not bundle a receipt for `static/data.json`, and CI must not fabricate one.

This is unsigned consistency between supplied public bytes and a supplied receipt, **not** authentication of the collecting run, independent validation of internal snapshot bytes, or a governance pass. In particular, `receipt.status=FAIL_CLOSED` can coexist with `public_snapshot.state=FRESH_COLLECTION_BOUND`; the compiler does not equate those verdicts. The public `source_snapshot_sha256` is not compared to `receipt.snapshot.sha256` because they can describe different internal serializations.

```bash
python3 -I -B build_series_a_diligence.py \
  --input static/data.json \
  --source-revision "$(git rev-parse HEAD)" \
  --output generated/series-a-diligence.json \
  --markdown generated/SERIES_A_DILIGENCE.generated.md \
  --require-source-bound

python3 -I -B build_series_a_diligence.py \
  --input static/data.json \
  --source-revision "$(git rev-parse HEAD)" \
  --output generated/series-a-diligence.json \
  --markdown generated/SERIES_A_DILIGENCE.generated.md \
  --check --historical-check \
  --require-source-bound
```

An explicit `--as-of` makes a build byte-reproducible. A default `--check` first verifies stored bytes and then reevaluates freshness at current UTC; stale evidence exits nonzero. Its top-level digest, state, and gap count always identify the byte-verified stored output, while the ephemeral current reassessment is reported separately under `current_*` fields and is not written. `--check --historical-check` verifies historical bytes only and reports `HISTORICAL_BYTES_VERIFIED`; it is not a current-readiness claim.

The compiler-source check uses `git hash-object --no-filters` against the exact tree object. `.gitattributes` pins the six source-bound files to LF, while the verifier hashes executing working-tree bytes without normalization, so CRLF drift fails closed. The isolated loader resolves the exact local package and compiler files without adding the repository to `sys.path`, so untracked root modules cannot shadow standard-library dependencies. The JSON and Markdown outputs must also be distinct from the input and policy, including filesystem aliases.

A persistent deterministic cross-process lock serializes writers for the normalized output pair. Both outputs are staged beside their destinations, flushed, and file-synced before replacement; caught publication failures restore the prior pair. Replacement remains sequential, so it is **not two-file crash-atomic**. Consumers must run `--check` before treating the pair as consistent.

The artifact digest proves canonical-content consistency only. It does not prove authorship, signing identity, deployment, or runtime availability. Those claims remain at the signed-commit, protected-CI, receipt, and witnessed-runtime boundaries.

The target policy records the dated conditional Killinchu exception but does not convert targets into observed state. Missing route/tab ownership, cost evidence, governed MCP authorization, reproduced model promotion, a generated API and typed-client contract, a shared design-system contract, or the complete Space deployment reconciliation chain remains explicit. More than five normal public Spaces plus the single dated exception is `DIVERGENT`, not green. An incomplete or unavailable Space census emits `null`, never a fabricated zero or false, for observation-dependent public-Space facts; during the active exception window, the observation-dependent authorized maximum remains `null` as well.

## Autonomic SRE control plane

`.github/workflows/autonomic-sre.yml` runs a single-flight controller
(`python -m autonomic.controller_v2`) every five minutes. It reads the
public-estate manifest only from the cryptographically verified
`szl-holdings/a11oy` default-branch tip, probes every declared required route
from its fixed HTTPS origin, and persists the state machine in one private
machine-managed issue.

**Automatic recovery is currently held.** Since 2026-10-04 (#231),
`autonomic/policy.json` sets `recovery.enabled` to `false`; the reasons and the
exit criteria are in
[`docs/incident-recovery-hold-20261004.md`](docs/incident-recovery-hold-20261004.md).
While the hold is in force the controller still validates the manifest, probes
every route, persists state, and emits receipts, but it requests no Hugging Face
mutation: an availability failure that would otherwise be eligible for recovery
is recorded as `DEGRADED` with the reason `automatic recovery is disabled by
policy`. The hold has no automatic expiry. The recovery rules below describe the
planner, not what the scheduled job currently does.

The states are `HEALTHY`, `SUSPECT`, `DEGRADED`, `RECOVERING`, and `INCIDENT`.
Two consecutive availability failures are required before mutation. When
recovery is enabled, the controller admits only one of three exact Hugging Face
operations:
`resume`, `soft-restart`, or `factory-restart`. One action is allowed per cycle,
each surface has a 30-minute cooldown, and three failed recovery attempts
terminalize to `INCIDENT` instead of creating a restart storm.

Source drift is never treated as an availability restart. The controller records
it as an incident because a runtime reboot cannot repair source identity. DNS,
billing, hardware allocation, visibility, repository content, arbitrary shell,
and asset deletion are outside this controller's authority.

Each cycle emits a sanitized JSON receipt and SHA-256 artifact. Credential values
are neither read back nor included in state, summaries, or artifacts.

Offline contract check (the scheduled workflow runs the v2 form; the v1
`autonomic.controller` entry point accepts the same flags):

```bash
python -m autonomic.controller_v2 --offline-contract-only \
  --output reports/autonomic-sre-contract.json
```

For recovery, the v2 controller uses the first non-empty secret among
`HF_ORG_TOKEN`, `HF_WRITE_TOKEN`, `HF_TOKEN`, `HUGGINGFACE_TOKEN`, and
`HUGGING_FACE_HUB_TOKEN`, and records only the selected name, never the value.
Without any of them, a planned recovery is `BLOCKED` with `HF_TOKEN_MISSING`; it
never converts missing authority into a successful repair.

## Autonomic SLO verdict evidence

The independent `autonomic-slo.yml` workflow captures the controller exit code
while it saves immutable receipts. Its final evidence step publishes the
recorded reasons and rolling-window metrics, then preserves the verdict:
`HEALTHY` returns 0, `INCIDENT` returns 2, and missing, invalid, or inconsistent
evidence returns 1. A successful artifact upload does not establish reliability.
The gate checks the canonical receipt digest, its sidecar, and agreement with
the controller exit code before accepting a healthy result.

Current `UP` probes do not erase failures retained in the 60-minute, 6-hour,
and 24-hour windows. For example, main run `34695092582` observed all seven
surfaces reachable but retained 24-hour availability failures for A11oy,
Killinchu, and Lyte. Their measured burn exceeded policy and correctly produced
`INCIDENT` / `SEV3`. Timeout receipts do not establish which service, provider,
or network component caused the timeout. Recovery requires fresh observations
passing the existing objectives; history and thresholds must not be changed
merely to make the workflow green.

`tests/test_slo_workflow_evidence.py` exercises the real workflow gate with
deterministic healthy and historical-incident fixtures, plus missing, malformed,
tampered, and contradictory evidence. A passing fixture or CI run proves the
gate's behavior; only a scheduled live receipt proves that cycle's SLO verdict.

## Scheduled watch liveness

A cron inside a target repository cannot report its own disablement: GitHub
disables schedules in public repositories after 60 days without repository
activity. `.github/workflows/scheduled-watch-liveness.yml` therefore runs here
every six hours (plus manual dispatch) and supervises the watch workflows
declared in `governance/scheduled-watches.v1.json`. For each entry,
`tools/scheduled_watch_liveness.py` requires the workflow `state` to be
`active`, its newest completed `schedule` run to be younger than
`max_age_hours` and green, and every declared job of that run to be green.
Verdicts are `HEALTHY`, `STALE`, `DISABLED`, `FAILED`, or `UNKNOWN`; `UNKNOWN`
is never healthy. The alert is the red run plus its step summary. The checker
uses only GET requests with the run's `GITHUB_TOKEN` and never re-enables,
dispatches, or writes to a target. That token can read other repositories only
when they are public, so watched targets must be public. This repository is
currently private, so the public-repository 60-day disablement does not apply
to the supervisor itself; if the repository is made public, the supervisor
carries the same boundary.

## Edge contract

`.github/workflows/edge-contract.yml` checks every six hours (plus manual
dispatch) that the Cloudflare edge gives an **unpaid, unauthenticated** client
what the owner decided. [`edge/contract.yaml`](edge/contract.yaml) declares,
per host and path: free surfaces get 2xx, 3xx or an origin 401/403 and never
402; paid machine endpoints get 402 with an x402 `PAYMENT-REQUIRED` header
whose decoded amount, scheme, network, asset, payTo and resource URL equal the
live rule; internal paths get a 403 that is not a bot challenge.
[`edge/check_contract.py`](edge/check_contract.py) (standard library only)
sends one GET, and on paid endpoints also one POST with the invalid body `{}`,
follows no redirects, labels each answer (`402-paywall`, `403-challenge`,
`5xx-origin` and so on), writes `reports/edge-contract-receipt.json` with a
`.sha256` sidecar, and exits 1 on any violation. The job needs no secrets and
only `contents: read`.

```bash
python -I -B edge/check_contract.py --validate-only
python -m unittest tests.test_edge_contract -v
```

The tests run against a local `http.server` stub, so they prove the checker's
behaviour, not the edge's; only a scheduled or dispatched run's receipt says
what the edge did. A GitHub-hosted runner is not a verified bot, so rules that
charge verified bots only are outside what this check can see. Semantics,
the seed evidence and the proof boundary are in
[`docs/EDGE_CONTRACT.md`](docs/EDGE_CONTRACT.md).

## Tests

```bash
python -m unittest discover -s tests -v
python -m compileall -q app.py refresh_snapshot.py build_series_a_diligence.py census autonomic scripts
python -m json.tool diligence/policy.json
python -m json.tool schemas/series-a-diligence.schema.json
```

The two `json.tool` commands verify document syntax only. Protected CI separately runs the dependency-free `validate_artifact` semantic contract and executes this repository's public Draft 2020-12 schema against the genuine source-bound artifact plus adversarial mutations. The schema executor independently recomputes the canonical artifact digest and reloads the exact local semantic validator, so redigested cross-field forgeries cannot earn a verified receipt. It also fails closed on unsupported keywords instead of silently ignoring them. This is an executable contract for the exact schema vocabulary used here, not a general-purpose implementation of every JSON Schema feature.

The regression suite verifies latest-per-workflow aggregation, fail-closed asset-class errors, strict Hugging Face identity and Space-host validation, model artifact and contract evidence, revision-bound operational-payload integrity, `FAIL > UNKNOWN > PASS` precedence, receipt non-disclosure, and public-projection canaries.

## Layout

```text
app.py                 schema-v2 HTTP service
build_series_a_diligence.py  deterministic diligence JSON and Markdown compiler
census/common.py        bounded HTTP, pagination, probes, and DNS primitives
census/diligence.py    fail-closed diligence compiler, validator, and renderer
census/github.py        dynamic GitHub organization census
census/huggingface.py   models, datasets, Spaces, collections, and buckets
census/sites.py         site headers plus SPF/DMARC evidence
census/report.py        isolated aggregation, cache, and public allowlist
census/receipt.py       internal-source-bound sanitized receipt gate
census/governance.py    fail-closed control evaluation (15 policy controls)
census/github_ci.py     bounded default-branch CI coverage contract
census/github_inventory.py  organization identity before repository pagination
census/space_readiness.py   scoped GET witnesses for four documented Spaces
census/portal_projection.py small public /api/portal view of the projection
census/file_audit.py    complete default-branch repository and file audit
refresh_snapshot.py    atomic internal/public snapshot writer
static/index.html       responsive, searchable dashboard
static/data.json        timestamped public fallback projection
governance/policy.json  solo-maintainer fail-closed control policy
diligence/policy.json  locked target roles and dated five-plus-one exception
schemas/series-a-diligence.schema.json  public artifact structure contract
autonomic/               fixed-origin state machine and recovery policy
governance/scheduled-watches.v1.json  declared external scheduled watches
tools/scheduled_watch_liveness.py  read-only watch liveness supervisor
edge/contract.yaml     unpaid-client edge contract (free, paid, internal)
edge/check_contract.py stdlib edge contract checker and receipt writer
tools/run_with_validated_github_reader.py  credential selection after inventory validation
tools/run_repository_file_audit.py  organization file audit behind the inventory gate
tools/pypi_release_path_audit.py  nightly fail-closed PyPI release-path audit
governance/pypi/        package manifest and canonical publish workflow and gate
scripts/verify_series_a_schema_contract.py  dependency-free Draft 2020-12 schema executor
docs/                   design records, incident holds, and verification notes
requirements-autonomic.lock hash-locked Hugging Face control closure
tests/                  collector, governance, receipt, and leak contracts
Dockerfile              pinned container runtime
```

Estate on Hugging Face: models, datasets and Spaces are published under the [SZLHOLDINGS](https://huggingface.co/SZLHOLDINGS) org.

## License

Apache-2.0 — see [LICENSE](LICENSE).


### Local agent storage-admission precheck (read-only)

The separate [Local Storage Admission v1](docs/LOCAL_STORAGE_ADMISSION.md) supplies a
source-bound, fail-closed Python precheck for SZL developer workstations. It
computes whether a **declared maximum job disk budget** can fit while leaving a
free-space floor (default 50 GiB), using the minimum of two local OS measurements.
It never deletes caches, runs jobs, stores credentials, takes reservations or
asserts that all autonomous agents obey it.

For example, `python -I tools/szl_storage_admission.py --mode admit --drive C:/ --reserve-gib 8`
returns 0 only for a measured preflight fit, 2 for a capacity HOLD, and 3 for
bad input or unavailable measurements. This is a **precheck, not a lease or
future-space guarantee**. The older privileged PowerShell V13 recovery script
remains intentionally source-blocked; this addition does not remove its hold.
Linux CI tests the portable implementation with synthetic disk fixtures, not
the owner's Windows drive.
