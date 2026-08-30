# szl-org-health

Live, fail-closed census and health dashboard for the SZL Holdings GitHub and Hugging Face estates.

Every displayed value is either a reading collected during the current request or an explicit `UNKNOWN`. Authorization failures, timeouts, incomplete pagination, and unavailable APIs are never converted into zero, healthy, protected, or operational states.

## What it inventories

| Source | Dynamically discovered evidence |
|---|---|
| GitHub (`szl-holdings`) | All repositories visible to the runtime credential, archive/visibility/default-branch metadata, preliminary role classification, latest **run per workflow** on the default branch, branch-protection readability, open PRs/issues, and organization security-alert counts |
| Hugging Face (`SZLHOLDINGS`) | Models, datasets, Spaces, collections, and buckets; exact repository SHAs and modification dates; declared model contract shape plus observed tensor, GGUF, estimator, and embedding artifacts; revision-bound operational-payload manifest size and SHA-256 verification; Space SDK, hardware/runtime stage, live root probe, and governed `/healthz` probes for the flagships |
| Sites and DNS | Reachability, security response headers, SPF, and DMARC posture |

The GitHub collector follows pagination instead of maintaining a hand-written repository subset. The Hugging Face collector uses the public Hub APIs with bounded pagination and isolates every asset class: for example, an unreadable bucket API is shown as `UNKNOWN` while independently verified Spaces and datasets remain available.

## Honesty contract

- Repository CI is calculated from the latest default-branch push run **for each workflow**. A newer unrelated green workflow cannot conceal a failing guard.
- Tensor/GGUF weights, serialized estimators, and embedding indexes are reported separately. A kernel may satisfy its declared contract without a weight file. Operational payloads satisfy their artifact expectation only when every revision-bound manifest entry is present and matches its declared byte size and SHA-256. Neither classification claims that inference or deployment was executed.
- Space `RUNNING` state and HTTP reachability are separate readings. Neither substitutes for the other.
- Direct bucket discovery may require an authenticated Hugging Face token. Without it, bucket count remains `UNKNOWN`; collection-visible bucket references are labeled as partial discovery.
- A 403/404 from GitHub branch-protection endpoints remains `UNKNOWN` because an unprotected branch and an under-scoped credential can be indistinguishable.
- Preliminary repository classifications are deterministic and visible. Anything not proven by the current policy is `unclassified`, not guessed.
- No credential values are returned by the API or rendered by the interface.

## Public and internal evidence boundary

The collectors may use read-only credentials to evaluate evidence that is not public. That evidence is never returned directly by `/api/health`, written to `static/data.json`, printed by `refresh_snapshot.py --stdout`, or uploaded as a workflow artifact.

The public report is constructed from a closed, versioned allowlist. Unknown fields are dropped. GitHub repositories must be explicitly public, Hugging Face assets must have `private` set to the literal boolean `false`, collection membership is removed, credential posture is reduced to a public scope marker, and governance is recomputed from the projected evidence. Raw errors, paths, principals, grants, private identifiers, revisions, filenames, runtime URLs, and private-derived counts stay internal.

A scheduled refresh creates `census-internal.json` only as an ephemeral, gitignored input to the fail-closed receipt gate. The workflow artifact contains only the public projection and the sanitized receipt; it never contains the internal census.

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

Supplying a credential does not establish organization-complete visibility. Bounded endpoint enumeration remains `UNKNOWN` until an authoritative organization reconciliation is observed.

Endpoints:

- `GET /` — responsive estate dashboard.
- `GET /api/health` — cached, versioned public projection; never the credential-derived internal census.
- `GET /healthz` — service liveness and schema version.

## Static snapshot mode

When no live backend is available, the frontend falls back to the allowlisted public projection in `static/data.json` and labels the page `SNAPSHOT`. Regenerate it with the same collectors used by the live service:

```bash
python3 refresh_snapshot.py
python3 refresh_snapshot.py --stdout
```

The snapshot refresh has a hard deadline, derives public output from the exact in-memory internal report, and replaces files atomically. If collection or projection cannot finish, it does not publish a partial file as a fresh complete census.

## Tests

```bash
python -m unittest discover -s tests -v
python -m py_compile app.py refresh_snapshot.py census/*.py
```

The regression suite verifies latest-per-workflow aggregation, fail-closed asset-class errors, strict Hugging Face identity and Space-host validation, model artifact and contract evidence, revision-bound operational-payload integrity, `FAIL > UNKNOWN > PASS` precedence, receipt non-disclosure, and public-projection canaries.

## Layout

```text
app.py                 schema-v2 HTTP service
census/common.py        bounded HTTP, pagination, probes, and DNS primitives
census/github.py        dynamic GitHub organization census
census/huggingface.py   models, datasets, Spaces, collections, and buckets
census/sites.py         site headers plus SPF/DMARC evidence
census/report.py        isolated aggregation, cache, and public allowlist
census/receipt.py       internal-source-bound sanitized receipt gate
refresh_snapshot.py    atomic internal/public snapshot writer
static/index.html       responsive, searchable dashboard
static/data.json        timestamped public fallback projection
governance/policy.json  solo-maintainer fail-closed control policy
tests/                  collector, governance, receipt, and leak contracts
Dockerfile              pinned container runtime
```
