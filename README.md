# szl-org-health

Live, fail-closed census and health dashboard for the SZL Holdings GitHub and Hugging Face estates.

Every displayed value is either a reading collected during the current request or an explicit `UNKNOWN`. Authorization failures, timeouts, incomplete pagination, and unavailable APIs are never converted into zero, healthy, protected, or operational states.

## What it inventories

| Source | Dynamically discovered evidence |
|---|---|
| GitHub (`szl-holdings`) | All repositories visible to the runtime credential, archive/visibility/default-branch metadata, preliminary role classification, latest **run per workflow** on the default branch, branch-protection readability, open PRs/issues, and organization security-alert counts |
| Hugging Face (`SZLHOLDINGS`) | Models, datasets, Spaces, collections, and buckets; exact repository SHAs and modification dates; observed model weight filenames; Space SDK, hardware/runtime stage, live root probe, and governed `/healthz` probes for the flagships |
| Sites and DNS | Reachability, security response headers, SPF, and DMARC posture |

The GitHub collector follows pagination instead of maintaining a hand-written repository subset. The Hugging Face collector uses the public Hub APIs with bounded pagination and isolates every asset class: for example, an unreadable bucket API is shown as `UNKNOWN` while independently verified Spaces and datasets remain available.

## Honesty contract

- Repository CI is calculated from the latest default-branch push run **for each workflow**. A newer unrelated green workflow cannot conceal a failing guard.
- A model is reported as `weights-present` only when a recognized weight file is observed in the returned repository siblings. `no-weight-file-observed` is not treated as a trained model.
- Space `RUNNING` state and HTTP reachability are separate readings. Neither substitutes for the other.
- Direct bucket discovery may require an authenticated Hugging Face token. Without it, bucket count remains `UNKNOWN`; collection-visible bucket references are labeled as partial discovery.
- A 403/404 from GitHub branch-protection endpoints remains `UNKNOWN` because an unprotected branch and an under-scoped credential can be indistinguishable.
- Preliminary repository classifications are deterministic and visible. Anything not proven by the current policy is `unclassified`, not guessed.
- No credential values are returned by the API or rendered by the interface.

## Run

```bash
python -m pip install --require-hashes -r requirements.txt
PORT=7860 python3 app.py
# open http://localhost:7860/
```

Optional credentials expand visibility without changing honesty semantics:

- `GITHUB_TOKEN`, `GH_TOKEN`, or `SZL_GITHUB_TOKEN` for private GitHub metadata, protection, and alert APIs.
- `HF_TOKEN` or `HUGGING_FACE_HUB_TOKEN` for private Hugging Face repositories and buckets.

Endpoints:

- `GET /` — responsive estate dashboard.
- `GET /api/health` — schema-v2 machine-readable census, cached for 60 seconds.
- `GET /healthz` — service liveness and schema version.

## Static snapshot mode

When no live backend is available, the frontend falls back to `static/data.json` and labels the page `SNAPSHOT`. Regenerate it with the same collectors used by the live service:

```bash
python3 refresh_snapshot.py
python3 refresh_snapshot.py --stdout
```

The snapshot refresh has a hard deadline. If collection cannot finish, it keeps the prior snapshot rather than publishing a partial file as a fresh complete census.

## Tests

```bash
python -m unittest discover -s tests -v
python -m py_compile app.py refresh_snapshot.py census/*.py
```

The regression suite verifies latest-per-workflow aggregation, fail-closed asset-class errors, static Space URL construction, model-weight evidence, classification precedence, and pagination parsing.

## Layout

```text
app.py                 schema-v2 HTTP service
census/common.py        bounded HTTP, pagination, probes, and DNS primitives
census/github.py        dynamic GitHub organization census
census/huggingface.py   models, datasets, Spaces, collections, and buckets
census/sites.py         site headers plus SPF/DMARC evidence
census/report.py        isolated source aggregation and cache
refresh_snapshot.py    bounded static snapshot writer
static/index.html       responsive, searchable dashboard
static/data.json        timestamped fallback snapshot
tests/test_census.py    dependency-free collector contract tests
Dockerfile              pinned container runtime
```
