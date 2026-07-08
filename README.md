# szl-org-health

Live org-health dashboard for SZL Holdings. Reads **real data** from three sources
and renders a single status view — with an honesty contract: every value is a real
reading or an explicit `UNKNOWN`. Nothing is fabricated, and no source is ever shown
green when it could not be verified.

## Data sources

| Source | What it reads |
|---|---|
| GitHub (`szl-holdings`) | per-repo latest-CI conclusion, branch-protection coverage, open code/secret/dependabot alert counts, open PRs & issues |
| Hugging Face (`SZLHOLDINGS`) | runtime stage of each Space + `/healthz` for the monitored flagships |
| DNS / sites | reachability + security headers for the sites, and SPF/DMARC posture across the domains |

## Honesty rules

- A value is either a **real reading this request** or an explicit **UNKNOWN** (gray) — never a fabricated green/false.
- Endpoints requiring an admin-scoped token (org alert counts, branch protection) render `UNKNOWN` when the running token can't read them, rather than guessing.
- No secret values are ever surfaced.

## Run

```bash
PORT=7860 python3 app.py
# open http://localhost:7860/
```

The backend needs a GitHub token on the environment (via the credential proxy in
the SZL sandbox, or a `GITHUB_TOKEN`-style setup) to read the GitHub source; HF and
DNS reads are public.

- `GET /` — the dashboard UI
- `GET /api/health` — the live aggregated report (JSON), cached 60s
- `GET /healthz` — service liveness

## Static snapshot mode

When served as static files with no backend (e.g. a deployed preview), the frontend
falls back to `static/data.json` — a captured, **timestamped** snapshot. The header
badge honestly reads `SNAPSHOT` in that mode and `LIVE` when the backend is present.
Regenerate the snapshot with:

```bash
curl -s http://localhost:7860/api/health > static/data.json
```

A scheduled task refreshes this snapshot so a deployed board does not go stale.

## Layout

```
app.py              # backend: collectors + HTTP server (stdlib only)
static/index.html   # dashboard UI (single file, no build step)
static/data.json    # snapshot for static-serve mode
Dockerfile          # container for Space / server deploy
```
