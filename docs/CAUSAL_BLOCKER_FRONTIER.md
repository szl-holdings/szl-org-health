# Causal first-blocker frontier (advisory only)

`tools/causal_evidence_frontier.py` is a small, offline analysis of one redacted JSON observation. It reduces downstream symptoms to the deterministic, sorted set of first locally failing causal ancestors for four fixed targets: `served`, `model_inference`, `receipt_proof`, and `money_settled`.

It is **not** a real-time tracker, authorization engine, release gate, SLSA verifier, Lean proof, or production monitoring system. It does not execute inference, move money, emit a receipt, query a provider, fetch a URL, mutate a graph, or verify a signature. Existing review and release gates are unchanged.

## Fixed causal scope

The 13 gate IDs and parent relations are source-owned:

| Gate | Plane | Parents |
|---|---|---|
| `SOURCE` | `source` | none |
| `BUILD` | `build` | `SOURCE` |
| `HF_PUBLICATION` | `hf` | `BUILD` |
| `HF_IDENTITY` | `handoff` | `HF_PUBLICATION`, `SOURCE` |
| `RUNTIME` | `runtime` | `BUILD` |
| `MODEL` | `model` | `HF_PUBLICATION`, `RUNTIME` |
| `AUTH` | `auth` | `RUNTIME` |
| `INFERENCE` | `inference` | `AUTH`, `HF_IDENTITY`, `MODEL`, `RUNTIME` |
| `SERVING` | `serving` | `RUNTIME` |
| `SIGNER` | `signer` | `BUILD` |
| `CUSTODY` | `custody` | `INFERENCE`, `SIGNER` |
| `PAYMENT` | `payment` | `CUSTODY` |
| `SETTLEMENT` | `settlement` | `CUSTODY`, `PAYMENT` |

`served` terminates at `SERVING` and depends on the runtime, **not** on model inference; `model_inference` terminates at `INFERENCE`, `receipt_proof` at `CUSTODY`, and `money_settled` at `SETTLEMENT`. An HTTP-serving homepage can be reachable while Khipu inference remains unavailable. These are separate *caller-claimed* scopes, not assertions that serving, model execution, receipt proof, or settlement occurred.

Every gate must appear exactly once with exactly the fields in the implementation. State is one of `VERIFIED_CLAIM`, `HOLD`, `UNAVAILABLE`, or `INVALID`. All states, timestamps, SHA-40/SHA-256 values, identity flags, readback labels, and coverage counts are untrusted caller claims. `SOURCE_CLAIM` and `PROVIDER_AUTHENTICATED_CLAIM` distinguish the caller's evidence source; neither is independently authenticated by this module. Extra/private fields, duplicate JSON keys, unknown or cross-plane IDs, non-UTC/future/stale envelope time, malformed digests, zero denominators, and non-finite JSON values are refused. A stale/future individual gate becomes a blocker. A five-minute future skew is tolerated, matching the existing frontier lane; it is not a trusted-clock claim.

## Zero-veto relation

For target `t`, the advisory claim is the conjunction of effective verification over `t` and all its transitive prerequisites. Any local non-verification, stale/future timestamp, missing/mismatched source binding, incomplete supplied coverage, or failed required identity is a zero veto: no downstream green, average, or score can compensate. Along each prerequisite path, analysis reports the **earliest upstream local failure**, before any failing descendant; the sorted union across independent paths is `first_blockers`. For example, if `SOURCE=HOLD` and `INFERENCE=UNAVAILABLE` together, the first blocker for `model_inference` is `SOURCE`, not `INFERENCE`. The downstream `REPORTED_UNAVAILABLE` condition remains recorded in `gate_assessments.local_reasons`, so the causal cut suppresses duplicate symptoms without concealing observed failures on other branches. This is a syntactic diagnosis over caller-supplied claims, never independently authenticated evidence.

This is formally analogous to conjunctive prerequisite/weakest-link zero veto and to the pinned `lutar-lean` Boolean cross-component conjunction. No Lean theorem was run, no deployed-runtime refinement is claimed, and no unconditional or conditional Lutar uniqueness is asserted.

## Exact synthetic fixture

Run from the repository root. This deterministic fixture represents only synthetic claims. Runtime is claimed reachable while inference is unavailable; every other gate claims verification.

```bash
PYTHONDONTWRITEBYTECODE=1 python - <<'PY'
import json
from pathlib import Path
from tools.causal_evidence_frontier import GATE_PLANES, SCHEMA, TOPOLOGY

stamp = "2026-11-19T00:00:00Z"
source_sha = "af765edc49122cf84311b0f8e48ec080dfee3e47"
gates = []
for gate_id in TOPOLOGY:
    gates.append({
        "id": gate_id,
        "plane": GATE_PLANES[gate_id],
        "state": "UNAVAILABLE" if gate_id == "INFERENCE" else "VERIFIED_CLAIM",
        "observed_at": stamp,
        "source_sha40": source_sha,
        "content_sha256": "b" * 64,
        "identity_matches": True if gate_id in {"SOURCE", "HF_IDENTITY", "SIGNER", "CUSTODY"} else None,
        "readback": "PROVIDER_AUTHENTICATED_CLAIM" if gate_id in {"RUNTIME", "INFERENCE"} else "SOURCE_CLAIM",
        "coverage_numerator": 1,
        "coverage_denominator": 1,
    })
value = {
    "schema": SCHEMA,
    "observed_at": stamp,
    "evaluated_at": stamp,
    "max_age_seconds": 3600,
    "source": {
        "repository": "szl-holdings/szl-org-health",
        "commit_sha40": source_sha,
        "tree_sha256": "a" * 64,
    },
    "gates": gates,
    "credentials_recorded": False,
}
Path("/tmp/szl-causal-synthetic.json").write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
PYTHONDONTWRITEBYTECODE=1 python tools/causal_evidence_frontier.py \
  --input /tmp/szl-causal-synthetic.json
test "$?" -eq 2
```

The CLI prints the complete canonical result and exits `2` for a diagnostic HOLD. Its three model-dependent targets (`model_inference`, `receipt_proof`, `money_settled`) contain:

```json
{"first_blockers":["INFERENCE"]}
```

The distinct HTTP `served` target contains `{"first_blockers":[]}` and `state=ALL_PREREQUISITES_CLAIMED_VERIFIED` from caller claims alone. It does **not** certify any actual service or real model completion.

The `model_inference` blocker detail contains `"reported_state":"UNAVAILABLE"` and `"reasons":["REPORTED_UNAVAILABLE"]`; `RUNTIME` remains a separate claimed-verified gate. The result also always contains:

```json
{
  "classification": "ADVISORY_ONLY_NOT_RELEASE_PROOF",
  "production_authorized": false,
  "effects_authorized": false,
  "independent_signature_verified": false
}
```

An all-verified synthetic input exits `0` with state `CLAIMS_COMPLETE_NO_AUTHORITY`; this still does not authorize production or effects. Invalid input exits `3` with state `UNAVAILABLE`.

## Expected refusal

```bash
python - <<'PY'
from pathlib import Path
Path("/tmp/szl-causal-duplicate.json").write_text(
    '{"schema":"first","schema":"duplicate"}', encoding="utf-8")
PY
PYTHONDONTWRITEBYTECODE=1 python tools/causal_evidence_frontier.py \
  --input /tmp/szl-causal-duplicate.json
test "$?" -eq 3
```

Expected stdout, exactly:

```json
{"classification":"ADVISORY_ONLY_NOT_RELEASE_PROOF","effects_authorized":false,"error_code":"DUPLICATE_JSON_KEY","external_effects_performed":false,"independent_signature_verified":false,"network_access_performed":false,"production_authorized":false,"provider_readback_independently_verified":false,"schema":"szl.causal-evidence-frontier/v1","state":"UNAVAILABLE"}
```

The deterministic test suite is:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_causal_evidence_frontier -v
```

Owner review must confirm the fixed topology and schema against real source-to-runtime evidence before any producer adapter is proposed. Such an adapter is outside this work package.
