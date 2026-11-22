# Domain Leader Study — szl-org-health (live org-health dashboard)

OUROBOROS phase-3, cohort-02 tranche-2, Kimi ruling W26-C2T2-KIMI-20261123-ASK (GO, 7 bindings). PROPOSE-ONLY, DRAFT. Documentation only, no implementation in this PR.

## Current state (repo inspection 2026-11-23)
Python repo; description: live org-health dashboard with real GitHub CI/security, Hugging Face Space health, and DNS/email-auth posture. Topics: ci-health, dashboard, github-api, governance, governed-ai, honest-status.

## Domain leaders studied
| Leader | What they have | Key sources |
| --- | --- | --- |
| GitHub branch-protection + required-checks documentation | The canonical machine-readable contract for what green means: required status checks, contexts, strict/loose merge semantics, documented failure modes (queued checks, deleted contexts, running-after-required) — the leader ground truth for any CI-health scoring | docs.github.com/en/rest/branches/branch-protection; docs.github.com required-status-checks troubleshooting (accessed 2026-11-23) |
| GitHub status API semantics | Per-commit status states (success/failure/pending) and their exact roll-up into protection decisions — the基础上 any honest dashboard must mirror, else it invents green | same doc family (accessed 2026-11-23) |

## What the leaders do better
- Green is defined as a checkable contract (contexts + timing + merge settings), not a vibe; leaders document the known lies (queued check reads green-then-pends, deleted contexts silently unlock).
- Failure modes are written down next to the feature, so a dashboard can classify health by measured failure class rather than truncating to a boolean.

## Gaps
- Description-measured posture exists, but no documented classification mapping to the leader failure modes (queued/deleted/stale contexts) was found in card scope for the GitHub leg.

## Ranked #1 absorb proposal (NOT implemented in this PR)
Adopt the leader failure-mode taxonomy in the dashboard's GitHub leg: every repo status renders as {green, red, queued, stale-context, unknown} mapped explicitly to the documented semantics, never collapsed to a binary. Expected benefit: honest-status claim becomes externally checkable; eliminates manufactured-green reading paths. Cost/risk: low; display-contract change documented for future implementation PR. Validation: cross-render of the 62 signature-wall repos matches sibling drain-lane classifications. Rollback: taxonomy removal only.

## Sources
- Branch protection REST docs: https://docs.github.com/en/rest/branches/branch-protection (accessed 2026-11-23)
- Required status checks troubleshooting: https://docs.github.com/pull-requests/collaborating-with-pull-requests (accessed 2026-11-23)
