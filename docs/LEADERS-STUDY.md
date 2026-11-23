# Domain Leader Study — szl-org-health (live org-health dashboard)

OUROBOROS phase-3, cohort-02 tranche-2, Kimi ruling W26-C2T2-KIMI-20261123-ASK (GO, 7 bindings). PROPOSE-ONLY, DRAFT. Documentation only, no implementation in this PR.

## Current state (repo inspection 2026-11-23)
Python repo; description: live org-health dashboard with real GitHub CI/security, Hugging Face Space health, and DNS/email-auth posture. Topics: ci-health, dashboard, github-api, governance, governed-ai, honest-status.

## Domain leaders studied
| Leader | What they have | Key sources |
| --- | --- | --- |
| GitHub branch-protection + required-checks documentation | The canonical machine-readable contract for what green means: required status checks, contexts, strict/loose merge semantics, documented failure modes (queued checks, deleted contexts, running-after-required) — the leader ground truth for any CI-health scoring | docs.github.com/en/rest/branches/branch-protection; docs.github.com required-status-checks troubleshooting (accessed 2026-11-23) |
| GitHub status API semantics | Per-commit status states and their exact roll-up into protection decisions — the basis any honest dashboard must mirror, else it invents green. Per the required-checks docs: successful outcomes include skipped and neutral check results, not only success; and if a required workflow or check is deleted, its required context is not silently satisfied — it remains unsatisfied, typically reported as Expected/pending | required-status-checks troubleshooting doc (accessed 2026-11-23) |

## What the leaders do better
- Green is defined as a checkable contract (contexts + timing + merge settings), not a vibe; leaders document the known traps (a queued check can report a status before the required run reports, so the PR can look green briefly; if a required workflow or check is deleted, its required context stays unsatisfied as Expected rather than silently unlocking the branch).
- Failure modes are written down next to the feature, so a dashboard can classify health by measured failure class rather than truncating to a boolean.

## Gaps
- Description-measured posture exists, but no documented classification mapping to the leader failure modes (queued/deleted/stale contexts) was found in card scope for the GitHub leg.

## Ranked #1 absorb proposal (NOT implemented in this PR)
Adopt the leader failure-mode taxonomy in the dashboard's GitHub leg: every repo status renders as {green, red, expected/pending, queued, stale-context, unknown} mapped explicitly to the documented semantics, never collapsed to a binary. expected/pending is an explicit, non-green state for required checks not yet reported; skipped and neutral check results roll up as successful (green) per GitHub docs. Expected benefit: honest-status claim becomes externally checkable; eliminates manufactured-green reading paths. Cost/risk: low; display-contract change documented for future implementation PR. Validation: cross-render of the signature-wall repos matches sibling drain-lane classifications, where the exact repo list (currently 62) is pinned as a manifest inside that future implementation PR so the validation target is reproducible rather than a dangling count. Rollback: taxonomy removal only.

## Sources
- Branch protection REST docs: https://docs.github.com/en/rest/branches/branch-protection (accessed 2026-11-23)
- Required status checks troubleshooting: https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks (accessed 2026-11-23)
