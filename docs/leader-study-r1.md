# szl-org-health domain leader study r1 (propose-only)

Date: 2026-11-22. Method: web-verified 2026 leaders. Documentation only: no code, CI, config, or existing-PR status changes. All absorb actions are FUTURE and non-authorizing; implementation and merges remain separately reviewed and gated by the signature wall.

## Domain: honest estate status surface (provider failures vs evidence integrity)

## Leaders studied (web-verified 2026-11-22)

1. **SRE error budgets** (burn-rate based status distinguishing degraded from down). [SRE Workbook](https://sre.google/workbook/implementing-slos/).
2. **Freshness-as-first-class-signal** monitoring practice (missing data more dangerous than bad data).

## Absorb actions (FUTURE PROPOSALS, non-authorizing)

1. (error budgets) Status classes are separate: provider-failure class (e.g., Router 503), evidence-integrity class (e.g., unsigned digest), and freshness class, never merged into one red/green.
2. (freshness) Every status cell carries window + sample size + last-seen; no cell renders green from stale data.
3. (honesty) The surface reports UNKNOWN first-class and never infers health from reachability.
Read-only alignment: open PRs #413 (separate Router 503 and Anatomy unsigned evidence) and #419 (provider failure precedence over SHA drift); no status claim.

## Sources (accessed 2026-11-22)

- Google SRE Workbook, implementing SLOs: https://sre.google/workbook/implementing-slos/ (book doctrine, non-normative)
- Freshness doctrine synthesized from SRE practice; no single canonical URL claimed.

## Do not do

Do not merge, bypass the signature wall, or claim implementation beyond this card.
