# Provider-recovery containment — 2026-10-04

## Evidence and decision

A11oy PR [2541](https://github.com/szl-holdings/a11oy/pull/2541) describes a GDW SQLite integrity incident and an admitted preservation prerequisite. Even verified preservation deliberately exits 2 with deployment not admitted; it is not authorization to resume the runtime.

The separate [SRE state issue](https://github.com/szl-holdings/szl-org-health/issues/41) nevertheless recorded a `PAUSED` A11oy and a successful provider resume **request** at 2026-10-04T19:08:24Z. The SRE source was `b51a4fde1b43d8d8ad3d15f879fb907b107d6bb2`. This observation does not establish which process paused the Space, that the runtime started, or that any additional data was damaged.

Direct source inspection found that both recovery planners treat PAUSED as eligible for resume and RUNTIME_ERROR as eligible for factory restart after their existing thresholds. They do not consult the canonical publisher's preservation decision. A provider pause alone is therefore not a shared maintenance fence.

## Bounded containment

Set the existing `autonomic/policy.json` recovery switch to **false**. Do not add another publisher, restart script, token, alternate storage location, or recovery path.

This inhibits this repository's automatic provider restart effects for all seven declared surfaces. It does not stop healthy services. Source checks, route probes, outage classification, issue-state persistence, and receipt output remain enabled. Healthy measurements remain healthy; unavailable or drifting measurements must not become green because recovery is held. Existing cooldowns, failure counts, attempts and source-verification requirements remain unchanged.

The hold has no automatic expiry or retry-based release. This is containment, not a database repair or a claim of restored service. It does not cancel an already-running job, fence other writers/controllers, or revoke provider credentials. After normal protected admission, inspect the next exact-source SRE cycle for zero provider mutation attempts. Reconcile any overlapping older run independently.

## Verification

The new `tests/test_recovery_containment.py` is discovered by the existing Estate census CI job. It exercises both actual planners across unavailable and source-drift states and checks valid offline contracts. A network-blocked integration fixture executes `controller_v2.run_live` with fake provider/GitHub dependencies, checks that no provider recovery is called, and requires truthful outage state plus written receipt and checksum.

The fixture is a test, not a live-provider observation. Native CI, protected merge admission, and a subsequent production cycle remain separate evidence. No test failure may be hidden to admit this change.

## Recovery exit criteria

Before any reviewed successor re-enables automatic recovery:

1. Verify private preservation of the original database and sidecars against immutable object identities and digests. Retain partial outcomes and never overwrite incident originals.
2. Identify every possible runtime/storage writer and establish a shared, source-bound maintenance/recovery fence. A healthy HTTP response, PAUSED label, or elapsed cooldown cannot clear it.
3. Qualify a recovery candidate on isolated copies: SQLite integrity, schema compatibility, acknowledged record/receipt continuity, idempotence and replay behavior. No empty-database fallback or fabricated completion receipt.
4. Prove the storage durability and acknowledgement contract under interrupted writes, lost acknowledgements, process death, concurrent writers, and restart. Do not assume bucket-mounted filesystem semantics are database-safe.
5. Deploy through the canonical publisher only, with exact source/artifact binding, an authorized restore generation, reversible rollout, and readback of customer-critical journeys. Keep the previous preserved generation available.
6. Run a bounded canary/observation window with explicit stop conditions, then verify current source parity, error/latency objectives, and private/public evidence boundaries. Only then review the recovery policy and this hold's tests together.

## Solo-maintainer release and debugging discipline

Use small changes and one canonical mutation owner per resource. Keep a failing reproduction, a narrow repair, security/contract checks, exact-head review, normal merge, immutable artifact identity, controlled rollout and live verification as distinct stages. Do not substitute another bot's summary for independent evidence or introduce a second-human requirement that the real solo-maintainer process cannot satisfy.

For this incident, the debug hypotheses are controller/preservation authority mismatch and unsuitable storage/writer semantics. Only the first has a direct source-level reproduction in this change; the second requires private incident evidence. Run adversarial break/fix tests offline with synthetic stores before any live exercise. Test stale authorization, lost write acknowledgement, duplicate dispatch, public/private projection leaks, and failed rollback. No active attack, load flood, paid compute or production database mutation is authorized by this document.

Transferable methods researched, not proprietary implementations copied:
- Google SRE: https://sre.google/workbook/canarying-releases/
- AWS Builders' Library: https://aws.amazon.com/builders-library/automating-safe-hands-off-deployments/
- Microsoft AI Red Team: https://learn.microsoft.com/en-us/security/ai-red-team/

These references inform the procedure; they do not certify SZL or establish that an estate-wide red-team exercise has been executed.
