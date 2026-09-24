# Autonomic SRE v2 — Two-Plane Reliability Architecture

SZL public-estate reliability is split into two independent control planes so a defect in recovery logic cannot also erase the evidence used to detect it.

## Plane A — bounded recovery

`autonomic-sre.yml` runs every five minutes. It reads the signed public-estate manifest, probes the exact declared routes, persists per-surface state, and may request at most one Hugging Face Space recovery per cycle. Two consecutive availability failures are required before mutation. Per-surface cooldowns and a fixed attempt budget prevent restart storms. Source-integrity drift is an incident, never a reboot target.

## Plane B — SLO and deadman

`autonomic-slo.yml` runs on an offset five-minute cadence. It has no service-restart, workflow-dispatch, source-write, DNS, hardware, deletion, or product-action authority. It independently:

- validates the exact signed manifest tip;
- probes every required route from a fixed HTTPS origin with redirects rejected;
- records surface availability and maximum route latency;
- aggregates compact 15-minute buckets for a bounded 14-day history;
- calculates 60-minute, 6-hour, and 24-hour error-budget burn;
- enforces a 99.9% availability objective, 2.5-second latency objective, and 20-minute recovery objective;
- verifies that the recovery workflow's scheduled heartbeat is no more than 20 minutes old;
- distinguishes provider payment, access, rate-limit, and legal blockers from ordinary runtime failure;
- maintains one compressed machine-state issue and one deduplicated reliability incident;
- requires three consecutive healthy cycles before closing an incident;
- emits an immutable JSON receipt and SHA-256 digest every cycle.

A recent failed recovery run still proves that the scheduler is alive; the SLO plane evaluates recovery success separately through route availability and error-budget consumption. This prevents a false deadman alarm from concealing a real service incident.

## Burn-rate semantics

For a 99.9% objective, the allowed error fraction is 0.1%. Error-budget burn is:

```text
observed error fraction / allowed error fraction
```

The controller requires minimum sample coverage before making a burn-rate claim. Sparse evidence cannot establish health or advance the three-cycle incident-closure counter; it records an observability `SEV3` incident until all windows have sufficient coverage.

Severity is deterministic:

- **SEV1** — fast and medium windows exceed their configured burn thresholds, or the recovery heartbeat is stale;
- **SEV2** — medium and slow windows exceed their thresholds, a provider blocker is observed, or recovery exceeds 20 minutes;
- **SEV3** — slow-window burn, sustained latency breach, a current outage without enough history for a stronger claim, or insufficient sample coverage to establish health.

## Evidence and privacy boundary

The durable state contains public route outcomes, timing aggregates, manifest revisions, and incident counters. It is compressed and size-bounded before being embedded in a machine-managed issue. Response bodies, credentials, authorization headers, private addresses, arbitrary commands, and product data are never persisted.

## Failure-domain boundary

The two GitHub-hosted planes remove routine human dependence for modeled software and provider-runtime faults. They cannot restore utility power, repair a failed motherboard, change BIOS behavior, revive an unavailable home ISP, or bypass a provider subscription requirement. Continuous physical availability still requires restore-on-AC-power-loss, UPS coverage, a Wake-on-LAN relay, and an independent network path.

## Verification

```bash
python -m py_compile autonomic/slo_controller.py tests/test_autonomic_slo.py
python -m unittest tests.test_autonomic_slo -v
python -m autonomic.slo_controller \
  --offline-contract-only \
  --output reports/autonomic-slo-contract.json
```

The offline receipt must show fixed signed-manifest and fixed-origin authority, while every mutating capability remains `false` except issue-state maintenance in the scheduled workflow.
