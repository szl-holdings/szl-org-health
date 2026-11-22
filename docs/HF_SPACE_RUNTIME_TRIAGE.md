# Public Hugging Face Space runtime triage (read-only)

Source: `tools/hf_space_runtime_triage.py`. Uses Python standard library only.

Run `python -I -B tools/hf_space_runtime_triage.py --json` from an authorized
environment with public HTTPS access. It makes **one** bounded anonymous Hub
listing GET and **at most 99** public runtime GETs, with four workers and
8-second per-request timeouts. It never reads tokens or credentials, writes
files, starts Spaces, changes settings, wakes sleeping instances, or deploys.

The page must contain 1–99 unique, explicitly public `SZLHOLDINGS/` IDs.
100 results is **UNAVAILABLE** (pagination not proven), not a complete census.
Missing/invalid details are UNAVAILABLE, never zero. The output contains only
public Space names and typed metadata states. Exit 0 means every listed Space
has a RUNNING provider stage and equal Hub/runtime revisions **only**. Exit 2
means a nonmatching state; exit 3 means incomplete/invalid census.

**No exit code grants application readiness or production authorization.**
RUNNING, even with matching revisions, is not endpoint health, a GitHub
source-to-build attestation, model quality, authorization, or release approval.
SLEEPING may be ordinary scale-to-zero. PAUSED may be intentional. Investigate
the owning vertical's source and budget before proposing an authorized change.
Do not interpret this inventory as proof of all authenticated/private Spaces.

Offline tests: `python -m unittest discover -s tests -p test_hf_space_runtime_triage.py -v`.
