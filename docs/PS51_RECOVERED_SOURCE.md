# Recovered V11 source proposal and wait boundaries

This is a new, inactive source proposal in PR234. It is not evidence that the
original V11 was admitted, and it does not authorize controller execution.
The installed operator, launcher, disk guard and schedules remain unchanged.

## Lineage

The historical reference `tests/fixtures/ps51/operator-23b1aaab.ps1.txt` remains
exactly 243573 bytes with SHA-256
`23b1aaabef7aed9c2801c975bead79ac16084432537cff26059952208b3d687b`.
Its runtime version is `11.0.6-rate-safe`; its older descriptive header says
`11.0.0`. The retained repair receipt reports predecessor
`c6ea52536a3a5c0562a8deb16de5a7db023bed802dff1029944317f12d1cda78`
and identifies `Invoke-Native` as the only repaired function. That receipt does
not establish protected source admission. Its test counts are historical
**REPORTED** evidence; separately replayed native tests have their own receipts.

`tools/SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_RECOVERED_1.ps1` has a distinct version,
`11.0.6-recovered-bounded.3`. The adjacent lineage JSON records exact byte ranges
and hashes for six transformations: identity note; first-statement admission
hold; standalone inert native
definitions and read-only policy preflight; the V11 native wrapper; bounded
Python discovery probes; removal of
the historical watchdog's execution-policy override. Every byte outside these
ranges must match the original reference. The executable successor preserves
the BOM and mixed line endings; Git must not normalize its bytes.

The seven standalone definitions are exact copies of this revision's inert
process library. This keeps the existing whole-file watchdog copy self-contained
without adding a hidden adjacent-library dependency. Tests verify that equality.
No watchdog or copied script is installed or executed by this proposal.

Phase 2 continues accepted inactive source `39a2070d2492ee9e674e81880552cb75b67821fd`.
The new candidate is 251617 bytes, SHA-256
`9ab9abe318b9b2706dc688fe5aa213755b8645a9e01f7170def9584a447a319b`.
The five copied native/policy definitions are unchanged from that baseline.
All four entry points have an unconditional first-statement admission hold;
the three former operator invocations now call an always-rejecting assertion.
No runtime effects, token retrieval, authentication, ACL operation, cleanup,
service/volume operation or registration are enabled by this phase.

The embedded V10 Python payload is 108583 bytes with SHA-256
`19cd7b182c9b97ce9ec06a694dbc67f342ab87fe7c0de2288e9df47bbccdfee2`.
Decoding it as data reproduced the declared identity. `Get-EmbeddedController`
would write it to the per-run controller path; `Invoke-Controller` delegates to
the native wrapper. The payload is unchanged and is never executed by these tests.

The original canonical repository/path/revision, reproducible template mapping,
and protected admission/signature receipt for the historical V11 remain
**UNKNOWN**. Two fresh organization default-branch code searches found neither
the exact filename nor version; history, nondefault refs and unindexed sources
are not exhausted. A new explicitly recovered-source admission can establish a
future reviewed baseline through normal protected admission. It cannot recreate
missing historical provenance. This proposal's protected admission is **BLOCKED**
until that process completes; runtime activation requires separate authority.

## Native-helper change and test boundary

The V11 wrapper now uses the same bounded process implementation as V13: one
monotonic deadline for the direct process and both UTF-8 pipes, followed by at
most a one-second direct-child cleanup wait. Missing/non-integer exit observations
fail closed. The wrapper retains the V11 `File` result field, redaction, nonzero
exit behavior and Echo contract. A timeout throws; partial-output retention and
descendant-tree termination are not claimed. Batch/command-script entry points
are not qualified by the native executable probe and remain a compatibility gap.
The sole reader polls available bytes and alternates bounded chunks from both
pipes, with no background read tasks. Both owned readers are explicitly closed
on return or failure. The deadline covers process/pipe supervision after native
pipe initialization; it is not a total controller/bootstrap wall-clock guarantee.

The added synthetic descendant inherits the owned probe's output handles and
exits after eight seconds. Its parent exits immediately. The test requires a
one-second output deadline to reject and return in under four seconds, followed
by native write failures proving both read ends are closed. A negative control
keeps both readers open and verifies successful writes. This tests inherited-pipe
completion and resource release without an indefinite or production child.

The separate recovered-source harness imports only ten named inert definitions,
never the complete controller. It tests byte-range lineage, immutable embedded
payload, copied definitions, unavailable exits, quoting and Unicode, twenty
rapid exits, direct and descendant-held-pipe timeouts, redaction, result shape,
and policy preflight. Mutation controls reject altered source, lineage regions,
embedded payload, and reintroduced parameterless native waits.

V12 and V13 no longer set process execution policy. They call the read-only
preflight before controller work. It permits an already effective AllSigned,
RemoteSigned or Unrestricted policy and holds Restricted, Bypass, Undefined,
unknown or unreadable observations. It does not grant effect authorization or
relax any policy. Tests substitute only the policy reader and a mutation trap;
no real setting changes. The laptop's denied test execution remains **BLOCKED**.

## Remaining waits and source/runtime relationships

The observational coordinator repair follows accepted source
`27b5d43682755281927804bbc98bfddfd9aca1e3` without changing the recovered
candidate, library, lineage, native mechanics or embedded Python. Its worker
wait requires all four declared names, captures their nonempty unique instance
GUIDs from the supplied job objects once, and demands that exact name/GUID/count
coverage on every snapshot. Empty expectations, duplicate or missing identities,
changed instances, unreadable metadata and unsupported states return UNKNOWN.
Failed or Stopped returns FAILED; only all-Completed returns COMPLETED.
NotStarted/Running is an internal PENDING classification, never a final outcome.

The wait reuses the unchanged shared deadline arithmetic and one Stopwatch,
with the existing MaxHours/PollSeconds values (24 hours/30 seconds). Sleeps are
clamped to remaining milliseconds; observations and completion are checked
against expiry. Final outcomes are COMPLETED, FAILED, UNKNOWN or TIMED_OUT.
An exact-case gate holds every non-completion before Receive-Job, Remove-Job
or resume processing. No job discovery, recursive evidence scans, disk/mutex
probes or logging occur inside the new polling functions.

Tests import only the named observational definitions and use fake snapshots,
clocks, sleeps and downstream sentinels. They create or control no real jobs,
processes or mutexes and invoke no auth, network, cleanup or entrypoint. Negative
controls reject missing/forged/moved main gates and effect commands in polling
source. Existing assertions, timeouts, workflows and historical failures remain
unchanged; the new head needs its own native CI receipts.

This is a bound on polling decisions, not worker execution or successful audit
content. A blocking metadata getter, job output collection/removal, worker
termination, descendants and coordinator-lock lifetime are not qualified. Timeout
leaves workers untouched; the existing outer finally is unchanged. An owned-worker
lifecycle library would be separate work. All four entry HOLDs and unconditional
operator admission refusal remain intact, so no operational behavior is enabled.

Phase 2 replaces both direct invocations in `Resolve-PythonCommand` with the
existing bounded native helper. One Stopwatch covers direct and launcher probes;
defaults are 30 seconds overall and five seconds per probe. The launcher similarly
shares one two-hour Stopwatch between `Get-GitHubBudgetObservation` and
`Wait-SzlGitHubBudget`, with 30-second probe caps. Timeouts are the smaller of the
per-probe cap and floored remaining seconds; a subsecond remainder refuses before
native handoff. Completion and readiness are rechecked against the same clock.
Sleep uses only the remaining milliseconds; no unconditional final probe exists.
Unavailable/nonzero exits and malformed GitHub observations cannot become ready.

The two new shared arithmetic definitions are pure; the five existing native/
policy definitions are unchanged. Fake-clock tests stub native invocations,
discovery reads, sleeps and logging. The added tests perform no auth, token
capture, network, cleanup, real Python or full entrypoint invocation. Existing
native assertions and timeouts stay intact. New exact-head native CI is required.

This limits probe handoff timeouts and rejects stale completion; it does not
establish a hard elapsed bound for synchronous discovery, native initialization,
logging, OS scheduling or the whole controller. The native helper's direct-child
cleanup allowance of up to one second remains explicit. Every entrypoint HOLD
and the unconditional admission assertion remains intact.

Line numbers below refer to the historical V11 reference or to PR head
`ecc3e620ecc910c3391b282d03a0f4115c2124ac` for the other scripts.

| Surface | Observation and boundary |
| --- | --- |
| V11 lines 332/344/359 | The timed wait was followed by parameterless cleanup and completion waits. The recovered native definitions replace those paths; the historical reference remains untouched. |
| V11 line 58 | `WaitOne(0,false)` is a nonblocking ownership probe. |
| V11 line 168 | Direct `icacls` pipeline has no explicit deadline. Not exercised or qualified. |
| Recovered `Resolve-PythonCommand` | Both version probes use the shared aggregate clock and bounded native handoff in Phase 2. Discovery filesystem/registry reads and native initialization have no separate hard deadline. |
| V11 lines 2572–2600 | Direct Codex pipeline is inside a job with a 7200-second `Wait-Job`, but `Stop-Job`/`Remove-Job` cleanup has no explicit deadline. Not qualified by the helper tests. |
| V11 lines 2677–2682 | Workflow polling has an absolute deadline but a 120-second in-flight native call plus a 20-second sleep can overshoot it. |
| V11 lines 2772–2776 | HTTP body reads have 30-second per-read timeouts and a byte ceiling, not a total elapsed deadline. |
| V11 lines 2994/3007/3045 | Direct interactive `gh auth login`, token capture, and `Read-Host` have no explicit deadlines. No authentication or prompt is executed by tests. |
| V11 lines 3162/3215/3227 | Finite sleeps and outer cycle/runtime checks do not impose a hard deadline on every synchronous operation. |
| Embedded Python lines 179–180 | `subprocess.run` uses a timeout; its descendant/pipe cleanup is not separately qualified. The outer supervisor bounds the direct Python process only. |
| Embedded Python lines 430/479/621 | Executor contexts, `as_completed` and shutdown can wait without their own total deadline. HTTP socket timeouts also do not impose total response deadlines. |
| Recovered launcher budget functions | Phase 2 bounds probe handoffs and clamps rate-limit sleeps to the same monotonic budget. Synchronous logging and native initialization remain outside a hard total limit. The installed launcher is unchanged. |
| Coordinator worker-state wait (formerly lines 287-295) | Polling now has a monotonic deadline and strict name/instance/count coverage. Non-completion holds downstream processing. Metadata access, receive/removal and worker/lock lifetime remain unbounded or unqualified; the later writer wait is separate. No worker is started by tests. |
| V13 lines 590/743 | Writer waits are unbounded loops. They preserve ownership rather than admitting overlapping work, but full-controller wall-clock boundedness is not established. |
| V13 `Optimize-Volume`; embedded Python review-thread pagination | Volume operations and no-cursor/page-cap behavior remain outside this patch and unqualified. |

The source selectors now identify the exact repository-adjacent recovered
successor and return a descriptor with both prospective and runtime admission
BLOCKED and CanInvoke=false. They reject path redirection and content drift and
have no installed-helper or timestamp fallback. All entry points hold before
effects; identity selection cannot activate them. The installed external launcher
still has its historical stale pin, and no runtime reconciliation is performed.
Admission, installation and activation remain separate transitions.

## Evidence retention

The prior `ecc3e620` native results remain 65/65 in each job, as linked from
`PS51_SOURCE_IDENTITY.md`; their JSON was not uploaded. Later revisions require
fresh CI and cannot inherit those results. The two existing Windows workflows
now retain only sanitized JSON verdicts on success or failure using the already
reviewed full-SHA artifact action pin and unchanged contents-read permissions.
No raw child output, arguments, exception strings, filesystem paths, environment
or credentials are included. A failure before a receipt is written remains an
explicit missing-evidence failure. Whole-controller boundedness and operational
qualification remain **BLOCKED** by the separate paths above, regardless of
native-helper results.

The first successor CI at `bafff3205ba06821455faf5054dc7876e811f4a7`
passed the existing 65 checks in both jobs, but the recovered suite passed 35/38.
The failures exposed a null AST argument collection under PS5.1 and two pipe
fixture assertions that addressed the child's default standard handles instead
of the inherited parent pipe handles. The follow-up fixture passes those exact
inherited handles explicitly and retains the open-pipe output negative control.
No production helper change was made for these test fixes. Failure artifacts
`11389736760` and `11389353034` each retain both sanitized receipts; downloaded
archive hashes match GitHub's published SHA-256 digest
`1ecf03ebe1a6dd42e8f8bc7ca393ade8ba942a7895b94bc726e306b48967a6ec`.
These failed results remain preserved. At the subsequent head
`b1b1c5dfcaf5fd5ec21ac21ad9cf149ec10bcc92`, the recovered suite passed 38/38
in both jobs. The mixed suite passed 65/65 in the disk job, but 63/65 in the
coordinator job: `legacy empty argv` threw `NATIVE_EXIT_UNAVAILABLE`, and
`legacy concurrent stdout stderr` exceeded five seconds. Both exercised the
unchanged historical definitions, not the recovered executable. They are genuine
failures with unresolved causes; no passing retry supersedes them.

## Prospective qualification and archived historical replay

The accepted `a1ed3461` contract separated the source being qualified from prior replay
evidence. No assertion or timeout for a prospective definition is relaxed.
Both harnesses still throw on any failed current test; workflows contain no
`continue-on-error`, waived gate or ignored current-source failure.
The disk workflow's existing static step parses/checks markers in V13; the
coordinator's static step does the same for V12_1. Neither executes those entry
points. Whole-workflow success means those static checks and the prospective
contracts below passed, not full-controller safety or historical qualification.

| Receipt / CI conclusion | Source and scope |
| --- | --- |
| `process-contracts.json` at `a1ed3461` | 48 prospective/identity checks: named definitions from the shared process library and V13 wrapper, plus V12/V13 selector contracts and launcher identity as data. The receipt binds all four source hashes. Historical source is hashed/parsed as data only. |
| `recovered-v11.json` at `a1ed3461` | 39 checks for named definitions in the standalone recovered V11, byte lineage, policy-reader mocks, and validator controls. The added control rejects the actual hash-verified historical source for its parameterless waits; the synthetic-call control is retained. Candidate, manifest and harness hashes bind this conclusion. |
| `historical-replay-b1b1c5df.json` | Exact archived mixed-suite receipt: 63 passed, 2 failed, including 15 passed and 2 failed historical cases. It is copied unchanged into each artifact after hash/count/failure-name integrity checks. No historical definitions are replayed now; preserving this receipt does not qualify them. |

The archive fixture is 9886 bytes with SHA-256
`1c4956b577bfc43e6e341551f1347b902f0c90d77b4063f86acfbf2c7c16efcb`.
It came from [coordinator artifact 11389074520](https://github.com/szl-holdings/szl-org-health/actions/runs/37412426623/artifacts/11389074520),
whose ZIP SHA-256 is `08d55482659fae7f998a809d7349a984bc50025d9119b0dce1f8989d2d3db50e`.
That artifact has since expired under the Actions retention policy (the run now
lists no artifacts), so the link no longer resolves; the committed fixture and
the digests recorded here are the durable evidence.
The original run `37412426623`, job `112103605426`, tested head
`b1b1c5dfcaf5fd5ec21ac21ad9cf149ec10bcc92` through merge
`cc5c9d2618d31a821bdab5326fec205093d159b4` with main
`ce381bd9a933f9f5e3211b1041e889e1e98f1184`. Its harness SHA-256 is
`1b7335c97e00a47b6174117665df6ebd0e48f9d9249b45cf30be88a8106b17ba`;
the historical reference remains `23b1aaab...d687b`. The baseline receipt and
source are non-normalized fixtures, and the original remote/local archives remain
preserved. Counts in this archived receipt are not fresh measurements.

Fresh native CI is required for this changed test contract. Exact-revision results
and artifact links belong in the PR validation record. Even a green prospective
CI conclusion leaves runtime admission **BLOCKED**. Phase 1 changes prospective
selector expectations from historical `23b1aaab` to the new recovered identity,
retains all native assertions/timeouts, and adds deterministic identity/path and
static entry-hold contracts. Both current receipt counts must come from fresh
exact-head CI; the accepted baseline receipts are not reused as new results.
Tests reject removed, moved, conditional or comment-only guards, a swallowing
trap, pre-guard parameter/module work, and restored operator invocation as data.
They never execute an entry point. The process receipt also binds candidate and
lineage hashes. Prospective admission is still BLOCKED pending normal protected
review; original canonical admission remains UNKNOWN. All direct CLI/auth,
job-cleanup, coordinator-loop,
embedded-Python and other waits inventoried above remain outside the tested
bounded-native-helper claim.

Historical receipt clarification: the older local native-exit receipt at
`2026-10-05T04:08:30.0374286Z` contains 13 passed / 1 failed plus 20 rapid repeats
(SHA-256 `2005ab1156e60c2d832d1622244ecf3f84081b1319a5f4d5d90809e2e4c95b73`).
It is distinct from the later reported 14+20 claim, which needs its own matching
receipt, and from the archived b1b1c5df replay with 63 passed / 2 failed.
None is relabeled or rerun by this phase.
