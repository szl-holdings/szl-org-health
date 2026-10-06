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
`11.0.6-recovered-bounded.1`. The adjacent lineage JSON records exact byte ranges
and hashes for four transformations: identity note; standalone inert native
definitions and read-only policy preflight; the V11 native wrapper; removal of
the historical watchdog's execution-policy override. Every byte outside these
ranges must match the original reference. The executable successor preserves
the BOM and mixed line endings; Git must not normalize its bytes.

The five standalone definitions are exact copies of this revision's inert
process library. This keeps the existing whole-file watchdog copy self-contained
without adding a hidden adjacent-library dependency. Tests verify that equality.
No watchdog or copied script is installed or executed by this proposal.

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

The separate recovered-source harness imports only seven named inert definitions,
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

Line numbers below refer to the historical V11 reference or to PR head
`ecc3e620ecc910c3391b282d03a0f4115c2124ac` for the other scripts.

| Surface | Observation and boundary |
| --- | --- |
| V11 lines 332/344/359 | The timed wait was followed by parameterless cleanup and completion waits. The recovered native definitions replace those paths; the historical reference remains untouched. |
| V11 line 58 | `WaitOne(0,false)` is a nonblocking ownership probe. |
| V11 line 168 | Direct `icacls` pipeline has no explicit deadline. Not exercised or qualified. |
| V11 lines 2572–2600 | Direct Codex pipeline is inside a job with a 7200-second `Wait-Job`, but `Stop-Job`/`Remove-Job` cleanup has no explicit deadline. Not qualified by the helper tests. |
| V11 lines 2677–2682 | Workflow polling has an absolute deadline but a 120-second in-flight native call plus a 20-second sleep can overshoot it. |
| V11 lines 2772–2776 | HTTP body reads have 30-second per-read timeouts and a byte ceiling, not a total elapsed deadline. |
| V11 lines 2994/3007/3045 | Direct interactive `gh auth login`, token capture, and `Read-Host` have no explicit deadlines. No authentication or prompt is executed by tests. |
| V11 lines 3162/3215/3227 | Finite sleeps and outer cycle/runtime checks do not impose a hard deadline on every synchronous operation. |
| Embedded Python lines 179–180 | `subprocess.run` uses a timeout; its descendant/pipe cleanup is not separately qualified. The outer supervisor bounds the direct Python process only. |
| Embedded Python lines 430/479/621 | Executor contexts, `as_completed` and shutdown can wait without their own total deadline. HTTP socket timeouts also do not impose total response deadlines. |
| Recovered launcher line 35 | Its direct `gh` budget probe has no explicit native deadline; later rate-limit sleeps can overshoot the outer deadline. This source and the installed launcher are unchanged in this iteration. |
| Coordinator lines 287–295 | Worker-state loop has no elapsed deadline and job removal is not bounded. The later writer wait has a separate deadline. No worker is started by tests. |
| V13 lines 590/743 | Writer waits are unbounded loops. They preserve ownership rather than admitting overlapping work, but full-controller wall-clock boundedness is not established. |

Selectors still identify the historical PS51_JSON bytes. They do not silently
repin to the recovered successor. The installed external launcher still has its
historical stale pin, and no runtime reconciliation is performed. Admission,
installation, selector repinning and activation are separate transitions.

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
