# PS51 source identity and qualification boundary

Phase 2 continues the accepted inactive PR234 source baseline
`39a2070d2492ee9e674e81880552cb75b67821fd`.
It changes source only. It does not install a controller, start an estate
process, reconcile local files, change a schedule, or admit a release.

## Recovered source

`tests/fixtures/ps51/operator-23b1aaab.ps1.txt` preserves exactly 243573 bytes
from the installed `SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_PS51_JSON.ps1`.
SHA-256: `23b1aaabef7aed9c2801c975bead79ac16084432537cff26059952208b3d687b`.
Git attributes disable text conversion for this reference, including its mixed
line endings and UTF-8 BOM. Never invoke or dot-source the full reference.
Its full-controller behavior and canonical admission remain **BLOCKED**.

The previously reported October 5 native-exit repair binds predecessor
`c6ea52536a3a5c0562a8deb16de5a7db023bed802dff1029944317f12d1cda78`
to this result and names `Invoke-Native` as the only changed function. The later
claim of 14 native checks and 20 rapid repeats is historical **REPORTED** evidence
awaiting its matching receipt. The separately inspected older receipt at
`native-exit-repair-20261005-000827-b26b7541/TEST-RESULTS.json`, timestamp
`2026-10-05T04:08:30.0374286Z`, records **13 passed, 1 failed**, plus 20 rapid
repeats; SHA-256 `2005ab1156e60c2d832d1622244ecf3f84081b1319a5f4d5d90809e2e4c95b73`.
These are distinct historical claims, not fresh test executions.
Two current scoped GitHub code searches did not locate a canonical V11 template.
That is a coverage gap, not proof that no template exists. This reference does
not establish prior canonical admission, full-controller review, provenance
signatures, or permission to activate it.

`tools/RUN_SZL_CTO_RATE_AWARE.ps1` recovers the existing launcher source from
historical SHA-256
`f4589a196d9257afbd3096952717266127d5cbcd1960f4b2dd9f68afb1344bdc`.
The source launcher now resolves the adjacent recovered successor through the
shared identity function and then rejects admission. The installed launcher
remains unchanged with its historical stale pin.

The candidate is version `11.0.6-recovered-bounded.3`, 251617 bytes, SHA-256
`9ab9abe318b9b2706dc688fe5aa213755b8645a9e01f7170def9584a447a319b`.
All four executable entry points begin with the literal unconditional
`throw 'SZL_SOURCE_ADMISSION_HOLD'` before imports, preferences, policy reads,
mutexes, directories, environment changes or other effects. The existing three
operator invocation sites have been replaced by an always-rejecting admission
assertion. No environment value, confirmation phrase, flag, or forged manifest
can remove either source-level hold.

`Resolve-SzlPinnedOperator` accepts an absolute local source directory and returns
identity data: Path, SHA256, Bytes, Version, HistoricalAdmission=UNKNOWN,
ProspectiveAdmission=BLOCKED, RuntimeAdmission=BLOCKED and Boolean CanInvoke=false.
V12 and V13 default that directory to their own script directory; the launcher
also uses its own script directory. There is no ProgramData or timestamp fallback.
The library pins the exact candidate hash and length; the lineage manifest is
evidence, never an authorization input. Original admission remains UNKNOWN.
A future prospective acceptance can bind this recovered baseline and reviewed
transformations through normal protected admission without inventing historical
provenance. Runtime activation requires a separate reviewed transition.

## Repair contracts and remaining gaps

- Both selectors require the exact recovered successor filename, size and SHA-256. Missing,
  changed, unreadable or unparsable content fails closed without older-family
  or timestamp fallback. Root, ancestor and leaf reparse points are rejected;
  relative, traversal, wildcard and stream roots are refused. Hashing and parsing
  use one byte buffer. This does not establish an adversarial replacement lock.
- The new process helper retains the original native process handle, rejects
  unavailable/non-integer exits, and preserves nonzero exits and argument values.
- Stdout and stderr drain in alternating bounded chunks with explicit UTF-8 decoding. Arbitrary
  legacy code pages are not qualified.
- New process/pipe waits share a finite deadline; direct-child cleanup waits at
  most one additional second. Descendant-tree cleanup and timeout partial-output
  retention are not claimed.
- The historical V11 `Invoke-Native` still has parameterless `WaitForExit` calls.
  It is preserved as evidence, not upgraded by the new V13 helper. Its direct-
  child timeout tests cannot qualify descendant-held pipes or all cleanup paths.
  The separately named recovered successor addresses this native-helper gap;
  original historical admission and full-controller qualification remain blocked.
- Identity is returned as a descriptor; no operator invocation is admitted.
- Phase 2 adds pure remaining-budget arithmetic. Both Python version probes use
  one monotonic discovery clock (30 seconds by default, five seconds per probe).
  The launcher's GitHub budget loop shares its two-hour Stopwatch across probes
  (30 seconds per probe by default) and sleeps. Native timeouts use the smaller
  of the cap and remaining whole seconds; a subsecond remainder refuses before
  handoff. Completed observations are rechecked, sleeps are clamped, and there
  is no unconditional final probe. These are inactive source contracts pending
  exact-head CI, not operational qualification or a whole-controller bound.
- Existing native initialization, synchronous discovery reads, log writes and
  scheduling can still consume time outside the native wait limit. Direct-child
  cleanup may add up to one second. The five existing native/policy definitions
  and embedded Python payload are unchanged by Phase 2.

## Qualification

Run `powershell.exe -NoProfile -NonInteractive -File tests/Test-PS51ProcessContracts.ps1`
only where test-file execution is already permitted. Do not relax local policy
or evaluate the script through another route after an execution denial.

The harness hashes/parses the historical reference as data, imports only named
prospective shared/V13, selector and launcher definitions, and compiles its own offline C#
probe in a new temporary directory. Historical definitions are not executed.
It tests helper identity, exit7, unavailable exit, rapid exits, empty argv,
Unicode/spaces/quotes/backslashes, simultaneous streams, direct-child timeout,
and assertion negative controls. It never imports controller main or runs
production tools. Its small owned fixture/evidence directory is retained.
The accepted baseline contained 48 prospective/identity assertions. Native
assertions and timeouts remain unchanged; selector assertions now bind the
recovered candidate and its explicit lack of authority. Added contracts cover
same-length drift, invalid roots, read failure, actual owned junctions, adjacent
wrapper binding, forged admission metadata, and unconditional entry ordering.
Only named selector definitions are written to and loaded from an owned inert
fixture so their default PSScriptRoot binding is exercised. No entry point runs.
Phase 2 adds fake-clock discovery and budget-loop tests with native calls,
filesystem discovery, logging and sleep stubbed. Added tests invoke no real
Python, GitHub, auth, token capture, network, cleanup or entry point. Existing
native-probe assertions and timeouts remain unchanged; prior counts cannot
qualify the new head. The original failed mixed-suite replay is retained separately, byte for byte,
with both historical failure rows false. Its integrity check is not a new replay
or a historical qualification pass. See the source-by-source conclusion map in
`PS51_RECOVERED_SOURCE.md`.

Local execution is **BLOCKED**: Windows PowerShell 5.1 rejected the test file
under its existing execution policy. No policy/security setting changed.
The user authorized a source-only push to existing draft PR234 for qualification
on its existing native Windows runners. Repository push/PR triggers were reviewed:
this change runs source/tests and disposable container CI; production controller
and census workflows are schedule-only and unchanged. Independent source review
is complete. Historical native CI at `ecc3e620ecc910c3391b282d03a0f4115c2124ac`
passed 65/65 in each Windows PowerShell 5.1 job: runs `37409450282` / job
`112094353536` and `37409450252` / job `112094353683`. The PR test merge
`1b52f7b3ebb5e2e153f188336489027470395501` has the same tree as that head.
The earlier `9473f56` runs each passed 64/65; the one failure compared an 8.3
temporary-path alias with its expanded filesystem path. The corrected assertion
preserves exact fixture selection. Historical receipts exist in logs; those runs
did not upload their temporary JSON. Successor workflows retain sanitized JSON.
These results do not qualify later source revisions. See
`PS51_RECOVERED_SOURCE.md` for the separately identified recovered proposal.
Local execution and full-controller admission remain **BLOCKED**. New helper
qualification cannot establish missing prior admission or authorize activation.
