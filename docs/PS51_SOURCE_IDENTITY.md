# PS51 source identity and qualification boundary

This proposal continues PR234 at `8a5c378810bea703f84a53f03a07b44e3ab499c8`.
It changes source only. It does not install a controller, start an estate
process, reconcile local files, change a schedule, or admit a release.

## Recovered source

`tests/fixtures/ps51/operator-23b1aaab.ps1.txt` preserves exactly 243573 bytes
from the installed `SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_PS51_JSON.ps1`.
SHA-256: `23b1aaabef7aed9c2801c975bead79ac16084432537cff26059952208b3d687b`.
Git attributes disable text conversion for this reference, including its mixed
line endings and UTF-8 BOM. Never invoke or dot-source the full reference.
Its full-controller behavior and canonical admission remain **BLOCKED**.

The retained October 5 native-exit repair receipt binds predecessor
`c6ea52536a3a5c0562a8deb16de5a7db023bed802dff1029944317f12d1cda78`
to this result and names `Invoke-Native` as the only changed function. Its
14 native checks and 20 rapid repeats are historical **REPORTED** results.
Two current scoped GitHub code searches did not locate a canonical V11 template.
That is a coverage gap, not proof that no template exists. This reference does
not establish prior canonical admission, full-controller review, provenance
signatures, or permission to activate it.

`tools/RUN_SZL_CTO_RATE_AWARE.ps1` recovers the existing launcher source from
historical SHA-256
`f4589a196d9257afbd3096952717266127d5cbcd1960f4b2dd9f68afb1344bdc`.
The proposal corrects its stale helper pin and adds the shared identity recheck.
The installed launcher remains unchanged. All three entry points now require
the adjacent inert library from the same reviewed source revision.

## Repair contracts and remaining gaps

- Both selectors require the exact PS51_JSON filename and SHA-256. Missing,
  changed, unreadable or unparsable content fails closed without older-family
  or timestamp fallback. Hashing and parsing use one byte buffer.
- The new process helper retains the original native process handle, rejects
  unavailable/non-integer exits, and preserves nonzero exits and argument values.
- Stdout and stderr drain concurrently with explicit UTF-8 decoding. Arbitrary
  legacy code pages are not qualified.
- New process/pipe waits share a finite deadline; direct-child cleanup waits at
  most one additional second. Descendant-tree cleanup and timeout partial-output
  retention are not claimed.
- The historical V11 `Invoke-Native` still has parameterless `WaitForExit` calls.
  It is preserved as evidence, not upgraded by the new V13 helper. Its direct-
  child timeout tests cannot qualify descendant-held pipes or all cleanup paths.
  Full V11 admission requires resolving that gap in its canonical source lane.
- Identity rechecks before the existing path-based invocation narrow drift but
  do not establish a lock against adversarial replacement during invocation.

## Qualification

Run `powershell.exe -NoProfile -NonInteractive -File tests/Test-PS51ProcessContracts.ps1`
only where test-file execution is already permitted. Do not relax local policy
or evaluate the script through another route after an execution denial.

The harness hashes/parses the reference, imports only named legacy and candidate
definitions, and compiles its own offline C# probe in a new temporary directory.
It tests helper identity, exit7, unavailable exit, rapid exits, empty argv,
Unicode/spaces/quotes/backslashes, simultaneous streams, direct-child timeout,
and assertion negative controls. It never imports controller main or runs
production tools. Its small owned fixture/evidence directory is retained.

Local execution is **BLOCKED**: Windows PowerShell 5.1 rejected the test file
under its existing execution policy. No policy/security setting changed.
The user authorized a source-only push to existing draft PR234 for qualification
on its existing native Windows runners. Repository push/PR triggers were reviewed:
this change runs source/tests and disposable container CI; production controller
and census workflows are schedule-only and unchanged. Independent source review
is complete. Native Windows CI results remain **UNKNOWN** until collected for
the exact pushed candidate. Local execution remains **BLOCKED**. Full-controller
release admission remains **BLOCKED** on canonical V11 source/admission and its
unbounded-wait gap, regardless of the helper harness outcome.
