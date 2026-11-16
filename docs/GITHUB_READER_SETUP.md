# Read-only organization census access

The scheduled census uses a short-lived GitHub App installation token. An
organization administrator session can configure the workflow but is not a
substitute for the App's private key or accepted installation permissions.
Never copy a broad administrator session credential into an Actions secret to
work around missing setup.

## Separate reader scopes

The `census` job observes inventory, workflow runs, branch protection/rulesets,
and code-scanning, secret-scanning, and Dependabot alerts. Its token explicitly
requests only these read permissions:

- Repository Contents
- Repository Actions
- Repository Administration
- Repository Code scanning alerts (`security-events`)
- Repository Secret scanning alerts
- Repository Dependabot alerts (`vulnerability-alerts`)
- Organization Administration

The separate `file-audit` job requires only Repository Contents/read and
Organization Administration/read. It must not inherit the broader census
token scope. Metadata access is implicit in installation tokens.

The exact input names are defined by the
[pinned token action](https://github.com/actions/create-github-app-token/blob/bcd2ba49218906704ab6c1aa796996da409d3eb1/action.yml).
The separate PyPI audit job requests only Repository Contents/read,
Repository Administration/read, and Organization Administration/read. These
are a subset of the existing census App permissions: file contents establish
private package markers; administration exposes tag ruleset bypass actors;
organization metadata establishes reader inventory coverage. It uses the same
validated reader selection and provider-fixed schedule. Pull requests and manual
audit dispatches receive only the repository token and may retain UNKNOWN
evidence. No new credential or installation permission is granted by this job.

None of these jobs requests write permissions. This reader does not publish, sign a
product release, modify protection, or actuate a runtime.

## Legitimate configuration

1. Select the organization-owned App and its active all-repository installation.
   Ensure the App grants the seven read permissions above and accept any pending
   installation permission update. Preserve unrelated existing attestor grants;
   each census token is narrowed by its explicit request.
2. Set Actions variable `QILLQAQ_CLIENT_ID` to that App's public client identifier.
   A value being present is configuration evidence, not authentication evidence.
3. Configure `QILLQAQ_PRIVATE_KEY` through GitHub's secret interface with a valid
   private key for that same App. Do not paste, print, or commit the key. Do not
   revoke or replace another consumer's existing key merely to configure this
   reader.
4. Observe a fresh provider-scheduled run at the protected source revision.
   Retain its census and file-audit artifacts and verify their subjects, counts,
   source timestamps, and terminal states. The workflow remains schedule-only;
   do not add a dispatch or lower a gate to manufacture completion.

## Evidence boundary

The sanitized census receipt now records one `github_alert_endpoints` observation
for each organization code-scanning, secret-scanning, and Dependabot collection.
`READ_COMPLETE` means the existing bounded paginator returned all observed pages,
including a valid empty list. `UNAVAILABLE` identifies an HTTP 401, 403, or 404;
the receipt does not infer the cause of a restriction. Transport, response,
pagination, rate-limit, and provider failures remain `UNKNOWN`. The HTTP failure
status describes a failed request anywhere in that collection, not necessarily
the initial page. Older snapshots without these observations say `NOT_OBSERVED`.
Only controlled states, completeness, failure status, and fixed reason labels
survive. Alert counts, identifiers, details, and raw provider errors do not.
These diagnostics do not change governance gates or establish permission grants,
organization coverage, absence of security findings, or production readiness.

Even valid App access does not guarantee a passing governance receipt. Real red
CI, missing protection, security alerts, incomplete HF evidence, and failed
runtime controls remain failures or unknowns. A local complete file audit, an
App installation badge, a configured identifier, or green source CI does not
close the hosted census or production-readiness gates.
