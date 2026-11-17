# Scheduled census: dedicated Hugging Face reader

## Credential boundary

The scheduled estate census uses exactly one Hugging Face credential:
`HF_CENSUS_READ_TOKEN`, stored as a GitHub Actions repository secret for
`szl-holdings/szl-org-health`. The workflow passes it as `HF_TOKEN` **only
to the census collection step**. The receipt step gets only the Boolean
`HAS_HF_TOKEN` and does not receive the credential.

Do not point this name at a publisher token, a legacy `write` token, or any
token previously pasted in a chat, deployment specification, or workflow log.
The previous alias chain is intentionally not used as a fallback.

## Provision and admit

1. In Hugging Face account settings, create a **fine-grained** user access
   token with read access to the required `SZLHOLDINGS` organization
   repositories (models, datasets, Spaces and other inventories in the census
   policy). Explicitly confirm that resource groups and organization token
   policies permit the intended read coverage. Do not grant write.
2. Add its value directly to the GitHub Actions repository secret named
   `HF_CENSUS_READ_TOKEN`. Never put the value in an issue, PR, Mistral prompt,
   runner output, or environment file in source control.
3. Observe a new **scheduled** run on protected `main`; retain the sanitized
   census receipt. The workflow is deliberately schedule-only. Do not enable
   a manual or PR-triggered privileged authority just to obtain green CI.
4. Require the collector to report fine-grained authentication with
   organization membership/read authority, accepted inventory completeness,
   and no global write permissions; require the independent receipt to
   return `PASS`. Missing or incomplete provider evidence must remain
   `FAIL_CLOSED`.
5. Confirm the minimum GitHub organization scope and all governance controls
   separately; a good Hugging Face token cannot excuse failed GitHub, DNS,
   rights, or source-integrity controls.
6. Only after positive readback, retire the old broad aliases from this
   repository and rotate any credential exposed in prior workflow/container
   configurations. **Do not revoke publisher credentials used by other
   production workflows without inventorying their consumers first.**

## Why an alias-only PR is not a production-ready census

This PR removes the accidental preference for broad write-capable credentials.
It does **not** create a credential, establish organization-complete inventory,
modify the producer or relax the receipt requirements. Until the dedicated
secret is installed and a current scheduled run is admitted, the census
remains operationally `BLOCKED`. Keep the deadman incident open.

## References

- Hugging Face user access tokens and fine-grained production practice:
  https://huggingface.co/docs/hub/security-tokens
- SZL census failure state:
  https://github.com/szl-holdings/szl-org-health/issues/39
- Scheduled workflow:
  `.github/workflows/scheduled-estate-census.yml`
