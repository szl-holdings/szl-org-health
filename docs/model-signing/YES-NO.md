# D05 yes/no asks for Stephen

Nothing below has been done. An agent's say-so is not approval. A fresh yes has to name the item.

Older quotes (including "get this fully operational", card answers on other items, and "dc in handel it") are context, not a go to sign models or to open this PR.

Standing limits: no email to br@szlholdings.com; no @Carlota-1 mentions, review requests, or assignments; no secrets in chat or files; do not use or rotate tokens (Stephen handles tokens); do not sign, push, merge, deploy, or publish until the matching line is yes.

## Asks

1. **Open a draft PR of this plan and the verify-only workflow, with no merge and no signing?**
   Recommended target: `szl-holdings/szl-org-health` (or another repo you name). Local files: `/workspace/amaru/d05-model-signing-20261126/`.
   - [ ] Yes, open the draft PR on ________ (repo).
   - [ ] No, keep it local.

2. **Pilot-sign one public, already-licensed, small adapter with OpenSSF Model Signing, after the draft PR exists?**
   Recommended subject: `SZLHOLDINGS/SZL-MiniEmbed-0.8B` (public, Apache-2.0, one adapter file, not Khipu, not unlicensed). Alternates: `SZL-Triage-0.8B` or `a11oy-r2`.
   - [ ] Yes, keyless Sigstore (GitHub Actions OIDC). I accept that this writes a public, append-only Rekor log entry naming the signer identity, which cannot be deleted.
   - [ ] Yes, but key-based only (no public Rekor). Create a new key in KMS/HSM first (ask 3). Do not reuse the box-local proofrun key.
   - [ ] No. Do not sign anything yet.

3. **Create a new model-signing key in KMS or HSM (needed for private models, and for ask 2 if you picked key-based)?**
   This is a credential-creation / possible spend item. Not the existing proofrun ed25519 key (OpenSSH fingerprint SHA256:Zh85M3LbIqkGrPzUcRgNyOV2FuqTH4leoDGuhaOvR4Y), which stays in the run-endorsement lane and is only box-local, not HSM-grade.
   - [ ] Yes, use ________ (cloud / HSM product). Budget up to ________.
   - [ ] No. Do not create a key.

4. **After a successful pilot verify, sign the remaining public weight-bearing models that already have a license?**
   That is 45 public licensed weight-bearing repos today (63 public weight-bearing minus 18 with no license). License PRs are a separate item. Do not treat a signature as a quality or "qualified" claim. Do not promote Khipu.
   - [ ] Yes, after the pilot verifies, sign the 45 licensed public weight-bearing models.
   - [ ] No, stop after the pilot.
   - [ ] Yes, but only this list: ________.

5. **Private model repos: key/KMS signing only, never public Sigstore/Rekor?**
   Public Rekor would publish a signing event and can leak that a private model exists.
   - [ ] Yes, private models stay off the public log.
   - [ ] No / discuss first.

6. **Add the verify workflow in report-only mode first, and only make it a required check later, in a separate yes?**
   Do not attach it to the deleted org rulesets, and do not turn on a required check that no repo produces.
   - [ ] Yes, report-only verify first; required-check is a later, separate yes.
   - [ ] No.
