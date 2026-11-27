# OMS model signing (SZL)

Plan and a reusable **verify-only** GitHub Actions workflow for OpenSSF Model Signing (`model-signing` 1.1.1).

Stephen approved (2026-11-26, 10:05 PM America/New_York) opening this as a draft PR and pilot-signing `SZLHOLDINGS/SZL-MiniEmbed-0.8B` via public Sigstore / GitHub Actions OIDC. No other model is in scope. The proofrun key is not used.

- [PLAN.md](PLAN.md) — recensus, why holo `.sig` files are not model signing, recommended design.
- [census.md](census.md) — 0/121 OMS signatures as of 2026-11-26, 9:00 PM ET.
- [YES-NO.md](YES-NO.md) — the asks that this PR and the MiniEmbed pilot answer.
- Verify workflow: `.github/workflows/model-verify.yml` (reusable, does not sign).
- One-shot pilot: `.github/workflows/model-sign-pilot-miniembed.yml` (this branch only).

A valid OMS signature means the listed file digests were signed by the stated identity. It is not a quality, license, or “qualified” claim.
