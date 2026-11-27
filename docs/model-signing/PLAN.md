# D05 — Model signing plan (OMS / sigstore)

Status: **local only**. Written 2026-11-26, 9:22 PM America/New_York. Nothing was signed, pushed, merged, uploaded, or published. No keys were created. No tokens were touched.

Owner: Amaru (SEC-PROVENANCE-SIGNING). Source assignment: Pukyu D05, `/workspace/pukyu/delegation-20261126/PLAN.md`. Yes/no asks: [YES-NO.md](YES-NO.md). Counts: [census.md](census.md).

**Update, 2026-11-26 10:05 PM America/New_York:** Stephen approved opening this plan and the verify-only workflow as a draft PR on `szl-holdings/szl-org-health`, and pilot-signing `SZLHOLDINGS/SZL-MiniEmbed-0.8B` via public Sigstore (GitHub Actions OIDC). No other model. The proofrun key is not used. The sign job lives in `.github/workflows/model-sign-pilot-miniembed.yml` and only runs on branch `amaru/d05-model-signing-20261126`.

## 1. Verdict

Pukyu's Nov 19 benchmark, "0/91 model repos with a signature file," is still true for **model integrity signing**.

A recensus of the 121 SZLHOLDINGS model repos in the 2026-11-26 9:00 PM ET inventory found:

- **0 / 121** with an OpenSSF Model Signing (OMS) / `model-signing` artifact (`model.sig`, Sigstore bundle, or in-toto/DSSE equivalent).
- **60 / 121** with `holo/holo-manifest-v1-1.json.sig`. Those appeared around 2026-11-25. They are SSH signatures over a holographic **card** manifest. They are not OMS, and they do not bind weight bytes.

So the estate still has no verifiable signature over model file digests. Existing "signed" files must not be described as model signing.

## 2. What the holo `.sig` files actually are

Sampled manifests (public, saved under `evidence/holo-manifests-public-samples/`):

| Repo | Artifacts in the manifest | Digests? | Weight filename listed? |
|---|---|---|---|
| `SZLHOLDINGS/szl-receiptagent-qwen35-0.8b-v3` (local copy of the Hub tree) | 12 names | No | No (`adapter_model.safetensors` omitted) |
| `SZLHOLDINGS/a11oy-r1` | 8 names | No | No |
| `SZLHOLDINGS/willay-r1` | 17 names | No | No (adapter weights live under `adapter-unsloth/` and are not listed) |
| `SZLHOLDINGS/SZL-Acoustic-Governance-1.7B` | 16 names | No | Yes, as a bare name: `adapter_model.safetensors` |

Every sampled manifest is the same schema (`szl-holo-card/v1.1`): a list of **path strings**, plus `head`, `model`, `renderer`, `generated_utc`. There is no sha256 (or any other) digest.

The matching `.sig` on the local v3 tree is a valid OpenSSH `SSHSIG` (`ssh-keygen -Y verify` returned "Good file signature") using:

- algorithm: ed25519
- namespace: `file`
- hash: sha512
- key fingerprint: `SHA256:bsO6I7d2U8Gsfh1yAo6e5xzUeOv0iAVtPkbnzfVlQyU`

That key is **not** the proofrun org key (`SHA256:Zh85M3LbIqkGrPzUcRgNyOV2FuqTH4leoDGuhaOvR4Y`).

A signature over a filename list without hashes does not protect the model. Anyone who can replace `adapter_model.safetensors` (or omit it from the list) leaves a still-valid card signature. Treat holo `.sig` as card-render provenance only.

Other nearby artifacts, also not OMS:

- `*.signed.json` training/eval/publication receipts on 6 repos — claim receipts, not weight-file signatures.
- `provenance.json` (5) and `bom/model-bom.cdx.json` (13) — useful inventories, not signatures.
- Proofrun endorsements (flagship54-v2 and the gpu-bridge fingerprint draft PR) — run/receipt lane, different subject, different key, still unpublished for outsiders.
- 26 public "models" that only contain `README.md` + `RESURRECTION_RECEIPT.json` (for example `szl-govsign`) — kernel pointers, not loadable models. Do not sign them as models.

## 3. Recommended design

Follow Pukyu's deferred E5 plan, tightened for SZL's constraints.

### Format

Use the OpenSSF Model Signing (OMS) format, via the reference CLI `model-signing` ([sigstore/model-transparency](https://github.com/sigstore/model-transparency)). A sign produces a detached Sigstore bundle (default `model.sig`) whose payload is a DSSE envelope around an in-toto statement. The statement lists `(path, digest)` pairs for the model files, with predicate type `https://model_signing/signature/v1.0`.

Verify recomputes those digests and checks the signature. That is the property holo `.sig` does not provide.

Install and read-only digest (no approval needed; not run as part of this write-up):

```bash
pip install model-signing
model_signing digest /path/to/model-dir
```

### Two signing tracks

**Track A — public models, keyless Sigstore (recommended for the pilot if Stephen accepts the log).**
GitHub Actions OIDC in a dedicated, reviewed workflow. Identity is the workflow identity (for example `https://github.com/szl-holdings/<repo>/.github/workflows/model-sign.yml@refs/tags/...`), issuer `https://token.actions.githubusercontent.com`. Fulcio issues a short-lived cert; Rekor records the event.

Cost: the Rekor entry is **public and append-only**. It names the signer identity and cannot be deleted. That is why this needs an explicit yes (Pukyu E5 already flagged it).

**Track B — private models, and any public model if Stephen rejects the public log.**
`model_signing sign key` or `certificate` / PKCS#11, with the private key in a KMS or HSM, not on the shared box, not on BETTERWITHAGE, and not the existing proofrun key. Publish only the public key or cert fingerprint. Optional later: a private Rekor/Fulcio (`--trust-config`), not the public log.

Do **not** send private model names or paths through public Sigstore.

### Key custody rules

- Do not reuse the box-local proofrun ed25519 key. It is for run endorsement, its custody is "box-local, not HSM-grade" (shared Unix user across agents), and its fingerprint is already in the gpu-bridge draft PR for a different purpose.
- Do not generate a long-lived model-signing key as a plaintext file on the box or the laptop.
- Creating a KMS/HSM key is credential creation and needs Stephen's yes (ask 3).
- Stephen handles token rotation; this plan does not request or load tokens.

### What a signature claims — and does not claim

A valid OMS signature means: these bytes, on these paths, were signed by this identity, and have not been altered since. It does **not** mean the run is qualified, the eval passed, the license is correct, or the model may be promoted.

Keep that distinction in the card text and in any annotations. Quality stays with proofrun / receipts / held-out eval. Khipu stays unpromoted while its restricted abstention condition is unresolved. Signing Khipu, if ever approved, must still say "integrity only, not qualified."

### CI verify

Add a reusable, **verify-only** workflow first (draft in `drafts/model-verify.yml`):

- Checkout or download a pinned model snapshot.
- Run `model_signing verify` (keyless or `--key`, matching how it was signed).
- Start in **report-only** mode: missing `model.sig` is a warning, not a blocker. After enough repos are actually signed, a separate yes can make verify required on those repos only.
- Pin `model-signing` and any Actions by commit SHA before merge.
- Do not attach this to the org rulesets that were deleted on Nov 22, and do not enable a required check that no workflow produces.

A sign job is deliberately absent from the draft workflow.

### Ignore rules when signing

Sign the published model payload, not the git directory: exclude `.git/`, card-only artwork if desired, trainer optimizer/rng/scheduler blobs, and any secret-bearing path. Always include weight files (`.safetensors`, `.gguf`, published `.bin`), tokenizer and config, and the model card / license. Document the ignore set in the PR so verify uses the same rules.

## 4. Phases

| Phase | What | Needs Stephen? | Status |
|---|---|---|---|
| 0 | Recensus + this plan, local | No (read-only / local prep) | Done, 2026-11-26 9:22 PM ET |
| 1 | Draft PR: plan + verify-only workflow, no merge | Yes, ask 1 | Prepared under `drafts/` |
| 2 | Pilot OMS sign of one named public licensed adapter; upload `model.sig` via HF or Git PR; verify | Yes, ask 2 (and 3 if key-based) | Not started |
| 3 | Sign remaining public **licensed** weight-bearing models (45 today). License the other 18 first (separate Amaru item) | Yes, ask 4 | Not started |
| 4 | Private models, track B only | Yes, ask 5 | Not started |
| 5 | Required verify on signed repos only | Separate later yes, ask 6 | Not started |

26 public kernel-pointer stubs are out of scope for model signing. If those kernels should be signed, that is a kernel-release lane (`szl-govsign` already has a publish workflow), not this one.

## 5. Risks and rollback

- **Public Rekor (track A):** no rollback for the log entry. Only stop future signing and/or rotate the OIDC identity. Say this plainly before the pilot.
- **Key-based (track B):** rollback is "delete or replace `model.sig` on the repo" plus a published revocation/fingerprint change. The old signature still verifies against the old public key until verifiers are told to stop trusting it.
- **Mistaking holo `.sig` for model signing:** communication risk. This plan should travel with the PR so we do not claim 60 models are already signed.
- **Signing unlicensed or unqualified models:** looks like an endorsement. Phase 3 waits on licenses; signatures never upgrade quality claims.
- **Org rulesets:** required-review and ci-gate were deleted on Nov 22. Restoring them is a separate item. Do not use model-verify as a hidden org-wide gate.

## 6. Coordination

- **Pukyu:** E5 is now a concrete plan; still not run. Recensus updated 0/91 → 0/121 OMS, plus 60 non-OMS holo signatures.
- **Ayni / license item:** 18 public unlicensed weight-bearing models stay out of phase 3 until license PRs merge.
- **Rikuy / proofrun:** complementary, not a substitute. Run endorsement stays in the proofrun lane.
- **Kamay / Chakana:** CI pin-by-SHA and "no required check without a producer" still apply.
- **Carlota-1 / br@:** no contact, no review request, no assignment.

## 7. What I did not do

I did not sign any model, create a key, open a PR, upload to Hugging Face, change GitHub settings, or run `model_signing sign`. I did not do a new org-wide Hub crawl; counts are from the 9:00 PM ET inventories plus four public manifest fetches and one local SSH-signature verify.
