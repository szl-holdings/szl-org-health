# D05 recensus — SZLHOLDINGS model repos

Captured read-only from already-collected inventories, not a new org-wide Hub crawl.

- Inventory: `/workspace/amaru/licenses-2026-11-26/hf_models_inventory.json` (mtime 2026-11-27 02:01 UTC).
- Org census: `/workspace/ayni/oneflet-2026-11-26/step1_census_20261127T020055Z/` observed **2026-11-27T02:00:55Z** (2026-11-26, 9:00 PM America/New_York).
- Row-level file: `evidence/census_rows.json`.
- Pukyu's Nov 19 benchmark (0/91 signature files) is in `/workspace/pukyu/evolve-2026-11-19/REPORT.md`.

## Headline counts (121 model repos)

| Class | Count |
|---|---|
| All model repos | 121 (89 public, 32 private) |
| OMS / sigstore / `model.sig` / in-toto bundle | **0** |
| `holo/holo-manifest-v1-1.json.sig` present | 60 |
| No holo `.sig` | 61 (59 public, 2 private) |
| Weight-bearing (safetensors / GGUF / bin / pt, excluding optimizer / rng / scheduler / training_args) | 82 (63 public, 19 private) |
| Public weight-bearing with holo `.sig` | 30 |
| Public weight-bearing without holo `.sig` | 33 |
| Private weight-bearing with holo `.sig` | 17 |
| Private weight-bearing without holo `.sig` | 2 (`salad-chaski-frontier-9b-op1-r14`, `...-r15`) |
| No weight files | 39 (26 public kernel/pointer stubs with only `RESURRECTION_RECEIPT.json`; 13 private card/progress-only repos) |
| Public and unlicensed | 18, all of them weight-bearing |
| Signed training/eval receipts (`*.signed.json`) | 6 |
| `provenance.json` | 5 |
| CycloneDX `model-bom.cdx.json` | 13 |

Nov 19 had 91 model repos. The org now has 121. The OMS finding is unchanged: still no model-integrity signature file.

## Public weight-bearing, no license (18)

Do not pilot-sign these until the separate license item lands.

- SZLHOLDINGS/SZL-Forge-1.5B-ReceiptAgent
- SZLHOLDINGS/SZL-Khipu-1.5B
- SZLHOLDINGS/brain-navigator-r2
- SZLHOLDINGS/KHIPU-R2
- SZLHOLDINGS/WILLAY
- SZLHOLDINGS/chakana-r1-candidate
- SZLHOLDINGS/KHIPU-R2-estate-sft-v1
- SZLHOLDINGS/Nemotron-Mini-4B-Instruct-st
- SZLHOLDINGS/szl1-experimental-estate-sft-v1
- SZLHOLDINGS/szl1-experimental-massed-20261104
- SZLHOLDINGS/SZL-Forge-1.5B-ReceiptAgent-estate-sft-v1
- SZLHOLDINGS/SZL-Khipu-1.5B-estate-sft-v1
- SZLHOLDINGS/SZL-Khipu-1.5B-sft-v2
- SZLHOLDINGS/SZL-Nemotron-Mini-4B-Doctrine-v1
- SZLHOLDINGS/SZL-Nemotron-Mini-4B-Estate-DPO-v1
- SZLHOLDINGS/SZL-Nemotron-Mini-4B-Estate-DPO-v2
- SZLHOLDINGS/SZL-Nemotron-Mini-4B-Estate-v1
- SZLHOLDINGS/WILLAY-estate-sft-v1

## Suggested public licensed pilots (small, one adapter, Apache-2.0, no holo `.sig` required)

Preferred: `SZLHOLDINGS/SZL-MiniEmbed-0.8B`. Alternates: `SZL-Triage-0.8B`, `a11oy-r2` (and the other r2 verticals). Avoid Khipu, avoid `salad-flagship54-v2` (110 weight files), avoid unlicensed repos.
