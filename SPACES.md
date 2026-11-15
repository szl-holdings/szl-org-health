# SPACES.md - Space-to-Repository Binding Registry

Canonical binding table for every Hugging Face Space in the SZLHOLDINGS org, generated from a live measured audit on 2026-11-15. Match types: exact (same name), alias-norm, alias-token (token-overlap >= 0.5), unbound (no source repo found).

Manual-alias candidates to verify before creating new repos: szl-receipts-chain <- receipt-chain-live; szl-energy-hologram <- energy-attest-holo.

| Space | Visibility | SDK | Stage | Source repo | Match |
|---|---|---|---|---|---|
| README | public | static | RUNNING | - | unbound |
| a11oy | public | docker | RUNNING | a11oy | exact |
| a11oy-factory | private | docker | SLEEPING | a11oy-factory | exact |
| agents-studio | private | docker | RUNNING | agents-studio | exact |
| anatomy | public | docker | RUNNING | anatomy | exact |
| ayllu | public | docker | RUNNING | ayllu | exact |
| counsel | public | docker | RUNNING | counsel | exact |
| counsel-assurance | private | docker | RUNNING | counsel | alias-token |
| curation-atlas | public | docker | RUNNING | curation-atlas | exact |
| david-leads | public | docker | RUNNING | david-leads | exact |
| estate-gardener | private | docker | RUNNING | szl-estate-os | alias-token |
| eternal-auditor | private | docker | RUNNING | - | unbound |
| finance | public | docker | RUNNING | - | unbound |
| foundation-confirmation-v2 | private | static | RUNNING | - | unbound |
| frontier-showcase | private | docker | RUNNING | szl-frontier | alias-token |
| gdw-frontier | private | docker | RUNNING | gdw-frontier | exact |
| governed-agent-bench | private | gradio | SLEEPING | - | unbound |
| governed-receipt-verifier | private | static | RUNNING | governed-receipt-spec | alias-token |
| holographic-unify | private | docker | RUNNING | holographic-unify | exact |
| immune | public | docker | RUNNING | immune | exact |
| immune-lattice | private | docker | SLEEPING | immune-lattice | exact |
| khipu-hologram | public | static | RUNNING | szl-khipu | alias-token |
| khipu-playground | private | docker | RUNNING | szl-khipu | alias-token |
| killinchu | public | docker | RUNNING | killinchu | exact |
| living-anatomy | private | docker | RUNNING | anatomy | alias-token |
| llm-router-live | public | docker | RUNNING | szl-router | alias-token |
| lyte | public | docker | RUNNING | lyte-services | alias-token |
| measured-honesty-census | private | docker | RUNNING | - | unbound |
| newton-trust-upgrade | private | docker | RUNNING | - | unbound |
| nexus | private | docker | RUNNING | nexus | exact |
| oac-system-health-lab | private | docker | RUNNING | - | unbound |
| prove-it | private | static | RUNNING | - | unbound |
| puriq-markets | private | docker | RUNNING | puriq-live | alias-token |
| sentra | private | docker | RUNNING | - | unbound |
| szl-atelier | private | docker | SLEEPING | szl-atelier | exact |
| szl-bench-suite | public | static | RUNNING | - | unbound |
| szl-brand-campaign | private | static | RUNNING | szl-brand | alias-token |
| szl-chief-engineer | private | docker | RUNNING | - | unbound |
| szl-command-lab | public | docker | RUNNING | szl-command-lab | exact |
| szl-constellation | private | gradio | RUNNING | szl-constellation | exact |
| szl-constellation-staging | private | gradio | SLEEPING | szl-constellation | alias-token |
| szl-cyber-shield | private | docker | RUNNING | - | unbound |
| szl-dream-architect | private | docker | RUNNING | - | unbound |
| szl-energy-hologram | private | docker | RUNNING | - | unbound |
| szl-energy-ledger | public | static | RUNNING | - | unbound |
| szl-forge-lab | public | static | RUNNING | szl-forge | alias-token |
| szl-foundation-confirmation | public | docker | RUNNING | - | unbound |
| szl-frontier | public | docker | RUNNING | szl-frontier | exact |
| szl-frontier-deck | private | docker | RUNNING | szl-frontier | alias-token |
| szl-infra-warden | private | docker | RUNNING | - | unbound |
| szl-khipu | private | docker | RUNNING | szl-khipu | exact |
| szl-marketing | public | static | RUNNING | - | unbound |
| szl-marketing-1-1 | private | gradio | RUNNING | - | unbound |
| szl-model-inference-lab | public | docker | RUNNING | - | unbound |
| szl-receipts-chain | private | docker | RUNNING | - | unbound |
| szl-research-council | private | docker | RUNNING | - | unbound |
| szl-router-control | private | docker | RUNNING | szl-router | alias-token |
| szl-safe-stack | private | static | RUNNING | szl-safe-stack | exact |
| szl-second-brain | private | docker | RUNNING | szl-second-brain | exact |
| szl-seismic-review | private | docker | SLEEPING | szl-seismic-review | exact |
| szl-typesafe-triage | private | docker | SLEEPING | szl-typesafe-triage | exact |
| szlholdings-si | private | docker | RUNNING | - | unbound |
| terra | public | docker | RUNNING | - | unbound |
| terra-assurance | private | docker | RUNNING | - | unbound |
| the-grid | private | docker | RUNNING | the-grid | exact |
| truth-router | private | docker | RUNNING | szl-router | alias-token |
| vertical-services | public | docker | RUNNING | vertical-services | exact |
| yarqa | private | docker | RUNNING | yarqa | exact |

Doctrine: each Space is hard-coded in the GitHub org (owner directive 2026-11-15). Unbound Spaces are tracked for binding; a metric appears only with a receipt.