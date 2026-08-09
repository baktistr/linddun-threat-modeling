# Response to abstract reviews (submission 38) — 2026-08-07

Reviewer 1 raised no concerns. Reviewer 2 raised five, all valid; every number the revision adds
was measured against the official LINDDUN v241203 trees and is reproducible from this repo.

## Point-by-point

**R2.1 — "No quantitative results; report the magnitude of the citation-reliability improvement."**
Added to the abstract: grounded citation validity **1.00** on all three LINDDUN scenarios vs
**0.84–0.86** (RAG) and **0.79–0.86** (ungrounded) — the improvement is +0.14–0.21, closed to
exactly 1.00. Also added: 1.00 in 13 of 15 model × input conditions (exceptions 0.99/0.97, single
fabricated identifiers caught by the verifier); recall/F1 explicitly *not* improved by grounding;
robustness numbers (0.76 → 0.56 recall under source-derived DFDs with validity unchanged); and
grounded precision 0.19–0.40 labeled as the lower bound it is.
*Sources: `storage/regen_last.json`, `RESULTS_2026-07-28.md`, `RESULTS_2026-07-31.md`.*

**R2.2 — "Distinguish implemented / evaluated / partially evaluated / planned."**
The abstract no longer claims six scenarios (four exist; two are now explicitly planned), no
longer frames genomic as a held-out LINDDUN test (it is evaluated under MITRE PANOPTIC, and is
now presented as exactly that, with numbers), and gathers every planned item into one clearly
labeled closing sentence ("Clearly planned, and not presented as evidence: …"). The full
classification is the table below, intended for the final paper.

**R2.3 — "Do not rely on a single generation; report variability."**
The abstract now states n per condition and the *measured* variability: ~0.05 recall across
repeated generations of the same condition (three independent measurements), and 107–115 flows
across five repeated source derivations (`RESULTS_2026-08-07.md`), with the explicit rule that
orderings inside the noise band are not interpreted. Multi-run (n=3) repetition of the headline
conditions is planned before the final paper.

**R2.4 — "Which LLMs, prompts, parameters?"**
Named in the abstract: gpt-5.4, gpt-4o-mini, grok-4.3, one Azure AI Foundry endpoint, structured
output enforced via tool calls, one generation call per DFD flow. Added the finding that makes
this material: model choice moves recall by up to 0.22 while input modality costs at most 0.08 —
model selection matters ~4× more than input form. Full prompts, token budgets, and generation
parameters are in the repository and will be documented in the final paper.

**R2.5 — "Justify RAG when an exact mapping table exists — deterministic lookup may be better."**
The reviewer's intuition is our thesis, and the abstract now says so directly: deterministic
lookup *is* the proposed mechanism. The RAG condition exists (a) as a controlled ablation
reproducing retrieval-based prior work [2] inside our pipeline, so the comparison is internal
rather than cross-system, and (b) as the fallback for methodologies without a mapping table. The
ablation's result — RAG loses 0.14–0.16 citation validity against deterministic grounding — is
the empirical confirmation of exactly the concern the reviewer raises.

## Status classification (for the final paper, per R2.2)

| Status | Items |
|---|---|
| **Implemented and evaluated** | Post-generation citation verifier; grounded/RAG/ungrounded ablation on 3 LINDDUN scenarios; official v241203 threat trees (65 nodes); three input adapters (hand DFD, source code — `facts_only`/`llm`/`llm_naive` arms, DFD image — `vision_naive` arm); 3-model × 3-input sweep; threats-on-derived-DFD comparison; PILLAR export scored by our matcher; our pipeline run on PILLAR's own diagram exports |
| **Partially evaluated** | Genomic under PANOPTIC (exact-identifier tier only; category tier pending); Family Location and Smart Home (evaluated, gold standards await independent review); source-arm P/R/F1 (evaluation attrition: only 13–23 of 41 gold threats re-anchor) |
| **Planned validation** | Manual FP adjudication (worklist built, unlabelled → no human-corrected precision exists yet); n=3 repetition of headline conditions; matched-conditions PILLAR run (same model, same DFD) |
| **Planned future work** | School-grades and wearable-health scenarios; auto-updating knowledge base; category-level PANOPTIC tier; OCR verification of image-region citations (motivated by the silent-correction failure mode, `RESULTS_2026-07-31.md`) |

## Numbers used in the revised abstract, with provenance

| Claim | Value | Source |
|---|---|---|
| Grounded citation validity, 3 scenarios | 1.00 / 1.00 / 1.00 | `storage/regen_last.json` |
| RAG citation validity | 0.84–0.86 | same |
| Ungrounded citation validity | 0.79–0.86 | same |
| Model × input conditions at 1.00 | 13 of 15 (0.99, 0.97 exceptions) | `RESULTS_2026-07-28.md` §4, `RESULTS_2026-07-31.md` §5 |
| RAG F1 ≥ grounded F1 | all 3 scenarios (0.42/0.41/0.37 vs 0.37/0.40/0.32) | `storage/regen_last.json` |
| Source-derived recall cost | 0.76 → 0.56 (reachability-adjusted), validity 1.00 | `kidstube_derived_grounded_eval.txt` |
| Image-input recall tax | ≤ 0.08 | `RESULTS_2026-07-28.md` §2 |
| Model spread (recall, same input) | up to 0.22 (0.56–0.78) | same, §1 |
| Run-to-run variance | ~0.05 recall; 107–115 flows over 5 derivations | §7 + `RESULTS_2026-08-07.md` |
| Grounded precision range | 0.19–0.40 | regen + sweep tables |
| PILLAR node ids resolving | 0.82 (0.18 prose/empty), unverified | `knowledge_base/PILLAR/scored_vs_kidstube_gold.txt` (re-scored vs official trees) |
| PANOPTIC genomic F1 | 0.08–0.19 (exact sub-activity matching) | `RESULTS_2026-07-21.md` §4 |
