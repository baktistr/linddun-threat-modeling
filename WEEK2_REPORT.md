# Week 2 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — Grounded LINDDUN Pro
**Week:** 2
**Author:** Bakti Satria Adhityatama

## Goal for Week 2

Two carry-overs from Week 1 had to land before the threat-generation pipeline could be trusted: (1) complete the LINDDUN threat trees — Week 1 only had full trees for L/Dd/D and approximated the other four types; and (2) resolve the pending "additional evaluation scenarios" decision by adding at least one more gold standard beyond KidsTube. The week also hardened the KidsTube gold standard itself. In short: strengthen the evaluation foundation before wiring generation against it.

## Completed

**LINDDUN threat trees completed to all seven types.** The trees that Week 1 left approximated (I, Nr, U, Nc) are now fully encoded, and every sub-node ID was audited against the official LINDDUN semantics. `threat_trees.json` now exposes 7 type definitions and 51 individually-retrievable tree nodes, so grounded elicitation can cite a precise node for any of the seven types — not just three.

**KidsTube gold standard hardened (30 → 36 threats).** Six threats from a second HW2 analysis (Bilal) were merged in to close coverage gaps in the primary catalog: broken object-level authorization (BOLA), insecure password hashing, inference of sensitive child attributes from watch patterns, AB 2273 (AADC) privacy-by-default, CCPA/CPRA published-policy + DSAR, and a missing registration-time privacy notice. Separately, **8 LINDDUN sub-node IDs were audited and corrected** and 3 threats flagged borderline; corrected threats carry `original_hw2_node` + `mapping_note`, merged threats carry `source: "bilal_hw2"`. Still all seven types (Dd 13, Nc 6, L 5, I 4, U 4, D 2, Nr 2).

**Second evaluation scenario added — Genomic Sequencing (NIST SP 1800-43C).** This resolves pending decision #2 with an *authoritative* source: NIST runs its own LINDDUN + PANOPTIC analysis and validates every threat against the NIST Privacy Engineering Objectives. The gold standard is the **complete example — 99 itemized threats across all seven LINDDUN types** (U 32, L 17, I 14, Nr 10, Dd 9, Nc 9, D 8); the 10 threats of the smaller *core example* are tagged `in_core_example`. Each threat keeps NIST's native fields (`scenario_id`, `panoptic_actions`, `feasibility`, `difficulty`, `ranking_value`, `impacted_peos`) plus `nist_node` (verbatim) alongside `tree_node` (mapped to this repo's tree).

**Obtaining the complete example was non-trivial — documented for the record.** NIST publishes the complete analysis only as raster figures in external HTML appendices; no machine-readable table exists anywhere (not even in the source `.rst`). The 99 threats were therefore transcribed by vision-reading Appendix G Figures 20 (validations) and 24 (ranked threats), which were transcribed independently and cross-checked for agreement on node/scenario/feasibility/difficulty. The raw transcription is committed (`scripts/data/genomic_complete_raw.json`) and the gold JSON is regenerated from it by `scripts/build_genomic_gold.py`.

**Source materials bundled for provenance.** The NIST report PDF plus all appendix figures and `.rst` sources are committed under `references/nist-sp-1800-43c/` (outside the ingestion path, so not chunked) as the audit trail behind the genomic gold standard.

**Genomic gold standard verified against the source.** Because the genomic threats are OCR of a draft figure, `scripts/verify_genomic.py` cross-checks every row two ways: against an *independent* transcription of Figure 24, and against NIST's own ranking formula (`ranking = combination_value(feasibility, difficulty) × type_weight`, Tables 18/19). The first pass found and we corrected three real transcription errors (rows #23/#24 had swapped feasibility; #27's description was recovered from the source). Current state: **all 99 rows formula-consistent, 97/99 corroborated by both figures** — the 2 remainder are node-only differences between transcriptions, with only #24's node not yet independently re-confirmed. The check is wired into the test suite so the file can't silently drift.

**RAG pipeline scaled and green.** The corpus grew from 118 to **252 retrievable chunks** (linddun 79, scenarios 158, regulations 15; including 135 gold-threat chunks and 51 tree-node chunks). The test suite expanded to **33 checks** — adding genomic file-existence, integrity (99 threats / 7 types / core-example tagging / node resolution), source-accuracy cross-check, and retrieval — all passing.

## Open items / caveats

1. **Genomic rows are OCR of a DRAFT figure.** Despite the cross-checks above, per-threat details remain transcription-confidence rather than authoritative; high-stakes use should spot-check against the bundled figures. One cell is still unconfirmed: #24's node (`I.1.2`; evidence favors it).
2. **LINDDUN tree-version gap.** NIST uses a deeper/newer LINDDUN revision than this repo's tree (e.g. `I.2.3`, `U.2.2/2.3`, `Nr.2`, `Nc.2/Nc.4`). Those nodes were mapped to the nearest ancestor in our tree, preserving the verbatim NIST node. A follow-up could instead extend the canonical `threat_trees.json` with the missing official nodes.

## Still pending with advisor (carried from Week 1)

Target paper/workshop venue; IP / publication scope (open-sourcing the catalogs as a benchmark); API budget confirmation (~$200–$500); partner coordination on the shared canonical-DFD schema with the RAG-MCP-system repo. (Pending decision #2, additional evaluation scenarios, is now partially resolved — one authoritative second scenario added; more can follow.)

## Plan for Week 3

Wire the grounded threat-generation pipeline: retrieval → per-category prompt construction → Claude generation → structured JSON output, then compare against the gold standard — now across **two** scenarios (KidsTube and Genomic). The genomic scenario's native ranking/feasibility/PEO fields also open up a richer evaluation than presence/absence alone. Refine retrieval based on what the first comparison reveals.
