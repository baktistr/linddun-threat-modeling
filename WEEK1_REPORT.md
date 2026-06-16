# Week 1 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — Grounded LINDDUN Pro
**Week:** 1
**Author:** Bakti Satria Adhityatama

## Goal for Week 1

Per the project proposal: stand up the RAG knowledge base, ingest the LINDDUN methodology and supporting reference material, confirm the KidsTube manual analysis as the gold standard, and lock outstanding decisions with the advisor.

## Completed

**Knowledge base curated and structured.** The LINDDUN Pro methodology is now machine-readable, not just a PDF:
- All seven threat types and their threat-tree nodes encoded as structured JSON (`threat_trees.json`), so each node is independently retrievable.
- The LINDDUN Pro mapping table (Table 4.1) encoded as JSON (`mapping_table.json`), capturing which threat types apply at source/flow/destination for each valid DFD interaction, plus the invalid interactions.
- Threat-type definitions and the S/fl/D elicitation methodology as clean Markdown.
- COPPA (16 CFR Part 312), GDPR (EU 2016/679), and CCPA provisions most relevant to privacy threat modeling, each summarized and mapped to the LINDDUN threat types it supports — this is what will let generated threats carry regulatory citations.

**Gold standard encoded.** The 30-threat KidsTube catalog from HW2 is now structured JSON (`gold_standard_threats.json`) with per-threat id, interaction, originator, tree node, type, description, assumptions, severity, and likelihood. Integrity-checked: 30 threats, contiguous ids, all seven LINDDUN types represented (Dd 11, L 5, I 4, U 4, Nc 3, Nr 2, D 1). This is the evaluation ground truth for every later week.

**RAG pipeline working.** Ingestion → embedding → hybrid retrieval, with a persisted index:
- 118 retrievable chunks across the three corpora (LINDDUN 65, regulations 15, scenarios 38).
- Hybrid retrieval (dense cosine + keyword overlap) so exact node IDs and regulation numbers surface reliably.
- Pluggable embedding backend; ships dependency-light (TF-IDF) and upgrades to semantic embeddings via one env var.
- CLI (`build` / `search` / `stats` / `ask`) and a 21-check test suite, all passing.

**Bridge to Week 2 built.** `interaction_context.py` takes a DFD interaction and returns the applicable threat types, positions, and tree nodes — the exact context the Week-2 threat-generation prompt will consume.

## Decisions still pending with advisor

These were flagged in the proposal as Week-1 items and are not yet resolved:

1. **Target paper/workshop venue** — sets the evidence bar and deadline.
2. **Additional evaluation scenarios (2–3)** beyond KidsTube — source TBD (published LINDDUN examples, releasable student work, or OSS apps).
3. **IP / publication scope** — can the webapp be open-sourced and the threat catalogs released as a benchmark?
4. **API budget confirmation** — estimate ~$200–$500.
5. **Partner coordination** — division of labor and shared canonical-DFD schema with the RAG-MCP-system repo, so the shared repo isn't pulled in two directions.

## Note on the LINDDUN threat trees

The v0.1 tutorial prints full trees only for Linking, Data Disclosure, and Detecting; the other four types are given as type definitions. The encoded `threat_trees.json` reflects this — fully detailed nodes for L/Dd/D, and approximated top-level nodes for I/Nr/U/Nc (flagged in `_note` fields). Before evaluation, these should be replaced with the official complete trees from the LINDDUN website. This is a one-session transcription task for Week 2.

## Plan for Week 2

Wire the grounded threat-generation pipeline: retrieval → per-category prompt construction → Claude generation, emitting the structured JSON threat schema. First end-to-end test feeds KidsTube DFD interactions through the pipeline and compares the output against the gold standard. Refine retrieval based on what that first comparison reveals.
