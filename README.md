# LINDDUN Knowledge Base

RAG knowledge base for AI-assisted LINDDUN Pro privacy threat modeling: the curated, chunked, and retrievable knowledge that every stage (DFD synthesis, threat elicitation, regulatory mapping) draws on.

> The retrieval engine is intentionally minimal and dependency-light; it can later be swapped for / merged with a shared `RAG-MCP-system` backend (Qdrant + hybrid + reranker). The knowledge base content (LINDDUN trees, mapping table, regulations, and the KidsTube + genomic gold standards) is the durable asset and is backend-agnostic.

**Progress reports:** [Week 1](WEEK1_REPORT.md) · [Week 2](WEEK2_REPORT.md)
**Background & related work:** [REFERENCES.md](REFERENCES.md)

## What's in the knowledge base

| Path | Contents | Why it matters |
|------|----------|----------------|
| `knowledge_base/linddun/threat_trees.json` | All 7 LINDDUN threat types + tree nodes (structured) | Each node is independently retrievable for grounded elicitation |
| `knowledge_base/linddun/mapping_table.json` | LINDDUN Pro Table 4.1 — which types apply at S/fl/D per interaction | Drives which threats to check for each DFD interaction |
| `knowledge_base/linddun/threat_types_and_methodology.md` | Type definitions + S/fl/D interpretation + iteration strategy | Prose context for the model |
| `knowledge_base/regulations/regulations.md` | COPPA, GDPR, CCPA provisions mapped to LINDDUN types | Enables regulatory citation on threats |
| `knowledge_base/scenarios/kidstube/system_description.md` | KidsTube DFD, assets, flows | Primary evaluation scenario |
| `knowledge_base/scenarios/kidstube/gold_standard_threats.json` | **36-threat gold standard** | Ground truth for all evaluation |
| `knowledge_base/scenarios/genomic/system_description.md` | Genomic sequencing DFD, assets, flows | Second evaluation scenario |
| `knowledge_base/scenarios/genomic/gold_standard_threats.json` | **99-threat gold standard** (NIST complete example; 10 tagged as the core-example subset) | Authoritative ground truth — NIST's own LINDDUN analysis, transcribed from Appendix G figures |

Sources: LINDDUN Pro Tutorial v0.1 (KU Leuven, downloads.linddun.org); eCFR Title 16 Part 312; GDPR (EU 2016/679); CCPA (Cal. Civ. Code §1798.100+); NIST SP 1800-43C DRAFT, *Genomic Data Threat Modeling: Privacy* (NCCoE, Aug 2025).

## Evaluation scenarios

Two scenarios provide the ground truth that AI-generated threats are scored against. Both ship a `system_description.md` (the DFD, assets, and flows) and a `gold_standard_threats.json` (the curated threat catalog). Each gold threat carries `tree_node`, `threat_type`, `severity`, and `likelihood`; scenario-specific provenance fields are noted below.

### KidsTube — primary scenario (36 threats, all 7 LINDDUN types)

A children's video-streaming platform under parental supervision (React / Node-Express / MongoDB). Source: EPS S26 HW2. **Current revision (v3):** 30 primary threats (Bakti's HW2) plus **6 merged from a second HW2 (Bilal)** that close coverage gaps — broken object-level authorization (BOLA), insecure password hashing, inference of sensitive child attributes from watch patterns, AB 2273 (AADC) privacy-by-default, CCPA/CPRA published-policy + DSAR, and a missing registration-time privacy notice. An earlier pass (v2) **audited 8 LINDDUN sub-node IDs** against the official trees and flagged 3 borderline threats; corrected threats record `original_hw2_node` + `mapping_note`, and merged threats record `source: "bilal_hw2"`. severity/likelihood are the HW2 qualitative ratings.

### Genomic Sequencing — second scenario (99 threats, all 7 LINDDUN types)

A genomic sequencing service (clinical + research pipelines). Source: **NIST SP 1800-43C DRAFT** — an *authoritative* model: NIST runs its own LINDDUN + PANOPTIC analysis and validates every threat against the NIST Privacy Engineering Objectives (PEOs). This gold standard is the **complete example** (~99 itemized threats); the 10 threats of the smaller *core example* walked through in the PDF body are tagged `in_core_example`. The complete analysis is published by NIST only as figures in the external HTML appendices, so it was **transcribed by vision-reading Appendix G Figures 20 (validations) and 24 (ranked threats)**, which were transcribed independently and cross-checked. Raw transcription is committed at `scripts/data/genomic_complete_raw.json`, and the **report PDF + appendix figures/sources** are bundled at `references/nist-sp-1800-43c/`. Each threat keeps NIST's native fields — `scenario_id`, `panoptic_actions`, `feasibility`, `difficulty`, `ranking_value`, `impacted_peos` — plus `nist_node` (verbatim NIST node) alongside `tree_node` (mapped to the nearest node in this repo's tree, since NIST uses a deeper LINDDUN revision). severity/likelihood are convenience projections from NIST's feasibility/difficulty.

**Accuracy:** `scripts/verify_genomic.py` cross-checks every genomic row against an independent transcription (Figure 24) and NIST's own ranking formula (Tables 18/19: `ranking = combo(feasibility, difficulty) × type_weight`). Current state: **all 99 rows formula-consistent, 97/99 corroborated by both figures.** The 2 remaining are node-only differences between the two transcriptions; the only cell not independently re-confirmed is #24's node. This check also runs in the test suite, so the file can't silently drift from the source.

> Caveat: the genomic rows are OCR of a **draft** figure — treat per-threat details as transcription-confidence and spot-check against the bundled figures before relying on a single row.

## How to use the repo

### 1. Install

```bash
pip install -r requirements.txt        # numpy + scikit-learn only
```

### 2. Build the index

The index must be built once before searching. It chunks every knowledge-base
document, embeds the chunks, and persists the result under `storage/index/`.

```bash
python cli.py build                    # build + persist the index
python cli.py stats                    # corpus statistics (chunk counts by source/kind)
```

Re-run `build` whenever you edit anything under `knowledge_base/` or change the
embedding backend.

### 3. Search the knowledge base

```bash
# top-k semantic + keyword (hybrid) search
python cli.py search "government ID stored unencrypted" -k 3

# restrict to one source: linddun | regulations | scenarios
python cli.py search "excessive data retention" --source linddun
```

Each hit prints a relevance score, its source/document/section, and a snippet —
so you can trace any result back to a specific tree node or regulation.

### 4. Ask a grounded question (optional, needs Claude)

`ask` retrieves context and has Claude answer using only that context, citing the
sources it used. Without an API key it just prints the retrieved context.

```bash
# .env: set ANTHROPIC_API_KEY, then
python cli.py ask "What threats apply when a process writes child PII to a data store?"
```

### 5. Run the tests

```bash
python tests/test_kb.py                # integrity + retrieval-quality checks
```

### Choosing an embedding backend

The default backend is **TF-IDF** (zero downloads, runs anywhere). Switch via a
`.env` file, then rebuild the index:

```bash
# .env
EMBEDDING_BACKEND=sbert                # semantic embeddings, needs sentence-transformers
# EMBEDDING_BACKEND=anthropic          # placeholder, not yet wired (falls back to tfidf)
```

```bash
python cli.py build                    # rebuild after changing the backend
```

## Architecture

```
knowledge_base/        curated source-of-truth documents (the durable asset)
  linddun/             methodology: trees, mapping table, definitions
  regulations/         COPPA / GDPR / CCPA excerpts
  scenarios/kidstube/  system description + 36-threat gold standard (primary)
  scenarios/genomic/   system description + 99-threat gold standard (NIST SP 1800-43C complete example)

ingestion/loader.py    md/json -> Chunk[] (structured items become individual chunks)
retrieval/
  embeddings.py        pluggable backend: tfidf (default) | sbert | anthropic
  index.py             vector index + hybrid (dense + keyword) retrieval, persisted
  interaction_context.py   assembles per-interaction methodology context for threat generation
storage/index/         persisted embeddings + chunk metadata (gitignored)
scripts/build_kidstube_gold.py   regenerates the KidsTube gold standard JSON
scripts/build_genomic_gold.py    regenerates the genomic (NIST SP 1800-43C) gold standard JSON
scripts/data/genomic_complete_raw.json   raw vision-transcription of NIST Appendix G figures (audit trail)
scripts/verify_genomic.py   cross-checks the genomic gold vs NIST Figure 24 + ranking formula
tests/test_kb.py       integrity + retrieval-quality checks
eval/                  evaluation harness
references/nist-sp-1800-43c/   NIST report PDF + appendix figures/sources (provenance; NOT ingested)
```

### Design choices

- **Structured chunks.** JSON threat trees, mapping rows, and gold threats are split into one chunk per item, so retrieval returns a precise node (e.g. `Dd.2.1`) rather than a wall of text. This is what makes grounding citations clean.
- **Hybrid retrieval.** Dense cosine similarity is blended with keyword overlap so exact node IDs and regulation numbers (`Dd.1.1`, `§312.5`) surface reliably, which pure dense embeddings tend to blur.
- **Pluggable embeddings.** Starts dependency-free for a reproducible demo; upgrades to semantic embeddings with one env var.
- **Backend-agnostic content.** If we adopt the partner's Qdrant/reranker stack, only `retrieval/` changes — the knowledge base and gold standard move over unchanged.

## Target pipeline (end-to-end goal)

The end goal is an LLM assistant that performs LINDDUN Pro threat modeling from a real-world input — either a **DFD** the user provides or the **source code** of an app — grounded in this knowledge base and graded against the gold standards.

```
INPUT                     PIVOT                  GROUNDED ELICITATION           OUTPUT
─────                     ─────                  ────────────────────           ──────
DFD (provided) ──┐
                 ├─► canonical DFD ──► per-interaction LINDDUN ──► threats ──► regulatory ──► threat model
source code ─────┘    (elements +      elicitation grounded         (LLM)      mapping        (scored vs gold)
                       interactions)    in the KB
```

The **canonical DFD is the pivot**: both inputs converge on one structured representation (elements, flows, trust boundaries, interactions), and everything downstream consumes it. This is the shared schema to align with the `RAG-MCP-system` backend.

### Stage status

| Stage | Component | Status |
|---|---|---|
| Knowledge base (LINDDUN trees, mapping table, regulations) | `knowledge_base/`, `ingestion/`, `retrieval/` | ✅ built |
| Evaluation ground truth (KidsTube 36 + genomic 99) | `knowledge_base/scenarios/`, `scripts/verify_genomic.py` | ✅ built |
| Methodology handoff (DFD interaction → applicable types/positions/nodes) | `retrieval/interaction_context.py` | ✅ built |
| **Input front-end** — DFD ingestion / **source-code → DFD synthesis** | — | ⬜ not built (the largest piece; code→DFD is the research-hard part) |
| Canonical DFD schema (the pivot representation) | — | ⬜ not built (formalize first) |
| Threat generation (LLM emits structured threats per interaction) | — | ⬜ Week 3 |
| Regulatory mapping on generated threats | — | ⬜ not built |
| Eval harness (generated vs gold; retrieval excludes the answer key) | `eval/` | ⬜ not built |

### Notes on evaluation

- `retrieval/interaction_context.py` is the current handoff: given a DFD interaction (e.g. `ExternalEntity -> Process`) it returns the applicable threat types, their S/fl/D positions, and the relevant tree nodes — exactly the context the per-interaction generation prompt will consume.
- **Avoid leakage:** the gold-standard threats are in the index today (over half the chunks). At generation time, retrieval must be restricted to methodology (`--source linddun` / `regulations` + the scenario's `system_description.md`) and the gold held out as the grader only.
- **Gold suits input modes differently:** KidsTube is anchored per DFD interaction (good for a per-interaction pipeline) and is a real React/Node app — the one scenario that can test the full **code → DFD → threats** chain end to end. Genomic has no codebase and no per-threat DFD anchor; it evaluates "for this system, did you find these threats" at a coarser grain, with NIST's native prioritization/PEO fields enabling a richer scoring metric.
