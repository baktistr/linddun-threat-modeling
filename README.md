# LINDDUN Knowledge Base

RAG knowledge base for AI-assisted LINDDUN Pro privacy threat modeling: the curated, chunked, and retrievable knowledge that grounds every stage of the pipeline (DFD synthesis, threat elicitation, traceable citation) — built to answer one question: can an LLM, grounded in the LINDDUN Pro methodology, help a privacy expert conduct a LINDDUN-based privacy risk analysis they can trust?

> The retrieval engine is intentionally minimal and dependency-light; it can later be swapped for / merged with a shared `RAG-MCP-system` backend (Qdrant + hybrid + reranker). The knowledge base content (LINDDUN trees, mapping table, and the KidsTube + genomic gold standards) is the durable asset and is backend-agnostic.

**Progress reports:** [Week 1](WEEK1_REPORT.md) · [Week 2](WEEK2_REPORT.md) · [Week 3](WEEK3_REPORT.md) · [Week 4](WEEK4_REPORT.md) · [Week 5](WEEK5_REPORT.md) · [Week 6](WEEK6_REPORT.md)
**Background & related work:** [REFERENCES.md](REFERENCES.md)

## What's in the knowledge base

| Path | Contents | Why it matters |
|------|----------|----------------|
| `knowledge_base/linddun/threat_trees.json` | All 7 LINDDUN threat types + tree nodes (structured) | Each node is independently retrievable for grounded elicitation |
| `knowledge_base/linddun/mapping_table.json` | LINDDUN Pro Table 4.1 — which types apply at S/fl/D per interaction | Drives which threats to check for each DFD interaction |
| `knowledge_base/linddun/threat_types_and_methodology.md` | Type definitions + S/fl/D interpretation + iteration strategy | Prose context for the model |
| `knowledge_base/scenarios/kidstube/system_description.md` | KidsTube DFD, assets, flows | Primary evaluation scenario |
| `knowledge_base/scenarios/kidstube/gold_standard_threats.json` | **36-threat gold standard** | Ground truth for all evaluation |
| `knowledge_base/scenarios/genomic/system_description.md` | Genomic sequencing DFD, assets, flows | Second evaluation scenario |
| `knowledge_base/scenarios/genomic/gold_standard_threats.json` | **99-threat gold standard** (NIST complete example; 10 tagged as the core-example subset); each threat now also carries `dfd_source_id`/`dfd_destination_id` (97/99 resolved, Week 3) | Authoritative ground truth — NIST's own LINDDUN analysis, transcribed from Appendix G figures |
| `knowledge_base/scenarios/genomic/dfd.json` | Structured DFD: **32 elements, 39 flows** across the shared + clinical + research pipelines (Week 3) | Lets generation iterate over concrete named flows, same as KidsTube |

Sources: LINDDUN Pro Tutorial v0.1 (KU Leuven, downloads.linddun.org); NIST SP 1800-43C DRAFT, *Genomic Data Threat Modeling: Privacy* (NCCoE, Aug 2025).

## Evaluation scenarios

Two scenarios provide the ground truth that AI-generated threats are scored against. Both ship a `system_description.md` (the DFD, assets, and flows) and a `gold_standard_threats.json` (the curated threat catalog). Each gold threat carries `tree_node`, `threat_type`, `severity`, and `likelihood`; scenario-specific provenance fields are noted below.

### KidsTube — primary scenario (36 threats, all 7 LINDDUN types)

A children's video-streaming platform under parental supervision (React / Node-Express / MongoDB). Source: EPS S26 HW2. **Current revision (v3):** 30 primary threats (Bakti's HW2) plus **6 merged from a second HW2 (Bilal)** that close coverage gaps — broken object-level authorization (BOLA), insecure password hashing, inference of sensitive child attributes from watch patterns, AB 2273 (AADC) privacy-by-default, CCPA/CPRA published-policy + DSAR, and a missing registration-time privacy notice. An earlier pass (v2) **audited 8 LINDDUN sub-node IDs** against the official trees and flagged 3 borderline threats; corrected threats record `original_hw2_node` + `mapping_note`, and merged threats record `source: "bilal_hw2"`. severity/likelihood are the HW2 qualitative ratings.

### Genomic Sequencing — second scenario (99 threats, all 7 LINDDUN types)

A genomic sequencing service (clinical + research pipelines). Source: **NIST SP 1800-43C DRAFT** — an *authoritative* model: NIST runs its own LINDDUN + PANOPTIC analysis and validates every threat against the NIST Privacy Engineering Objectives (PEOs). This gold standard is the **complete example** (~99 itemized threats); the 10 threats of the smaller *core example* walked through in the PDF body are tagged `in_core_example`. The complete analysis is published by NIST only as figures in the external HTML appendices, so it was **transcribed by vision-reading Appendix G Figures 20 (validations) and 24 (ranked threats)**, which were transcribed independently and cross-checked. Raw transcription is committed at `scripts/data/genomic_complete_raw.json`, and the **report PDF + appendix figures/sources** are bundled at `references/nist-sp-1800-43c/`. Each threat keeps NIST's native fields — `scenario_id`, `panoptic_actions`, `feasibility`, `difficulty`, `ranking_value`, `impacted_peos` — plus `nist_node` (verbatim NIST node) alongside `tree_node` (mapped to the nearest node in this repo's tree, since NIST uses a deeper LINDDUN revision). severity/likelihood are convenience projections from NIST's feasibility/difficulty.

**Accuracy:** `scripts/verify_genomic.py` cross-checks every genomic row against an independent transcription (Figure 24) and NIST's own ranking formula (Tables 18/19: `ranking = combo(feasibility, difficulty) × type_weight`). Current state: **all 99 rows formula-consistent, 97/99 corroborated by both figures.** The 2 remaining are node-only differences between the two transcriptions; the only cell not independently re-confirmed is #24's node. This check also runs in the test suite, so the file can't silently drift from the source.

**DFD locations (Week 3):** `dfd_source_id`/`dfd_destination_id` per threat, transcribed from Appendix F Figure 11 ("Task 4: Assess System Design") via `scripts/build_genomic_dfd.py`, cross-checked against each threat's `nist_node`. 97/99 resolved (93 high-confidence, 4 low-confidence from an ambiguous locally-repeated cluster, 2 left unresolved rather than guessed — ids and reasoning in the script). **Important:** of the 97 resolved, only **17** sit on one of the 5 interaction pairs `mapping_table.json` covers — all of which route through a Process. The other 80 are interactions NIST models directly with no Process step: `ExternalEntity -> DataStore` (39, e.g. a researcher requesting a sample straight from `DNA Store`), `ExternalEntity -> ExternalEntity` (23, e.g. Clinician↔Patient), `DataStore -> ExternalEntity` (17), and `DataStore -> DataStore` (1). None of these are in the LINDDUN Pro tutorial's mapping table, so they're structurally unreachable by the current per-flow generation loop regardless of prompt quality. See `WEEK3_REPORT.md` for the full reasoning and the options this raises.

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

# restrict to one source: linddun | scenarios
python cli.py search "excessive data retention" --source linddun
```

Each hit prints a relevance score, its source/document/section, and a snippet —
so you can trace any result back to a specific tree node or scenario document.

### 4. Ask a grounded question (optional, needs Claude)

`ask` retrieves context and has Claude answer using only that context, citing the
sources it used. Without an API key it just prints the retrieved context.

```bash
# .env: set ANTHROPIC_API_KEY, then
python cli.py ask "What threats apply when a process writes child PII to a data store?"
```

### 5. Generate + evaluate threats (needs an LLM API key)

```bash
# .env: set ANTHROPIC_API_KEY (or OPENAI_API_KEY + LLM_PROVIDER=openai), then
python cli.py generate --scenario kidstube                  # grounded generation, one flow at a time
python cli.py generate --scenario kidstube --ungrounded     # ablation baseline, no retrieval/context
python cli.py eval --scenario kidstube --generated storage/generated/kidstube_grounded.json
```

`generate` is provider-agnostic (`LLM_PROVIDER=anthropic|openai` in `.env`, or `--provider` on the
CLI — see `generation/llm_backend.py`); any OpenAI-compatible endpoint works via `OPENAI_BASE_URL`.
`eval` matches generated threats against the scenario's gold standard, reports recall/precision/F1
per LINDDUN category, and independently re-verifies every citation against the knowledge base
(`generation/verify.py`) rather than trusting what the model claims.

### 6. Run the tests

```bash
python tests/test_kb.py                # integrity + retrieval-quality checks
python tests/test_generation.py        # generation schema, verifier, matcher/metrics (offline, no API key)
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
  scenarios/kidstube/  system description + dfd.json (12 elements, 17 flows) + 36-threat gold standard (primary)
  scenarios/genomic/   system description + dfd.json (32 elements, 39 flows, all 4 pipelines) + 99-threat gold standard

ingestion/loader.py    md/json -> Chunk[] (structured items become individual chunks; dfd.json excluded)
retrieval/
  embeddings.py        pluggable backend: tfidf (default) | sbert | anthropic
  index.py             vector index + hybrid (dense + keyword) retrieval, persisted; exclude_kinds guards against gold-standard leakage
  interaction_context.py   assembles per-interaction methodology context for threat generation
storage/index/         persisted embeddings + chunk metadata (gitignored)
storage/generated/     generated threats per scenario/run (gitignored)
generation/
  schema.py            GeneratedThreat + the Claude/OpenAI-agnostic tool-call schema (3-way citations)
  prompt.py             per-flow grounded / ungrounded (ablation) prompt construction
  generate.py            drives one prompt per DFD flow -> GeneratedThreat[], persists results
  llm_backend.py         pluggable LLM provider: Anthropic | OpenAI (or any OpenAI-compatible endpoint)
  verify.py               independently verifies each citation against the KB (not self-reported)
eval/
  match.py                generated-vs-gold matching: flow+type for KidsTube, (source,destination)+type for genomic
  metrics.py               recall/precision/F1 per LINDDUN category + citation-correctness rates
  run_eval.py              CLI-facing report
scripts/build_kidstube_gold.py   regenerates the KidsTube gold standard JSON
scripts/build_genomic_gold.py    regenerates the genomic (NIST SP 1800-43C) gold standard JSON
scripts/build_genomic_dfd.py     regenerates genomic dfd.json + adds dfd_source_id/dfd_destination_id to gold (Week 3)
scripts/data/genomic_complete_raw.json   raw vision-transcription of NIST Appendix G figures (audit trail)
scripts/data/genomic_figure11_raw.json   raw vision-transcription of Appendix F Figure 11 (audit trail, Week 3)
scripts/verify_genomic.py   cross-checks the genomic gold vs NIST Figure 24 + ranking formula
tests/test_kb.py       integrity + retrieval-quality checks
tests/test_generation.py   offline: schema, verifier, matcher/metrics, LLM-backend routing
references/nist-sp-1800-43c/   NIST report PDF + appendix figures/sources (provenance; NOT ingested)
```

### Design choices

- **Structured chunks.** JSON threat trees, mapping rows, and gold threats are split into one chunk per item, so retrieval returns a precise node (e.g. `Dd.2.1`) rather than a wall of text. This is what makes grounding citations clean.
- **Hybrid retrieval.** Dense cosine similarity is blended with keyword overlap so exact node IDs (`Dd.1.1`) surface reliably, which pure dense embeddings tend to blur.
- **Pluggable embeddings.** Starts dependency-free for a reproducible demo; upgrades to semantic embeddings with one env var.
- **Backend-agnostic content.** If we adopt the partner's Qdrant/reranker stack, only `retrieval/` changes — the knowledge base and gold standard move over unchanged.

## Target pipeline (end-to-end goal)

The end goal is not full automation but an LLM assistant that helps a privacy expert conduct LINDDUN Pro threat modeling faster and more completely — from a real-world input (a **DFD** the user provides, or the **source code** of an app), grounded in this knowledge base, with every generated threat independently traceable to a specific methodology node and DFD location so the expert can verify rather than blindly trust it. Where a gold standard exists, output is also graded against it as a proxy for how close the assistant gets to expert-level analysis.

```
INPUT                     PIVOT                  GROUNDED ELICITATION                OUTPUT
─────                     ─────                  ────────────────────                ──────
DFD (provided) ──┐
                 ├─► canonical DFD ──► per-interaction LINDDUN ──► cited threats ──► reviewed threat model
source code ─────┘    (elements +      elicitation grounded         (LLM, tree-        (privacy expert
                       interactions)    in the KB                    node + DFD-        verifies, scored
                                                                      location cited,    vs gold where
                                                                      independently      available)
                                                                      verified)
```

The **canonical DFD is the pivot**: both inputs converge on one structured representation (elements, flows, trust boundaries, interactions), and everything downstream consumes it. This is the shared schema to align with the `RAG-MCP-system` backend.

### Stage status

| Stage | Component | Status |
|---|---|---|
| Knowledge base (LINDDUN trees, mapping table) | `knowledge_base/`, `ingestion/`, `retrieval/` | ✅ built |
| Evaluation ground truth (KidsTube 36 + genomic 99) | `knowledge_base/scenarios/`, `scripts/verify_genomic.py` | ✅ built |
| Methodology handoff (DFD interaction → applicable types/positions/nodes) | `retrieval/interaction_context.py` | ✅ built |
| Per-scenario structured DFD (named elements/flows, not the general pivot schema) | `knowledge_base/scenarios/*/dfd.json` | ✅ built (Week 3) |
| **Input front-end** — DFD ingestion / **source-code → DFD synthesis** | — | ⬜ not built (the largest piece; code→DFD is the research-hard part) |
| Canonical DFD schema (the general pivot representation, arbitrary systems) | — | ⬜ not built (formalize first) |
| Threat generation (LLM emits structured threats per flow, 2-way citations) | `generation/` | ✅ built (pipeline + tests); ⬜ live run pending an API key |
| Citation verification (node / location independently checked) | `generation/verify.py` | ✅ built (Week 3) |
| Eval harness (generated vs gold, per-category P/R/F1 + citation-correctness; retrieval excludes the answer key) | `eval/` | ✅ built (Week 3) |
| Grounded-vs-ungrounded ablation | `generation/generate.py --ungrounded` | ✅ built; ⬜ live comparison pending an API key |

### Notes on evaluation

- `retrieval/interaction_context.py` is the handoff: given a DFD interaction (e.g. `ExternalEntity -> Process`) it returns the applicable threat types, their S/fl/D positions, and the relevant tree nodes — the context each per-flow generation prompt consumes (`generation/prompt.py`).
- **Leakage closed:** `Retriever.search(..., exclude_kinds=["gold_threat"])` excludes gold-standard chunks from generation-time retrieval (Week 3); `search`/`ask` are unaffected by default.
- **Gold suits input modes differently:** KidsTube is anchored per DFD flow (good for a per-flow pipeline) and is a real React/Node app — the one scenario that can eventually test the full **code → DFD → threats** chain end to end. Genomic has no codebase, but (as of Week 3) 97 of its 99 threats do have a real per-threat DFD anchor (`dfd_source_id`/`dfd_destination_id`, transcribed from Appendix F Figure 11) and `eval/match.py` matches on it, the same as KidsTube. The catch: only 17 of those 97 sit on an interaction type the mapping table covers (see the genomic scenario section above) — the rest are direct ExternalEntity↔DataStore, ExternalEntity↔ExternalEntity, or DataStore↔DataStore interactions with no mediating Process, which the LINDDUN Pro tutorial's mapping table doesn't model at all, so genomic's realistic recall ceiling with the current pipeline is far below 99, independent of generation quality.
- **Citations are independently verified, not self-reported:** `generation/verify.py` re-checks each generated threat's tree node and DFD location against the knowledge base files directly — the concrete mechanism behind the abstract's "traceability that is verified" claim.
