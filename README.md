# LINDDUN Knowledge Base — Week 1 Deliverable

RAG knowledge base for AI-assisted LINDDUN Pro privacy threat modeling. This is the Week-1 foundation: the curated, chunked, and retrievable knowledge that every later stage (DFD synthesis, threat elicitation, regulatory mapping) draws on.

> Part of the summer project *AI-Assisted Privacy Threat Modeling: Grounded LINDDUN Pro*. The retrieval engine here is intentionally minimal and dependency-light; it can later be swapped for / merged with the shared `RAG-MCP-system` backend (Qdrant + hybrid + reranker). The knowledge base content (LINDDUN trees, mapping table, regulations, KidsTube gold standard) is the durable asset and is backend-agnostic.

## What's in the knowledge base

| Path | Contents | Why it matters |
|------|----------|----------------|
| `knowledge_base/linddun/threat_trees.json` | All 7 LINDDUN threat types + tree nodes (structured) | Each node is independently retrievable for grounded elicitation |
| `knowledge_base/linddun/mapping_table.json` | LINDDUN Pro Table 4.1 — which types apply at S/fl/D per interaction | Drives which threats to check for each DFD interaction |
| `knowledge_base/linddun/threat_types_and_methodology.md` | Type definitions + S/fl/D interpretation + iteration strategy | Prose context for the model |
| `knowledge_base/regulations/regulations.md` | COPPA, GDPR, CCPA provisions mapped to LINDDUN types | Enables regulatory citation on threats |
| `knowledge_base/scenarios/kidstube/system_description.md` | KidsTube DFD, assets, flows | Primary evaluation scenario |
| `knowledge_base/scenarios/kidstube/gold_standard_threats.json` | **30-threat gold standard from HW2** | Ground truth for all evaluation |

Sources: LINDDUN Pro Tutorial v0.1 (KU Leuven, downloads.linddun.org); eCFR Title 16 Part 312; GDPR (EU 2016/679); CCPA (Cal. Civ. Code §1798.100+). The KidsTube catalog is the author's EPS S26 HW2.

## Quick start

```bash
pip install -r requirements.txt        # numpy + scikit-learn only
python cli.py build                    # build + persist the index
python cli.py stats                    # corpus statistics
python cli.py search "government ID stored unencrypted" -k 3
python cli.py search "excessive data retention" --source linddun
python tests/test_kb.py                # 21 integrity + retrieval tests
```

Default embedding backend is **TF-IDF** (zero downloads, runs anywhere). To upgrade:

```bash
# .env
EMBEDDING_BACKEND=sbert                # needs sentence-transformers
```

Optional Claude-grounded answers:

```bash
# .env: set ANTHROPIC_API_KEY, then
python cli.py ask "What threats apply when a process writes child PII to a data store?"
```

## Architecture

```
knowledge_base/        curated source-of-truth documents (the durable asset)
  linddun/             methodology: trees, mapping table, definitions
  regulations/         COPPA / GDPR / CCPA excerpts
  scenarios/kidstube/  system description + 30-threat gold standard

ingestion/loader.py    md/json -> Chunk[] (structured items become individual chunks)
retrieval/
  embeddings.py        pluggable backend: tfidf (default) | sbert | anthropic
  index.py             vector index + hybrid (dense + keyword) retrieval, persisted
  interaction_context.py   bridge to week 2: assembles per-interaction methodology context
storage/index/         persisted embeddings + chunk metadata (gitignored)
scripts/build_kidstube_gold.py   regenerates the gold standard JSON
tests/test_kb.py       integrity + retrieval-quality checks
eval/                  (week 6+) evaluation harness lives here
```

### Design choices

- **Structured chunks.** JSON threat trees, mapping rows, and gold threats are split into one chunk per item, so retrieval returns a precise node (e.g. `Dd.2.1`) rather than a wall of text. This is what makes grounding citations clean.
- **Hybrid retrieval.** Dense cosine similarity is blended with keyword overlap so exact node IDs and regulation numbers (`Dd.1.1`, `§312.5`) surface reliably, which pure dense embeddings tend to blur.
- **Pluggable embeddings.** Starts dependency-free for a reproducible demo; upgrades to semantic embeddings with one env var.
- **Backend-agnostic content.** If we adopt the partner's Qdrant/reranker stack, only `retrieval/` changes — the knowledge base and gold standard move over unchanged.

## How this connects to Week 2

`retrieval/interaction_context.py` is the handoff. Given a DFD interaction (e.g. `ExternalEntity -> Process`), it returns the applicable threat types, their positions (S/fl/D), and the relevant tree nodes — exactly the context the Week-2 per-interaction threat-generation prompt consumes. Week 2 wires this into prompt construction + Claude generation and compares output against the gold standard.

## Status

- [x] Knowledge base curated and structured (LINDDUN trees, mapping table, regulations, KidsTube)
- [x] 30-threat gold standard encoded as machine-readable JSON
- [x] Ingestion + chunking (118 chunks)
- [x] Hybrid retrieval with pluggable embeddings, persisted index
- [x] CLI (build / search / stats / ask)
- [x] Interaction-context assembler (bridge to threat generation)
- [x] 21 passing tests
- [ ] (Week 2) Threat-generation pipeline
- [ ] (Week 1, with advisor) Confirm gold standard; lock venue, scenarios, IP, budget
```
