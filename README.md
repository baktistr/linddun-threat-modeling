# LINDDUN Knowledge Base

RAG knowledge base for AI-assisted LINDDUN Pro privacy threat modeling: the curated, chunked, and retrievable knowledge that every stage (DFD synthesis, threat elicitation, regulatory mapping) draws on.

> The retrieval engine is intentionally minimal and dependency-light; it can later be swapped for / merged with a shared `RAG-MCP-system` backend (Qdrant + hybrid + reranker). The knowledge base content (LINDDUN trees, mapping table, regulations, KidsTube gold standard) is the durable asset and is backend-agnostic.

## What's in the knowledge base

| Path | Contents | Why it matters |
|------|----------|----------------|
| `knowledge_base/linddun/threat_trees.json` | All 7 LINDDUN threat types + tree nodes (structured) | Each node is independently retrievable for grounded elicitation |
| `knowledge_base/linddun/mapping_table.json` | LINDDUN Pro Table 4.1 — which types apply at S/fl/D per interaction | Drives which threats to check for each DFD interaction |
| `knowledge_base/linddun/threat_types_and_methodology.md` | Type definitions + S/fl/D interpretation + iteration strategy | Prose context for the model |
| `knowledge_base/regulations/regulations.md` | COPPA, GDPR, CCPA provisions mapped to LINDDUN types | Enables regulatory citation on threats |
| `knowledge_base/scenarios/kidstube/system_description.md` | KidsTube DFD, assets, flows | Primary evaluation scenario |
| `knowledge_base/scenarios/kidstube/gold_standard_threats.json` | **30-threat gold standard** | Ground truth for all evaluation |

Sources: LINDDUN Pro Tutorial v0.1 (KU Leuven, downloads.linddun.org); eCFR Title 16 Part 312; GDPR (EU 2016/679); CCPA (Cal. Civ. Code §1798.100+).

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
  scenarios/kidstube/  system description + 30-threat gold standard

ingestion/loader.py    md/json -> Chunk[] (structured items become individual chunks)
retrieval/
  embeddings.py        pluggable backend: tfidf (default) | sbert | anthropic
  index.py             vector index + hybrid (dense + keyword) retrieval, persisted
  interaction_context.py   assembles per-interaction methodology context for threat generation
storage/index/         persisted embeddings + chunk metadata (gitignored)
scripts/build_kidstube_gold.py   regenerates the gold standard JSON
tests/test_kb.py       integrity + retrieval-quality checks
eval/                  evaluation harness
```

### Design choices

- **Structured chunks.** JSON threat trees, mapping rows, and gold threats are split into one chunk per item, so retrieval returns a precise node (e.g. `Dd.2.1`) rather than a wall of text. This is what makes grounding citations clean.
- **Hybrid retrieval.** Dense cosine similarity is blended with keyword overlap so exact node IDs and regulation numbers (`Dd.1.1`, `§312.5`) surface reliably, which pure dense embeddings tend to blur.
- **Pluggable embeddings.** Starts dependency-free for a reproducible demo; upgrades to semantic embeddings with one env var.
- **Backend-agnostic content.** If we adopt the partner's Qdrant/reranker stack, only `retrieval/` changes — the knowledge base and gold standard move over unchanged.

## How this connects to threat generation

`retrieval/interaction_context.py` is the handoff. Given a DFD interaction (e.g. `ExternalEntity -> Process`), it returns the applicable threat types, their positions (S/fl/D), and the relevant tree nodes — exactly the context the per-interaction threat-generation prompt consumes. The next stage wires this into prompt construction + Claude generation and compares output against the gold standard.
```
