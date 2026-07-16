# LINDDUN Threat Modeling — Grounded and Verified

Can an LLM, grounded in the LINDDUN Pro methodology, help a privacy expert produce a threat model
they can **audit** rather than blindly trust?

Every generated threat cites two things: the LINDDUN threat-tree node it instantiates, and the DFD
location where it arises. Both are **independently re-derived** against the knowledge base after
generation, not trusted from the model's own output. The same idea applies one level up: a DFD
derived from source code cites the code facts behind it, and those are re-parsed against the source.

## What's inside

```
knowledge_base/          curated source-of-truth (the durable asset)
  linddun/               threat trees, mapping table (Table 4.1), methodology prose, PANOPTIC crosswalk
  panoptic/              MITRE PANOPTIC taxonomy (5 domains, 13 activities, 100 sub-activities)
  scenarios/<name>/      system_description.md + dfd.json + gold_standard_threats.json

ingestion/ retrieval/    chunking, pluggable embeddings, hybrid (dense+keyword) index
generation/              per-flow prompts -> threats; llm_backend.py (Anthropic/OpenAI/Azure);
                         verify.py re-checks every citation against the KB
eval/                    match.py, metrics.py, reachability.py, adjudicate.py, run_eval.py
adapters/                source code -> DFD (Week 10). extract/resolve -> code facts with file:line;
                         synthesize -> DFD citing fact ids; verify_dfd -> re-derives every citation
scripts/                 gold/DFD builders, verifiers, DFD renderer (all regenerable)
storage/                 index/ (gitignored), generated/ + derived/ + adjudication/ (tracked)
tests/                   test_kb.py (77), test_generation.py (227), test_adapter.py (90) — all offline
```

## Install

```bash
pip install -r requirements.txt                 # numpy + scikit-learn only
```

Optional extras are commented in `requirements.txt`: an LLM provider (`anthropic` / `openai`) for
generation, `sentence-transformers` for better embeddings, and `tree-sitter` + `tree-sitter-javascript`
for the adapter's extraction stage. Everything else runs without them.

## Run

### Knowledge base

```bash
python cli.py build                             # build + persist the index (rerun after editing knowledge_base/)
python cli.py stats                             # chunk counts by source/kind
python cli.py search "government ID stored unencrypted" -k 3
python cli.py ask "What threats apply when a process writes child PII to a data store?"   # needs an API key
```

### Generate + evaluate threats

Set `LLM_PROVIDER` and the matching key in `.env` (see `config.py`), then:

```bash
python cli.py generate --scenario kidstube                      # grounded: deterministic mapping-table lookup
python cli.py generate --scenario kidstube --rag                # RAG: genuine retrieval over the LINDDUN KB
python cli.py generate --scenario kidstube --ungrounded         # ablation baseline: no context
python cli.py generate --scenario genomic --framework panoptic  # same three modes against MITRE PANOPTIC

python cli.py eval --scenario kidstube --generated storage/generated/kidstube_grounded.json
python cli.py adjudicate --scenario kidstube --generated storage/generated/kidstube_grounded.json
```

`--framework` (linddun | panoptic) picks *which methodology* to ground in; `--rag`/`--ungrounded` pick
*how*. Six combinations. `eval` scores against the gold standard and re-verifies every citation.
`adjudicate` is manual by design — gold standards are curated, not exhaustive, so automated precision
is a lower bound, and a model grading its own output would just relocate the problem this project
exists to address.

### Source code → DFD (adapter)

```bash
python cli.py extract --source-root ~/src/KidsTube-PE --scenario kidstube    # -> adapters/data/*_code_facts.json
python cli.py derive  --scenario kidstube_derived --mode facts_only          # facts_only | llm
python cli.py verify-dfd --scenario kidstube_derived --source-root ~/src/KidsTube-PE
python cli.py eval-dfd --derived kidstube_derived --against kidstube         # needs a hand-authored DFD
```

`extract` needs the source; everything after it runs from the committed facts, so no tree-sitter or
checkout is required to reproduce a result. **`extract`/`derive`/`verify-dfd` need no ground truth** —
that is the path for an arbitrary repo. Only `eval-dfd` does, and it is the experiment, not the
product: recall and precision require knowing the right answer.

### Tests

```bash
python tests/test_kb.py && python tests/test_generation.py && python tests/test_adapter.py
```

## Scenarios

Provenance varies, and that governs how much weight any one scenario's numbers carry.

| Scenario | Threats | Source | Weight |
|---|---:|---|---|
| KidsTube | 41 | Human-authored HW2 (two passes); real React/Node app | Real analysis; not independently reviewed |
| Genomic | 99 | NIST SP 1800-43C, published report | **Strongest** — external, expert-validated |
| Family Location | 20 | Hand-authored here (Week 8), LLM-assisted | **Weakest** — treat as illustrative until reviewed |
| Smart Home | 18 | Hand-authored here (Week 8), LLM-assisted | Same caveat |
| `kidstube_derived` | — | Adapter output, not ground truth | Pipeline artifact; excluded from retrieval |

Two ceilings worth knowing before reading any recall number. **Genomic: 72/99** — the other 27 threats
sit on interactions LINDDUN Pro's mapping table doesn't model at all, so the per-flow loop can never
produce them. **KidsTube adapter: 10/12 elements, 15/17 flows** — P4 (AI engine) and EE3 (advertisers)
are marked "(planned)" in the system description and exist in no code. Both are reported separately
from real misses (`eval/reachability.py`, `adapters/evaluate.py`).

## Status

| Stage | Status |
|---|---|
| Knowledge base, retrieval, methodology handoff | ✅ |
| Threat generation + citation verification | ✅ built, ✅ live runs |
| Eval harness (P/R/F1, citation correctness, reachability) | ✅ |
| Ablations: grounded / RAG / ungrounded, LINDDUN + PANOPTIC | ✅ built, ✅ live runs |
| Canonical DFD schema (`adapters/schema.py`, a validator) | ✅ built (Week 10) |
| **Source code → DFD** — `facts_only` + `llm` arms | ✅ built (Week 10), Express/Mongoose only |
| `llm_naive` arm (open `file:line` citations) | ⬜ not built — until it exists, the adapter's citation rates are 1.00 *by construction* and carry no information |
| End-to-end: threats generated on a derived DFD | ⬜ not run |
| Manual FP adjudication | ✅ built (Week 9); ⬜ no scenario reviewed yet |

**Adapter scope:** `adapters/extract.py` and `resolve.py` speak conventional Express/Mongoose/React
idioms and return ~zero facts on other stacks, silently. The generalizable parts are the schema, the
fact-id citation discipline, and the derivability-ceiling reporting — not the JS patterns.

## More detail

**Pipeline** (why `grounded` ≠ RAG, and why that matters for citation validity): [PIPELINE.md](PIPELINE.md)
**Results:** [RESULTS_2026-07-14.md](RESULTS_2026-07-14.md) · **Background:** [REFERENCES.md](REFERENCES.md)

**Progress reports:** [1](WEEK1_REPORT.md) · [2](WEEK2_REPORT.md) · [3](WEEK3_REPORT.md) · [4](WEEK4_REPORT.md) · [5](WEEK5_REPORT.md) · [6](WEEK6_REPORT.md) · [7](WEEK7_REPORT.md) · [8](WEEK8_REPORT.md) · [9](WEEK9_REPORT.md) · [10](WEEK10_REPORT.md)

Sources: LINDDUN Pro Tutorial v0.1 (KU Leuven); NIST SP 1800-43C DRAFT, *Genomic Data Threat Modeling:
Privacy* (NCCoE, Aug 2025) — report + appendix figures bundled at `references/nist-sp-1800-43c/`.
