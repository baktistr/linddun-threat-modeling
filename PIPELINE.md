# Grounded vs. RAG vs. Ungrounded Generation Pipeline

Reference documentation for how threat generation actually works, mechanically, in all three
modes. (For *what the modes measured* on real data, see [WEEK6_REPORT.md](WEEK6_REPORT.md); the
`rag` mode is new and its live numbers aren't in that report yet.)

## At a glance

All three modes answer the same question — "what LINDDUN privacy threats apply to this one DFD
data flow?" — with the same LLM, the same forced structured-output schema, and the same
independent verifier downstream. The only difference is what the model is told *before* it
answers, and by what mechanism.

> **Terminology note:** only `rag` is retrieval-augmented generation in the literal sense (a
> similarity search that can retrieve the wrong passage). `grounded` is a deterministic,
> exhaustive lookup against `mapping_table.json`/`threat_trees.json` — there is no similarity
> search, so it cannot retrieve the wrong node. Calling `grounded` "RAG" would be inaccurate; the
> two are different mechanisms with different failure modes, which is exactly what this
> three-way ablation is designed to isolate.

```
                    ┌─────────────────────────────────────────────────────────┐
                    │  for each flow in scenario's dfd.json (one at a time)    │
                    └─────────────────────────────────────────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
        mode="grounded"                mode="rag"                mode="ungrounded"
              │                             │                             │
              ▼                             ▼                             ▼
 get_interaction_context(src,dst)  Retriever.search(query,           (no lookup at all)
 against mapping_table.json         source="linddun",
              │                     exclude_kinds=["gold_threat"])
   ┌──────────┴──────────┐                  │                             │
   │                     │                  ▼                             │
ctx.valid==False   ctx.valid==True    top-k chunks by                     │
   │                     │            hybrid dense+keyword                │
   ▼                     ▼            similarity (may miss                │
SKIP -- no LLM   build_grounded_      the right passage)                  │
call (structural  prompt(): flow            │                             │
ceiling)          text + applicable          ▼                             ▼
                  types + tree-node   build_rag_prompt(): flow      build_ungrounded_prompt():
                  list inlined,       text + retrieved chunks,      flow text ONLY --
                  explicit, an        framed as guidance, not       no methodology context
                  authoritative menu  an authoritative menu         at all
                        │                    │                             │
                        └────────────────────┼─────────────────────────────┘
                                             ▼
                                  backend.generate_threats(prompt)
                                  forced tool-call, THREAT_TOOL_SCHEMA
                                  (schema.py) -- same schema all three modes
                                             │
                                             ▼
                                  GeneratedThreat.from_dict(...)
                                  mode="grounded"/"rag"/"ungrounded" tagged on each threat
                                             │
                                             ▼
                                  verify_threat() -- independent check
                                  against threat_trees.json / mapping_table.json
                                  / dfd.json (same verifier, all three modes)
                                             │
                                             ▼
                                  eval/match.py + eval/metrics.py + eval/reachability.py
                                  -- scored against gold_standard_threats.json
```

## Shared setup

Both modes are driven by `generate_for_scenario()` (`generation/generate.py:24-57`), which:

1. Loads the scenario's `knowledge_base/scenarios/<name>/dfd.json` (elements + flows).
2. Iterates the flows list **one at a time**, in order. Each flow becomes exactly one LLM call
   (or zero, in grounded mode, if skipped — see below). There is no batching and no cross-flow
   context; the model only ever sees one flow per call.
3. Resolves the flow's `source`/`destination` element ids to their full element records
   (name and type).

Everything past this point diverges.

## Grounded pipeline

**Step 1 — interaction-context lookup** (`generate.py:38`, `retrieval/interaction_context.py:52-73`).

Before building any prompt, the pipeline calls:

```python
ctx = get_interaction_context(effective_type(src), effective_type(dst))
```

This is a **pure data lookup**, not a retrieval/embedding search — it reads
`knowledge_base/linddun/mapping_table.json` (the LINDDUN Pro tutorial's official Table 4.1,
5 valid interaction rows, byte-verified against the source PDF) and
`knowledge_base/linddun/threat_trees.json` (all 7 LINDDUN types, ~50 tree nodes) directly.
`effective_type()` (`retrieval/interaction_context.py`) is the identity function on
`element["type"]` — it does not reclassify anything. Week 4 introduced a lookup-time
reinterpretation here (genomic `ExternalEntity` elements tagged `role: "internal_staff"` were
treated as `Process` for this lookup only, raising genomic reachability from 17/99 to 70/99), but
that reclassification was never signed off by the advisor and was reverted in Week 8, restoring
the original 17/99 ceiling. Week 9 fixed the underlying mismatch at the source instead: genomic's
`dfd.json` (`scripts/build_genomic_dfd.py`) now types data-transforming staff (lab technicians,
clinicians, genetic counselors/physicians, bioinformaticists, researchers) as `Process` directly,
matching what they structurally are, rather than typing them `ExternalEntity` and patching the
mismatch at lookup time. No scenario's `dfd.json` carries a `role` field anymore, and genomic
reachability is 70/99 again — this time as a fact about the DFD, not a scoring-time hack.

**Step 2 — the reachability gate** (`generate.py:39-42`).

```python
if not ctx.valid:
    print(f"{tag}: skipped (invalid interaction, no Process mediates)")
    continue
```

If the flow's `(effective source type, effective destination type)` pair isn't one of the
mapping table's 5 valid rows (every valid row requires a `Process` on at least one side — an
`ExternalEntity` is by definition outside the system and a `DataStore` is inert), **the LLM is
never called for this flow.** This is the exact mechanism `eval/reachability.py` reproduces to
classify a gold threat as `structurally_unreachable` — it isn't a heuristic, it's the same check.

**Step 3 — prompt construction** (`generate.py:43`, `generation/prompt.py:18-34`).

`build_grounded_prompt()` inlines `ctx.as_prompt_block()` — the applicable threat types, their
S/fl/D assessment positions, and every relevant tree node's id + title + description — directly
into the prompt as an explicit, labeled list, then instructs the model to pick only from what's
listed. Concretely, for KidsTube's `DF1` (`Parent User (EE) -> Authentication Service (Process)`),
the model receives all 7 threat types' full node lists (51 nodes total for this interaction pair)
before being asked to decide which ones genuinely apply. Example (abbreviated):

```
Interaction: ExternalEntity -> data flow -> Process
Applicable LINDDUN threat types and positions (S=source, fl=flow, D=destination):
  - L (Linking): assess at S, fl, D
  - I (Identifying): assess at S, fl, D
  ...
Relevant threat-tree nodes to consider:
  L (Linking):
    L.1.1 — Unique identifier: Linking based on an identifier that is unique...
    L.2.1.1 — Quasi-identifier combining data of a single individual: ...
    ...
Instructions:
- For each applicable threat type listed above, decide whether a genuine threat exists for
  THIS flow, using only the flow description and context given. Do not pad the list...
- tree_node must be one of the node ids listed above under the chosen threat_type.
```

The model is explicitly told not to pad the list, and that `tree_node` must come from the
provided set — it isn't free to invent a node id.

## RAG pipeline (genuine retrieval-augmented generation)

**Step 1 — retrieval** (`generate.py`, `mode == "rag"` branch; `retrieval/index.py:64-87`).

```python
query = build_flow_query(flow, elements_by_id)   # generation/prompt.py
hits = retriever.search(query, k=config.TOP_K, source="linddun", exclude_kinds=["gold_threat"])
```

`build_flow_query()` turns the flow into the same source/destination/description text every mode
sees, phrased as a query string (e.g. `"Parent User (ExternalEntity) -> Authentication Service
(Process): parent registration (email, password, name, govt ID, six-digit code)"`). The retriever
embeds that query and does hybrid dense-cosine + keyword-overlap top-k search over the **same
`linddun` corpus** the deterministic mode's `mapping_table.json`/`threat_trees.json` are drawn
from — restricting to `source="linddun"` isolates *retrieval mechanism* as the only variable
against the deterministic `grounded` mode, rather than also changing *what knowledge is available*.
`exclude_kinds=["gold_threat"]` is defense-in-depth against gold-standard leakage; the `source`
filter alone already excludes it, since gold-standard chunks only exist under the `scenarios`
corpus.

**Step 2 — no reachability gate.** Unlike `grounded`, RAG mode never checks `mapping_table.json`
validity and never skips a flow — every flow gets exactly one LLM call, same as `ungrounded`. This
is deliberate: RAG's failure mode is retrieving the *wrong* passage, not correctly detecting an
*invalid* interaction (it has no concept of mapping-table validity at all), so gating it the same
way as `grounded` would conflate two different mechanisms. It also means RAG's reachability
accounting (via `eval/reachability.py`) looks like `ungrounded`'s, not `grounded`'s: no
`structurally_unreachable` flows from a skip that never happens.

**Step 3 — prompt construction** (`generation/prompt.py:build_rag_prompt`). The retrieved chunks
are inlined as numbered, cited context (mirroring `cli.py ask`'s context-block format), but the
instructions explicitly tell the model the context is *guidance*, not an authoritative menu —
unlike `build_grounded_prompt`'s "`tree_node` must be one of the node ids listed above," since
retrieval can't guarantee the right node was even retrieved.

## Ungrounded pipeline (ablation baseline)

**No lookup, no gate, no skip.** `build_ungrounded_prompt()` (`generation/prompt.py:37-48`) gets
only the bare flow description:

```
You are a privacy-threat-modeling assistant analyzing one DFD data flow using the LINDDUN
methodology from your own knowledge (no reference material is provided).

Flow DF1: Parent User (ExternalEntity, id EE1) -> Authentication Service (Process, id P1)
Flow description: parent registration (email, password, name, govt ID, six-digit code)

Identify any privacy threats for this flow. For each, classify it under a LINDDUN threat type
(L, I, Nr, D, Dd, U, or Nc) and give your best LINDDUN Pro threat-tree node id.
```

Every flow gets exactly one call — including the ones grounded mode would have skipped, since
there's no mapping-table check to skip against. Whatever threat types and tree-node ids the model
produces come entirely from what it learned about LINDDUN during training, not from this repo's
knowledge base.

## What's identical across all three

- **Output schema.** All three call the same `backend.generate_threats(prompt)` with the same
  forced tool-use schema (`generation/schema.py::THREAT_TOOL_SCHEMA`) — `originator_id`,
  `threat_type`, `tree_node`, `title`, `description`, `assumptions`, `severity`, `likelihood`,
  `uncertainty_note`. There is no free-text parsing in any mode; the model must return structured
  JSON matching this schema or the call fails.
- **The `mode` field** (`"grounded" | "rag" | "ungrounded"`, plus the legacy `grounded` bool) is
  stamped onto every resulting `GeneratedThreat` (`generate.py`) so downstream analysis can always
  tell which pipeline produced a given threat, even after all three are merged into one file.
- **Verification.** `generation/verify.py::verify_threat()` re-checks every generated threat —
  regardless of mode — against the knowledge base files directly, independent of what the model
  claims:
  - `node_valid` / `type_applicable`: does `tree_node` exist under `threat_type` in
    `threat_trees.json`, and is `threat_type` actually applicable at this flow's interaction per
    `mapping_table.json`? (This is where ungrounded's lack of guardrails shows up empirically —
    see below — and it's the same check that will show whether RAG's retrieval occasionally
    surfaces the wrong node.)
  - `location_valid`: does `originator_id` resolve to a real element/flow endpoint in `dfd.json`?
- **Evaluation.** All three modes' output files go through the identical `eval/match.py` →
  `eval/metrics.py` → `eval/reachability.py` pipeline, scored against the same
  `gold_standard_threats.json` — no eval-side changes were needed to add the `rag` mode, since
  scoring only ever looks at `flow_id`/`threat_type`/`tree_node`/`originator_id`, never at `mode`.

## What the grounded/ungrounded difference produces, empirically

From the first live runs (`WEEK6_REPORT.md`), Azure `gpt-5.4`, both scenarios — `rag` mode is new
and has no live numbers yet (see the open item this raises, below):

| | KidsTube grounded | KidsTube ungrounded | Genomic grounded | Genomic ungrounded |
|---|---|---|---|---|
| Flows called | 17/17 | 17/17 | 33/39 (6 skipped) | 39/39 |
| `type_applicable_rate` | 1.00 | 1.00 | 1.00 | 0.83 |
| `node_valid_rate` | 1.00 | 0.95 | 1.00 | 0.94 |
| Recall (reachable-adjusted) | 0.78 | 0.66 | 0.64 | 0.77 |

> **Historical table — the two Genomic columns don't reflect the exact mechanism behind current
> pipeline behavior, even though the reachability ceiling has landed back in the same place.**
> This table is Week 6's own reported numbers, generated while `effective_type()` reclassified
> `role: "internal_staff"` elements as `Process` at lookup time only (raising genomic's structural
> ceiling to 70/99). That reclassification was reverted in Week 8 without ever getting advisor
> sign-off (restoring 17/99), then superseded in Week 9 by a structural fix: genomic's `dfd.json`
> now types those staff elements `Process` directly, so the 70/99 ceiling is back — this time as a
> fact about the DFD rather than a scoring-time hack, and permanent rather than pending sign-off.
> The specific per-flow numbers in this table (e.g. "33/39 (6 skipped)") were measured against the
> Week 4-era hack and haven't been re-run against the Week 9 dfd.json, so treat them as
> illustrative of the mechanism, not current numbers — see `WEEK8_REPORT.md` and
> `storage/generated/genomic_*_eval.txt` for the most recent re-scored numbers.

Two things worth internalizing (true of the *mechanism*, independent of which specific numbers apply):

1. **Grounding's guardrail measurably prevents invalid assertions.** Genomic ungrounded asserts a
   LINDDUN type that the mapping table says isn't actually applicable at that interaction 17% of
   the time (`type_applicable_rate` 0.83 vs. grounded's 1.00) — it has no methodology context
   telling it a type doesn't apply there, so nothing stops it from guessing one that sounds
   plausible.
2. **Grounding's skip-if-invalid gate has a real recall cost, not just a precision benefit.**
   Genomic grounded structurally cannot produce a threat for the 6 skipped flows — it never calls
   the LLM on them at all. Ungrounded, having no such gate, still gets queried on those flows and
   coincidentally matches some of the gold threats sitting there. This is why ungrounded's raw
   reachable-adjusted recall is *higher* on genomic (0.77 vs. 0.64) despite being measurably less
   reliable about what it asserts — grounding trades some coverage for verifiable correctness, and
   that trade should be stated explicitly rather than assumed away.

## The open question `rag` mode is built to answer

`rag`'s reachability profile should resemble `ungrounded`'s (every flow attempted, no skip-gate),
but its citation-quality profile is the unknown: does semantic retrieval over the *same* LINDDUN
KB the deterministic mode uses recover most of `grounded`'s citation-validity advantage, or does
top-k similarity search miss the right node/mapping-row often enough that it behaves more like
`ungrounded`? That comparison — not raw F1 — is the number this ablation exists to produce, and
it's the one prior LLM-LINDDUN papers don't report: PILLAR doesn't run an ungrounded ablation at
all, and PriMod4AI runs RAG but never compares it against a no-retrieval or deterministic-lookup
baseline on the same scenarios.

## Last stage: manual FP adjudication (`eval/adjudicate.py`)

Every precision number reported above (`FP`, `precision`) treats every generated threat that
didn't match a gold threat as wrong. That's an overstatement: our gold standards are curated
catalogs (KidsTube from a human threat-modeling exercise, genomic from NIST's published analysis,
the rest author-constructed), not exhaustive enumerations of every valid threat a system could
have. Some "false positives" are threats the model found that the gold standard simply never
catalogued — the abstract's "zero-slot FP" problem. There's no deterministic KB lookup that can
tell spurious apart from valid-but-uncatalogued the way `generation/verify.py` checks a citation;
it's a human judgment call, so this stage is deliberately **not** LLM-automated — a model grading
its own (or another model's) output would just relocate the self-report-vs-verified problem this
whole project exists to avoid.

`eval/adjudicate.py` turns match.py's FP count into concrete, reviewable items:

1. **`build_worklist()`** resolves each unmatched generated threat's flow/source/destination names
   and citation-verification result from `dfd.json`, and writes them to
   `storage/adjudication/<scenario>_<mode>.json`. Reviewing every FP is the default (`n=None`); a
   smaller `--n` samples a reproducible (seeded) subset instead — the worklist is additive/resumable,
   so a second, larger `--n` tops it up without disturbing labels already given.
2. **`review_cli()`** is a terminal loop, one unlabeled item at a time, saving after every answer.
   Each item is labeled **spurious** (not a real threat), **valid_uncatalogued** (a real threat the
   gold standard missed), or **borderline** (unclear), plus an optional free-text note.
3. **`human_corrected_precision()`** turns labels into a corrected point estimate: `spurious`
   threats stay FPs, `valid_uncatalogued` threats move to the TP side, `borderline` splits 50/50 for
   the single-number estimate (the full spurious/valid/borderline breakdown is reported alongside so
   a reader can recompute either bound). If only a sample was labeled, the sample's split is
   extrapolated across the full FP count — reported as an estimate, not exact, unless every FP was
   reviewed (`is_full_review=True`).

`python cli.py eval` automatically looks for a worklist matching the scenario+mode of whatever
`--generated` file was scored and prints `precision_corrected` alongside the existing (conservative
lower-bound) `precision_raw` if one exists with at least one label; otherwise it prints the exact
`python cli.py adjudicate ...` command needed to start one. Run standalone:

```
python cli.py adjudicate --scenario kidstube --generated storage/generated/kidstube_grounded.json           # review every FP
python cli.py adjudicate --scenario kidstube --generated storage/generated/kidstube_grounded.json --n 20     # review a sample of 20
python cli.py adjudicate --scenario kidstube --generated storage/generated/kidstube_grounded.json --report-only  # no prompts, just print current status
```
