# Grounded vs. Ungrounded Generation Pipeline

Reference documentation for how threat generation actually works, mechanically, in both modes.
(For *what the two modes measured* on real data, see [WEEK6_REPORT.md](WEEK6_REPORT.md).)

## At a glance

Both modes answer the same question — "what LINDDUN privacy threats apply to this one DFD data
flow?" — with the same LLM, the same forced structured-output schema, and the same independent
verifier downstream. The only difference is what the model is told *before* it answers.

```
                    ┌─────────────────────────────────────────────────────────┐
                    │  for each flow in scenario's dfd.json (one at a time)    │
                    └─────────────────────────────────────────────────────────┘
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    │                                                 │
              grounded=True                                    grounded=False
                    │                                                 │
                    ▼                                                 ▼
     get_interaction_context(src, dst)                    (no lookup at all)
     against mapping_table.json                                       │
                    │                                                 │
        ┌───────────┴───────────┐                                     │
        │                       │                                     │
   ctx.valid==False        ctx.valid==True                            │
        │                       │                                     │
        ▼                       ▼                                     ▼
   SKIP -- no LLM call   build_grounded_prompt():          build_ungrounded_prompt():
   (structural ceiling)  flow text + applicable            flow text ONLY --
                          types + tree-node list            no methodology context
                          inlined, explicit                 at all
                                │                                     │
                                └───────────────┬─────────────────────┘
                                                 ▼
                                  backend.generate_threats(prompt)
                                  forced tool-call, THREAT_TOOL_SCHEMA
                                  (schema.py) -- same schema both modes
                                                 │
                                                 ▼
                                  GeneratedThreat.from_dict(...)
                                  grounded=True/False tagged on each threat
                                                 │
                                                 ▼
                                  verify_threat() -- independent check
                                  against threat_trees.json / mapping_table.json
                                  / dfd.json (same verifier, both modes)
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
   (name, type, and — for genomic only — `role`).

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
`effective_type()` (`retrieval/interaction_context.py:80-89`) is the one interpretive layer on
top: it reclassifies genomic `ExternalEntity` elements tagged `role: "internal_staff"` as
`Process` for this lookup only (the Week 4 fix that raised genomic reachability from 17/99 to
70/99) — `element["type"]` itself is never modified.

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

## What's identical between the two

- **Output schema.** Both call the same `backend.generate_threats(prompt)` with the same forced
  tool-use schema (`generation/schema.py::THREAT_TOOL_SCHEMA`) — `originator_id`, `threat_type`,
  `tree_node`, `title`, `description`, `assumptions`, `severity`, `likelihood`,
  `uncertainty_note`. There is no free-text parsing in either mode; the model must return
  structured JSON matching this schema or the call fails.
- **The `grounded` flag** is stamped onto every resulting `GeneratedThreat` (`generate.py:52`) so
  downstream analysis can always tell which pipeline produced a given threat, even after both are
  merged into one file.
- **Verification.** `generation/verify.py::verify_threat()` re-checks every generated threat —
  grounded or ungrounded — against the knowledge base files directly, independent of what the
  model claims:
  - `node_valid` / `type_applicable`: does `tree_node` exist under `threat_type` in
    `threat_trees.json`, and is `threat_type` actually applicable at this flow's interaction per
    `mapping_table.json`? (This is where ungrounded's lack of guardrails shows up empirically —
    see below.)
  - `location_valid`: does `originator_id` resolve to a real element/flow endpoint in `dfd.json`?
- **Evaluation.** Both modes' output files go through the identical `eval/match.py` →
  `eval/metrics.py` → `eval/reachability.py` pipeline, scored against the same
  `gold_standard_threats.json`.

## What the difference produces, empirically

From the first live runs (`WEEK6_REPORT.md`), Azure `gpt-5.4`, both scenarios:

| | KidsTube grounded | KidsTube ungrounded | Genomic grounded | Genomic ungrounded |
|---|---|---|---|---|
| Flows called | 17/17 | 17/17 | 33/39 (6 skipped) | 39/39 |
| `type_applicable_rate` | 1.00 | 1.00 | 1.00 | 0.83 |
| `node_valid_rate` | 1.00 | 0.95 | 1.00 | 0.94 |
| Recall (reachable-adjusted) | 0.78 | 0.66 | 0.64 | 0.77 |

Two things worth internalizing:

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
