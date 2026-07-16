# Week 10 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 10
**Author:** Bakti Satria Adhityatama

## Goal for Week 10

Build the **source-code → DFD adapter** — the `⬜ not built` row `README.md` has called "the largest
piece; code→DFD is the research-hard part" since Week 3, and the one `ABSTRACT.md:9` already claims
in the present tense ("our pipeline accepts either a structured DFD or a source-code repository").
Target: `https://github.com/Privacy-Engineering-CMU/KidsTube-PE`, the only scenario with both a real
codebase and a hand-authored DFD, so the adapter has ground truth to be scored against.

The Week 9 plan named manual FP adjudication as this week's work. It was deferred: the adapter was
prioritised after reviewing what `ABSTRACT.md` claims versus what exists. Adjudication remains
built, tested, and unrun.

## Completed

**Fixed a silent scoring bug that would have made the whole milestone unmeasurable.**
`eval/match.py:64` chose its gold-anchoring strategy with `flow_anchored = scenario == "kidstube"`.
Any other scenario took the location-anchored branch, which needs `dfd_source_id`/`dfd_destination_id`
— and KidsTube's gold has **0/41** of those (it anchors via `interaction: "EE1-P1 [DF1]"`). So a
`kidstube_derived` scenario resolved every gold threat to `None` and scored **P=R=F1=0.00 with no
error raised**, indistinguishable from a broken adapter. `gold_location_convention()` now reads the
convention off the catalog; verified as an exact discriminator on all four scenarios (kidstube 41/41
`[DFn]`, 0 `dfd_source_id`; genomic/family_location/smart_home the precise inverse). All 12 stored
eval reports reproduce byte-identically after the change. Same fix threaded through
`eval/reachability.py` and `eval/run_eval.py`, whose "Appendix F Figure 11" note also misfired for
flow-anchored scenarios.

**Formalised the canonical DFD schema** (`adapters/schema.py`), the second standing `⬜` row, as a
*validator* rather than a document — a schema that is prose is a wish; a schema that is a function
with a test over every `dfd.json` in the repo is a contract that cannot drift from the files it
describes. v1 (the four hand-authored DFDs) is a strict subset of v2 (adds optional `provenance`,
`trust_boundaries`, `_meta.derived_from`), so all four validate **unmodified** — that is the
backward-compatibility proof, asserted in `tests/test_kb.py`. Every existing consumer reads only
explicit keys, so a v2 DFD runs the existing pipeline unchanged.

**Built the adapter as three passes, mirroring the project's own thesis one level up.**
`adapters/extract.py` + `resolve.py` produce deterministic code facts, each with a `file:line`;
`adapters/synthesize.py` turns facts into a DFD; `adapters/verify_dfd.py` independently re-derives
every citation. The load-bearing decision: **citations are `fact_id`s, not raw `file:line`.** A
model emitting `server.js:58` could fabricate a plausible line number, putting us back to checking a
self-report — exactly what `generation/verify.py` exists to refuse. An id from a closed, provided
vocabulary either resolves or does not, and the `file:line` behind it came from a parser, so it is
true by construction. Same move `build_grounded_prompt` already makes with `tree_node`.
`generation/llm_backend.py` gained a generic `call_tool(prompt, tool_schema, max_tokens)`;
`generate_threats` is now a thin wrapper with unchanged behaviour (227 generation tests still pass).
The 2000-token cap became a parameter — a whole-DFD payload truncates mid-JSON on Azure with no
error, which reads as a model failure rather than a budget one.

**The extractor defeats every naming trap in this codebase, and the shortcut demonstrably fails.**
`backend/models/Parent.js:120` exports `mongoose.model('User', userSchema)` → collection `users`
(= hand DS1); the filename says "Parent". `server.js:57` mounts `routes/children.js` at
`/api/subprofiles`. `mongoose.connect(MONGODB_URI)` is a variable, resolved through its const
binding. The frontend calls `/subprofiles`, not `/api/subprofiles` — the prefix lives in a
`NODE_ENV` ternary in `api/config.js`, whose branches are collected and their common suffix taken
rather than a deployment guessed. Express dispatch is reproduced in registration order, so
`GET /api/subprofiles/approved-videos` hits the literal route registered at line 10 rather than the
`/:id` at line 132. **The tempting shortcut is not merely risky, it is wrong here:** `routes/auth.js`
binds `const Child = require('../models/Child')`, but that module exports model `'ChildProfile'` —
pluralising the local name yields `childs`; only the full binding chain yields `childprofiles`.
Mongoose's pluralisation is reproduced faithfully from `mongoose-legacy-pluralize`'s rule table
rather than approximated with `+s`. 492 facts (389 literal, 103 derived) from 36 files, committed at
source commit `8e98a1f` so every downstream stage runs from a clean clone with no tree-sitter and no
checkout — the same pattern as `scripts/data/genomic_figure11_raw.json`.

**Three arms, mirroring the repo's grounded/RAG/ungrounded ablation.** `facts_only` (no LLM, the bar
the LLM must beat), `llm` (closed fact-id vocabulary), `llm_naive` (open `file:line`, **not yet
built**). Shipping only the LLM arm would leave no way to show it earned its place. `facts_only`
alone finds **every element the code implements**.

**Results (`facts_only` deterministic; `llm` n=3, Azure `gpt-5.4`, `storage/derived/`):**

| Metric | facts_only | llm (n=3) |
|---|---:|---:|
| Element precision | **0.79** | 0.77 ± 0.06 |
| Element recall (derivability-adjusted) | **1.00** | **1.00** ± 0.00 |
| Flow precision | 0.33 | **0.61** ± 0.15 |
| Flow recall (derivability-adjusted) | 0.60 | 0.64 ± 0.28 |
| Element citation all_valid | 1.00 | 1.00 ± 0.00 |
| Flow citation all_valid | 1.00 | 0.92 ± 0.05 |
| Ceiling held at 2 (EE3/P4) | ✅ | ✅ every run |

**The LLM does not beat the deterministic baseline on elements** — 0.77 ± 0.06 vs 0.79, recall tied
at 1.00, inside the noise band. Reported rather than tuned away, per the pre-registered decision to
treat that outcome as the finding. Flow precision improves genuinely (0.33 → 0.61), but flow recall
is 0.64 **± 0.28** (run 2: 0.33, run 3: 0.87) — the spread exceeds the effect, so it is not yet a
measurement. What the LLM demonstrably buys is **naming**: "Authentication Service", "Parent User",
"Users Database" versus `/api/auth`, `parent (actor role)`. Both citation numbers are 1.00 *by
construction* in the `llm` arm (an element citing no resolvable fact is dropped, not warned about),
so they carry no information until `llm_naive` exists to contrast them against.

**Derivability ceiling reporting** (`adapters/evaluate.py`), the DFD-level analogue of
`eval/reachability.py` and deliberately sharing its vocabulary: `structurally_underivable` ~
`structurally_unreachable`, `derivable_but_missed` ~ `reachable_but_missed`, `unresolved_key` ~
`unresolved_location`. P4 (AI Recommendation Engine) and EE3 (Third-Party Advertisers) — and so
DF13/DF14 — are marked "(planned)" in `system_description.md` and exist in no code, so the ceiling
is 10/12 elements and 15/17 flows. It is **computed from the `implemented` flags in
`adapters/data/kidstube_hand_keys.json`**, which transcribe the description's own markers — data,
not a constant. Elements align by *provenance key* (`mongo_collection:users`,
`route_mount:/api/auth`, `actor_role:parent`), never by name; the hand-side key map is authored once
beside the adapter so `knowledge_base/scenarios/kidstube/dfd.json` is never modified.

**The confabulation guard held all 3 runs, structurally rather than by instruction.** The model knows
this is a children's video platform and would flatter itself by emitting an AI engine and an ad
partner — the exact two elements in no code. Had they survived, `structurally_underivable` would
silently drop 2→0 and the ceiling analysis would die *in the direction favouring the adapter*. No
fact mentions them, so in the closed-vocabulary arm they are literally uncitable; `_accept_elements`
drops any element citing zero resolvable facts. `tests/test_adapter.py` asserts the count stays 2.
Zero rejections occurred in practice — the model never attempted it.

**Findings the adapter produced that the hand-authored DFD does not contain.** All three `llm` runs
independently emitted an **Administrator** actor, and `facts_only` found it too:
`backend/routes/users.js:115` is `router.get('/', auth, requireRole(['admin']))` — a paginated
listing of every user's name, email, and username, plus two further admin-only routes. That is an
actor with no element in the hand DFD and a bulk-PII-disclosure surface (textbook Dd/L) that the
41-threat gold standard never modeled. `/api/users` likewise has no counterpart process. Adjudication
labels, not assumption, will decide `spurious` / `valid_uncatalogued` / `granularity_split`;
`mongo_collection:tests` (from `test-server.js`, an `npm test` harness) is the one likely-spurious
element and was deliberately **not** hand-excluded, since skipping `*.test.js` by convention is
defensible a priori but excluding a specific file because its output was unwelcome is tuning to the
answer key.

**Full retest.** `tests/test_kb.py` (77), `tests/test_generation.py` (227), `tests/test_adapter.py`
(90) — 394 total, up from 298. All 12 stored eval reports byte-identical. Retrieval corpus unchanged
at 411 chunks: `ingestion/loader.py` now skips `scenarios/*_derived/`, without which
`kidstube_derived`'s 41 re-anchored gold threats would have added near-duplicate `gold_threat`
chunks and shifted TF-IDF idf under `search`/`ask`/`test_retrieval_quality`.

## Open items / caveats

1. **`llm_naive` is not built, and until it is, every citation number in this report is vacuous.**
   1.00 in the `llm` arm is a property of the plumbing, not of the model: the closed vocabulary makes
   failure impossible. The claim only acquires content in contrast to an arm where the model emits
   `file:line` freely. Without it the adapter has a `grounded` with no `ungrounded` — precisely the
   gap this project criticises PILLAR for. Highest-value remaining item.
2. **Three bugs were found in this week's own measuring apparatus, two of them false passes.**
   (a) Element alignment was strictly 1:1, so `backend/uploads` and `backend/uploads/images` could
   not both map to hand DS4 — the loser became a false positive *and* silently cost DF15, whose flow
   projects through it (fixed: precision 0.71→0.79, flow recall 0.53→0.60; prefix-keyed kinds now
   match many-to-one, exact-keyed stay 1:1). (b) The M0 gate kept reporting green after
   `kidstube_derived` stopped being an identity copy, because both DFDs number flows `DF1..DFn` and
   the ids collided numerically while meaning different things; it now builds its fixture in-memory
   and asserts the real invariant (a scenario's *name* must not change its score). (c)
   `evidence_connects_endpoints` conflated "does the evidence link these two elements" with "does the
   arrow point the way data moves", scoring 36 of run 3's flows as citation failures. They were not:
   the model draws a read as Process→DataStore (the *query* direction) — **and so does the hand DFD**,
   whose DF9 is "P2→DS3, store/**retrieve** video metadata". The stricter reading would have
   penalised the model for agreeing with the ground truth. Split apart: integrity 0.92,
   `direction_matches_evidence` 0.38, reported and never folded into a correctness rate. Worth
   writing up: a verification layer can manufacture a false failure by encoding its author's
   modeling convention as ground truth.
3. **`facts_only` misses 6 implemented flows, with three distinct causes.** Four child-facing
   (DF4/DF5/DF8/DF12): it can only infer an actor→process edge where an explicit `requireRole`
   exists, but KidsTube's child login is a *public* route and `children.js` guards children with an
   in-handler `userType !== 'child'` check. DF7: it emits one `P2→DS1` write where the hand DFD draws
   two semantically distinct flows on the same edge (DF7/DF10), so one necessarily loses the tie —
   8 gold threats hang on that distinction. DF16: the hand DFD draws `P1 → DS5` (JWT to localStorage),
   but the code writes it from `frontend/src/contexts/AuthContext.js`; no fact connects the backend
   to localStorage, so the adapter leaves it an island rather than invent the edge. **The hand DFD's
   abstraction is correct analyst modeling that no deterministic checker can confirm** — the sharpest
   illustration that this design buys citation integrity, not modeling correctness.
4. **Scope: n=1 codebase, one stack.** `extract.py`/`resolve.py` are ~90% pattern-matched to
   conventional Express/Mongoose/React idioms and return ~zero facts on Django/Rails/Prisma —
   silently, since there is nothing to match. Claim "a source→DFD adapter for conventional
   Express/Mongoose apps, evaluated on one codebase against one hand-authored DFD", no more. The
   generalisable contributions are the schema, the fact-id citation discipline, and the
   derivability-ceiling reporting — not the JS patterns.
5. **The Mongoose collection name is the one deterministic fact the verifier cannot verify.**
   `"users"` appears in no source line; it is a Python re-implementation of a JS library's rules.
   Marked `derived=True` with a `from_fact_id` back to a real line, but nothing *checks* it — a wrong
   pluralisation would surface only as an alignment miss, reading as an LLM failure rather than our
   bug. The single named gap in the "verified, not asserted" story.
6. **Verification is gold-free; evaluation is not.** `extract`/`derive`/`verify-dfd` need only the
   source, and were confirmed running end-to-end on a scenario with no hand DFD, gold standard, or
   key map. Recall/precision require ground truth by definition. This is the split between the
   experiment (KidsTube, where a human did the work) and the product (an arbitrary repo, where nobody
   has). `eval-dfd --against` is now required rather than defaulting to `kidstube`, which would have
   let someone score their own repo against this one's DFD and get a confident, meaningless number.
7. Carried from Weeks 8–9, still not done: manual FP adjudication has still never been run on any
   scenario (`storage/adjudication/` remains empty); coarse category-level PANOPTIC matching tier;
   PA04/PA06's zero-gold-coverage prompt fix; contamination probe on genomic's ungrounded results;
   `--strict` variants not re-run; **Family Location's and Smart Home's gold standards still need
   independent human review before their numbers are cited anywhere.**
8. `storage/derived/` (adapter run output) is committed for auditability, matching
   `storage/generated/`'s existing treatment — the same undecided gitignore question as Week 8 open
   item #5, now spanning three directories.

## Still pending with advisor (carried from Weeks 1–9)

Target paper/workshop venue; IP/publication scope; sign-off on the #10/#18 KidsTube
duplicate-scoring decision; whether Family Location/Smart Home are real evaluation scenarios or
demo-only pending review. **New this week:** `ABSTRACT.md` (still untracked) claims six scenarios
where four exist — two are reportedly prepared elsewhere — and presents genomic as a held-out
**LINDDUN** generalisation test, though Week 8 deleted genomic's LINDDUN results per direction and
only PANOPTIC results exist. The decision taken was to reword that sentence to PANOPTIC-only; the
edit is not yet made, so the abstract remains uncommitted rather than committed with a claim known to
be wrong. The abstract's code→DFD claim can now honestly read as built and evaluated rather than
present-tense fiction.

## Plan for Week 11

Build `llm_naive` (open `file:line` citations) — the ablation that gives every citation number in
this report its meaning, and the arm with no confabulation guard, where P4/EE3 are predicted to
finally appear. Then end-to-end: `generate --scenario kidstube_derived` in all three grounding modes,
scored against the hand baseline **restricted to the same anchorable subset** (14 of 41 gold threats
sit on flows the derived DFD has no counterpart for; `_meta` keeps the 2 ceiling flows and the 6
adapter misses in separate fields so the two are never conflated). If time allows: the first real
adjudication pass, now with the adapter's own unmatched elements as a second worklist.
