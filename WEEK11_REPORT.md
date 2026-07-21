# Week 11 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 11
**Author:** Bakti Satria Adhityatama

## Goal for Week 11

Close the two items the Week 10 report named as the highest-value gaps in the source→DFD adapter:
build the **`llm_naive` arm** (M3) — the open `file:line` citation ablation without which "every
citation number in this report is vacuous" — and run **threats end-to-end on the derived DFD** (M4),
scored against the hand baseline restricted to the same anchorable subset. Both against
`Privacy-Engineering-CMU/KidsTube-PE` at the pinned commit `8e98a1f`.

## Completed

**Built the `llm_naive` adapter arm (M3): raw source in, open `file:line` out, no confabulation
guard.** This is the adapter-level analogue of the pipeline's `ungrounded` condition — the single
variable that separates it from the `llm` arm is that the model reads the raw repository and
self-reports `{file, line}` instead of reading resolved facts and picking a fact id from a closed
vocabulary. Everything else (element types, naming/granularity guidance, the two-call
elements→flows seam) is held identical, so any difference is attributable to grounding, not prompt
drift. Two deliberate absences are the experiment: no closed vocabulary (a `file:line` can point
anywhere), and no confabulation guard (nothing drops an element for a bad citation). New code:
`synthesize_llm_naive` and naive prompts in `adapters/synthesize.py`, naive tool schemas in
`adapters/schema.py`, wired through `cli.py derive --mode llm_naive --source-root` and
`scripts/run_adapter_arms.py`. It is the one arm that cannot run from the committed facts alone.

**Extended the verifier to independently re-derive open citations (`adapters/verify_dfd.py`).** The
closed arm's `citations_resolvable` is ~1.00 by construction and therefore vacuous; the whole point
of the naive arm is a number that can drop. For an open citation the verifier now splits two
distinct failure modes, mirroring the closed arm's id-in-vocabulary vs. construct-re-derivable
split: `citations_resolvable` = the cited `file:line` is a real source location (file exists, line
in range), checked against the raw source; `facts_present` = a construct is actually re-parsed at
that exact line. Without `--source-root` both report `not_checked`, never a fake pass — an
unavailable check that reads as 1.00 is the easiest way to fake the result this project exists to
refuse. `adapters/align.py` was extended to resolve `file:line`→fact at scoring time, so the naive
DFD is scored by the same provenance-key machinery as the closed arms, never by element name.

**The M3 finding — the open vocabulary is where citation validity collapses (1.00 → 0.25), and its
decomposition is the argument for fact-id citations** (n=3, Azure `gpt-5.4`, vs the `llm` arm):

| citation metric | `llm` (closed) | `llm_naive` (open) |
|---|---:|---:|
| citations_resolvable (real source line) | 1.00 | **1.00 ±0.00** |
| evidence_type_consistent | 1.00 | 0.69 ±0.03 |
| facts_present (exact construct line) | 1.00 | **0.27 ±0.03** |
| **all_valid** | **1.00** | **0.25 ±0.03** |

The open citations always point at a **real** source line — the model never fabricated a path — but
land on the *exact* line the extractor pins a construct to only 27% of the time. So they are "real
but not deterministically verifiable": near the right code, rarely the precise construct, so
accepting them would need fuzzy line-matching, which reintroduces exactly the judgment the closed
fact-id vocabulary removes. That is the argument for the fact-id design, now measured rather than
asserted. The naive arm also over-produces (≈45 flows vs. the hand DFD's 17) and its element/flow
quality drops (element precision 0.35 vs `llm` 0.77).

**One honest correction to a Week 10 prediction.** Week 10 predicted the guard-free naive arm would
finally emit P4 (AI Recommendation Engine) and EE3 (Third-Party Advertisers), the two planned
features in no code. It did **not**: `structurally_underivable` held at 2 every run. The model
over-decomposed *implemented* code ("MongoDB Database Server", "Authorization Middleware", "Image
Upload Handler") rather than inventing the planned features. The prediction was wrong; the result is
reported as it came out.

**Ran threats end-to-end on the derived DFD (M4).** `cli.py generate --scenario kidstube_derived` in
all three grounding modes (grounded 144 threats, rag 129, ungrounded 161) on the committed
`facts_only` derived DFD (14 elements, 27 flows). `scripts/compare_derived_threats.py` scores the
hand baseline **restricted to the same anchorable gold subset**: 27 of 41 gold threats anchor to a
flow the derived DFD has; the other 14 (2 planned-feature ceiling flows DF13/DF14 + 6 adapter-miss
flows DF4/5/7/8/12/16, kept in separate `_meta` fields so the two causes are never conflated) are
`unresolved_location` and stay out of the recall denominator, so the comparison is apples-to-apples.
Recall-only by design (restricting the gold turns a match on an excluded threat into a false
positive, so precision on a restricted gold is not meaningful).

**The M4 finding — deriving the DFD from source costs recall but not citation validity,** exactly
`ABSTRACT.md`'s claim that traceability's benefit concentrates in citation reliability rather than
raw recall:

| Mode | hand DFD recall (on 27) | derived DFD recall (on 27) | citation all_valid (hand → derived) |
|---|---:|---:|---:|
| grounded | 0.70 | **0.52** | 1.00 → 1.00 |
| rag | 0.41 | 0.44 | 0.96 → 0.99 |
| ungrounded | 0.59 | 0.48 | 0.92 → 0.94 |

Grounded recall on the same 27 gold threats falls 0.70 → 0.52 (the coarser `facts_only` modeling
misses ~5 more), while threat-level citation validity is preserved (`location_valid` stays 1.00 —
the derived DFD is a valid anchor target). The grounding order grounded > ungrounded > rag holds on
both DFDs.

**Two bugs caught mid-run and fixed, both with the failure surfaced *before* it can burn a live
call.** (a) A literal `{file, line}` in the flows prompt was misread by `str.format`, raising
`KeyError` *after* the elements call had already been billed; fixed by escaping, plus an offline
prompt-build test (`test_naive_prompts_build_without_format_errors`) that assembles both naive
prompts with no LLM so that whole class of bug is caught for free. (b) The open vocabulary made the
model emit sprawling citation lists that blew the token budget, and Azure truncates mid-JSON with no
error — the `JSONDecodeError` read as a model failure rather than a budget one. Fixed by capping
citations to a representative handful in the prompt, raising the naive budget to 16000, and turning
Azure length-truncation into a clear budget `RuntimeError` in `generation/llm_backend.py`.

**Consolidated all results into `RESULTS_2026-07-21.md`** — LINDDUN threat generation (3 scenarios ×
3 modes), the KidsTube adapter arms (`facts_only`/`llm`/`llm_naive`), M4, and genomic PANOPTIC for
reference. Recomputing the LINDDUN scores from the committed generated files (eval is deterministic)
surfaced a small arithmetic slip in `RESULTS_2026-07-14.md`: KidsTube RAG false positives are 59,
not 58 (82 gen − 23 TP).

**Test suite: 411 offline tests, all passing** (test_kb 77, test_generation 227, test_adapter 107,
up from 90). New adapter tests cover the absent confabulation guard, open-citation verification (the
0.27 drop), the M4 anchorable-subset accounting, and the prompt-build guard.

## Open items / caveats

1. **`llm_naive` is n=3 on one codebase.** The 0.25 all-valid is stable across runs (±0.03), but the
   `facts_present = 0.27` figure is sensitive to the exact-line matching convention: a span-tolerant
   check ("did the citation fall within a construct's `[line, end_line]`?") would raise it and is
   arguably fairer. Reported strict here because the closed vocabulary IS exact; the span-tolerant
   variant is a worthwhile follow-up to bracket the true rate.
2. **M4 used the `facts_only` derived DFD.** The `llm` arm produces a different (larger, ~110-flow)
   DFD; generating threats on *that* DFD, and on the `llm_naive` DFD, would show whether the recall
   cost tracks the adapter arm's own quality. Not yet run.
3. **The `llm` arm draws ≈110 flows** (verified against the stored DFD), far more than `facts_only`
   (27) or the hand DFD (17). Flow precision 0.61 absorbs it via granularity splits, but the raw
   over-production is worth a look — it is the flip side of the naive arm's own 45-flow sprawl.
4. **Precision on the derived side is unrestricted and low** — the derived generation over-produces
   (144/129/161 vs. hand 118/82/109). Manual FP adjudication (`cli.py adjudicate`, built Week 9)
   still has never run on any scenario, so no `precision_corrected` exists anywhere.

## Still pending with advisor (carried from Weeks 1–10)

Target paper/workshop venue; IP/publication scope. **Family Location and Smart Home gold standards
still need independent review before their numbers are cited as comparable to KidsTube.**
`ABSTRACT.md` remains untracked: it claims six scenarios where four exist, and presents genomic as a
held-out **LINDDUN** generalisation test though only PANOPTIC genomic results exist (the decided
reword to PANOPTIC-only is still unmade). Its code→DFD claim can now honestly read as built and
evaluated across three arms.

## Plan for Week 12

Generate threats on the `llm` and `llm_naive` derived DFDs (M4 open item #2) to tie the DFD-level
adapter quality to downstream threat recall. Add the span-tolerant citation-verification variant to
bracket the naive arm's `facts_present`. If time allows, the first real FP-adjudication pass, now
with three worklists (hand, derived, and the adapter's own unmatched elements).
