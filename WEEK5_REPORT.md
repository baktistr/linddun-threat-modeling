# Week 5 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 5
**Author:** Bakti Satria Adhityatama

## Goal for Week 5

Per advisor discussion (Hana), descope the regulatory-citation/"compliance analysis" feature and re-center the project's research question on a broader claim, then act on three follow-ups: come up with new test scenarios beyond the current two, design a deeper gap-analysis pass over the existing scenarios, and drop the regulatory-citation grounding entirely rather than continuing to extend it.

## Research question, restated

The project's original abstract framing (`WEEK3_REPORT.md`) was "traceable, regulation-grounded privacy threat modeling with LLMs" — regulatory citation was one of two headline claims, alongside traceability. That framing is now too narrow. The question this project answers going forward is:

**Can an LLM, grounded in the LINDDUN Pro methodology, help a privacy expert conduct a LINDDUN-based privacy risk analysis they can trust?**

Traceability (every generated threat citing a specific LINDDUN methodology node and DFD location, independently verified rather than self-reported) remains central — it's the mechanism that makes "trust" checkable. Regulatory grounding was always a narrower, additive claim layered on top (see `WEEK4_REPORT.md` open item #5: the regulatory KB was "a curated subset... scoped to what these two scenarios need, not an attempt at legal completeness"), and dropping it doesn't touch the traceability mechanism at all.

## Completed

**Regulatory-citation grounding removed entirely.** This was not a separate pipeline stage — it was a third citation field (`regulatory_citation`) generated in the same LLM tool-call and verified in the same function as the LINDDUN-node and DFD-location citations, so removal was a set of narrow, parallel edits rather than deleting an isolated module:

- `generation/schema.py` / `generation/verify.py`: dropped the `regulatory_citation` field, its tool-schema entry, and the `regulation_valid`/`regulation_relevant` checks. `node_valid`, `type_applicable`, and `location_valid` are untouched — traceability is now a two-way citation (methodology node + DFD location) instead of three-way.
- `generation/prompt.py` / `generation/generate.py`: dropped the regulatory retrieval call and prompt block from grounded generation.
- `eval/metrics.py`: dropped `regulation_valid_rate`/`regulation_relevant_rate` from citation-correctness reporting.
- `cli.py` / `config.py`: dropped the `regulations` retrieval source and KB corpus entry. Also split the scenario-choice lists into `GENERATE_SCENARIOS` (includes `smart_home`, which has no gold standard) and `EVAL_SCENARIOS` (only `kidstube`/`genomic`) — this incidentally fixes a latent bug where `cli.py eval --scenario smart_home` would crash with `FileNotFoundError`.
- Deleted `knowledge_base/regulations/` (the COPPA/GDPR/CCPA/HIPAA/GINA/Common Rule/CLIA KB) and `knowledge_base/scenarios/telehealth_demo/` (a demo scenario built specifically to showcase regulatory citations — its other purpose, demoing the `effective_type` reachability fix, is already proven at real scale on the genomic scenario and documented in `WEEK4_REPORT.md`, so nothing unique was lost).
- Index rebuilt (272 → 240 chunks); `tests/test_kb.py` (32 checks) and `tests/test_generation.py` (136 checks) both pass.
- `README.md` and `REFERENCES.md` updated: the target-pipeline diagram no longer routes through a "regulatory" stage, the opening framing states the broader research question above, and `REFERENCES.md` §H (regulatory sources) is removed.

`WEEK1`–`WEEK4_REPORT.md` are left unedited as historical record — in particular, `WEEK4_REPORT.md`'s "How grounded regulation citation actually works" section (its grounded-vs-ungrounded citation-accuracy table: 24%/77% valid vs. 80%/5% on the `smart_home` demo) was the project's strongest empirical result to date at the time it was written. That result is not wrong or retracted — it demonstrated that grounding makes citation *more conservative and more accurate*, a finding that generalizes beyond regulatory citations specifically — but the regulatory-citation mechanism it was measuring is no longer part of the pipeline, so the result should be read as historical evidence for the grounding hypothesis, not as a live feature.

## Open items / caveats — flagged for advisor sign-off

1. **The `effective_type` reclassification (Week 4, genomic 17/99 → 70/99 reachable) is still unsigned-off**, carried over from `WEEK4_REPORT.md` open item #1 — this pivot didn't touch that decision.
2. **Non-compliance (`Nc`) remains a LINDDUN threat type the model can emit**, just without a regulatory-provision citation attached. Whether `Nc`-type threats are still meaningfully gradable without that citation (vs. treated the same as any other category in `eval/metrics.py`'s per-category P/R/F1) hasn't been separately assessed — flagging in case it's worth a closer look once live `Nc` numbers exist.
3. **Next: new test scenarios, deeper gap analysis.** Both are scoped and sequenced in the working plan but not yet executed — see Plan for Week 6.

## Still pending with advisor (carried from Weeks 1–4)

Target paper/workshop venue; IP/publication scope; API budget confirmation; partner coordination on the shared canonical-DFD schema; sign-off on the `effective_type` internal-staff reclassification (Week 4 open item #1) before the 70/99 genomic reachability number is used in any paper claim.

## Plan for Week 6

1. First-ever live `generate`+`eval` runs (grounded + ungrounded, kidstube + genomic) under the now-final schema, since no P/R/F1 report has ever actually been saved to disk for either gold-standard scenario.
2. Build a reachability-status breakdown (`eval/reachability.py`) that classifies every unmatched gold threat as structurally unreachable (skipped before any LLM call, per `mapping_table.json`) vs. reachable-but-missed (a real recall failure) — this turns the hand-counted genomic 70/29 split into a runnable, regression-checkable number.
3. Add a tree-node/subcategory-level breakdown to `eval/metrics.py` to see where misses concentrate below the top-level LINDDUN category.
4. Start research/feasibility-checking candidate new scenarios (mixing NIST-authoritative-style and real-open-source-code-style sourcing), targeting 2-3 beyond the current KidsTube + genomic pair.
