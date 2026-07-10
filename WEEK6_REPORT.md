# Week 6 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 6
**Author:** Bakti Satria Adhityatama

## Goal for Week 6

Close out the "deeper gap analysis" item from the Week 5 pivot: build tooling to distinguish real recall failures from threats the pipeline could never have produced, then run the eval pipeline live for the first time — for both scenarios, grounded and ungrounded — since no `cli.py eval` run had ever actually been executed and saved to disk before this week.

## Completed

**New reachability-status tooling (`eval/reachability.py`).** Classifies every unmatched gold threat as `reachable_but_missed` (a real recall failure — the flow was valid and generated, nothing matched), `structurally_unreachable` (the flow's element-type pair isn't in `mapping_table.json`, so `generate.py` skipped it before any LLM call), or `unresolved_location` (no single flow to anchor to). It reuses `generate.py`'s own `effective_type`/`get_interaction_context` check and a new shared `eval/match.py::resolve_gold_flow()` helper, so it can't silently drift from what the pipeline actually does. Validated against genomic's gold standard with zero threats generated (an isolated structural check): reproduces the **70 reachable / 27 structurally unreachable / 2 unresolved** split hand-counted in `WEEK3_REPORT.md`/`WEEK4_REPORT.md` exactly. Also added `eval/metrics.py::per_node_scores()` (tree-node-level breakdown, gated behind `cli.py eval --by-node`) and a `--out` flag so reports persist instead of only printing.

**Unexpected finding, offline, before any live run: KidsTube isn't fully reachable either.** 4 of its 36 gold threats (e.g. `"P3-DS2 [DF7/DF10]"`) describe a threat spanning *multiple* flows at once. The per-flow generation architecture can never produce a match for these regardless of model quality — no single per-flow prompt call can be anchored to more than one `flow_id`. This is a different root cause from genomic's mapping-table gap (interaction-*type* validity) but the same category of problem (architectural ceiling, not a recall failure). Classified as `unresolved_location`; baked into the test suite as a regression check.

**First-ever live generate+eval runs**, both scenarios, grounded and ungrounded (Azure Foundry `gpt-5.4`):

| | KidsTube grounded | KidsTube ungrounded | Genomic grounded | Genomic ungrounded |
|---|---|---|---|---|
| n_generated | 130 | 113 | 193 | 249 |
| TP / FP / FN | 25 / 105 / 11 | 21 / 92 / 15 | 45 / 148 / 54 | 67 / 182 / 32 |
| Precision / Recall / F1 | .19 / .69 / .30 | .19 / .58 / .28 | .23 / .45 / .31 | .27 / .68 / .39 |
| Citation all-valid rate | 1.00 | 0.95 | 1.00 | 0.79 |
| Recall, reachable-adjusted | 0.78 | 0.66 | 0.64 | 0.77 |

Raw reports (per-category, per-node, reachability breakdown) saved to `storage/generated/*_eval.txt` — first time this has ever existed on disk.

## New findings from real numbers

1. **Grounding's citation-quality effect survives the removal of regulatory citations.** Week 4's headline result was about regulatory-citation validity specifically; that mechanism is gone (Week 5), but the same pattern shows up in the citations that remain. Genomic: grounded is 100% valid across `node_valid`/`type_applicable`/`location_valid`; ungrounded drops to `type_applicable_rate=0.83` — 17% of the time, the ungrounded model asserts a LINDDUN type that isn't actually applicable at that interaction per `mapping_table.json`, because it has no methodology context telling it what's valid there. KidsTube shows the same direction, smaller magnitude (1.00 vs 0.95).

2. **New: grounding's methodological purity has a real recall cost, not just a citation-quality benefit.** Genomic grounded's `structurally_unreachable` count is 27 — the full static ceiling — because `generate.py` skips those 7 mapping-table-invalid flows entirely, never calling the LLM. Genomic *ungrounded* doesn't skip any flow, so it still gets queried on those 7 flows, and its `structurally_unreachable` count is only 10: it coincidentally matched 17 of the 27 gold threats grounded generation structurally cannot ever produce. This is a genuine trade-off the abstract should probably name explicitly: grounding trades some recall (on interactions the methodology says shouldn't be checked) for precision/citation discipline. Not previously visible because no live run had compared the two on a real, non-demo scenario.

3. **Precision is low across the board (0.19–0.27) and should be read cautiously, not as "most threats are wrong."** Both gold standards are curated catalogs, not exhaustive ground truth (KidsTube: 36 hand-picked threats from two HW2 passes; genomic: NIST's own complete example, not literally every conceivable threat). A generated threat with no gold match may be a genuine false positive or a real threat the gold standard simply didn't itemize — the eval harness cannot currently distinguish these, which bounds how much weight precision numbers alone should carry until a manual spot-check pass exists.

4. **Reachable-adjusted recall is a materially different, more honest number than raw recall.** KidsTube grounded: 0.69 raw vs. 0.78 reachable-adjusted — a quarter of the "missing" recall was never attainable (the 4 multi-flow threats). Genomic grounded: 0.45 raw vs 0.64 adjusted. Papers reporting a single recall number for either scenario should report the adjusted figure alongside the ceiling, not raw recall alone.

## Open items / caveats

1. Precision's gold-standard-incompleteness caveat (finding #3) suggests a manual spot-check pass on a sample of "false positive" generated threats would materially improve confidence in the precision numbers — not done this week.
2. The grounded/ungrounded recall trade-off (finding #2) is new and not yet reflected in `README.md`'s framing — worth a short mention once the numbers are considered stable.
3. `--strict` (exact tree_node match) variants were not run this week — only the coarse (flow+type) tier. Would show a stricter but more conservative picture.
4. Carried from Week 5: `effective_type` reclassification sign-off (Week 4 open item #1) still pending advisor input.

## Still pending with advisor (carried from Weeks 1–5)

Target paper/workshop venue; IP/publication scope; API budget confirmation (this week's 4 live runs are the first real spend); partner coordination on the shared canonical-DFD schema; sign-off on the `effective_type` internal-staff reclassification.

## Plan for Week 7

Start Workstream 3 (new test scenarios) — candidate shortlist and sourcing-style mix already scoped; Nextcloud (file-sharing/federation subsystem) recommended first, built as a hand-authored gold standard the same way KidsTube was. Consider a manual spot-check pass on a sample of generated false positives (open item #1) before relying further on precision numbers.
