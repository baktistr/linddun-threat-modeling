# Week 7 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 7
**Author:** Bakti Satria Adhityatama

## Goal for Week 7

Act on Week 6 finding #3: 4 of KidsTube's 36 gold threats described something spanning more than one DFD flow at once, so the per-flow generation architecture could never produce a match for them regardless of model quality. Decide, per threat, whether that's fixable by restructuring the gold standard or is a genuine architectural limit that shouldn't be papered over.

## Completed

**Investigated all 4 threats individually rather than mechanically splitting every one.** Reading the actual content (not just the `interaction` field) showed two different situations:

- **#21 (JWT exposure across DF3/DF5) and #29 (no encryption across DF2/DF7/DF9) split cleanly.** Each contributing flow independently exhibits the *identical* vulnerability — the unencrypted JWT is the same defect whether it's carried to the parent (DF3) or the child (DF5); the unencrypted DB connection is the same defect whether it's DS1, DS2, or DS3. Splitting these loses nothing.
- **#10 (profiling via DS2) and #18 (systematic minimization violation) do not split cleanly.** Their own descriptions say the risk is the *combination*: #10 explicitly states the profile is built by combining DF7's static fields with DF10's behavioral logs; #18's title says "across the platform" and cites data types beyond even its own two tagged flows. Forcing either into one flow would mean fabricating weaker content or arbitrarily dropping half of what the analysis actually found.

**Decision (with advisor-adjacent sign-off in this session): split all 4, but differently.** #21 and #29 became genuinely independent per-flow entries. #10 and #18 became **duplicated** per-flow entries — identical content anchored to each contributing flow, so a match on *either* flow counts as finding the threat. This is a deliberate scoring choice, not free: if a run happens to independently generate matching content on both of a duplicated pair's flows, both count as separate true positives for what is conceptually one finding. Accepted as the more honest option versus leaving 2 of the 4 permanently unscoreable.

**`scripts/build_kidstube_gold.py` rewritten**, not the JSON hand-edited — the JSON is a build artifact. This meant renumbering every id from 10 onward (36 → 41 threats: +1, +1, +1, +2) and, less obviously, finding and fixing every in-text cross-reference to a shifted id (e.g. "(see threat 17)" → "(see threat 18)") across 6 different threats' `description`/`assumptions`/`mapping_note` fields — a stale cross-reference would have been a silent, hard-to-notice error in a research artifact. Each split threat's `mapping_note` documents which sibling id(s) it was split from and why (clean split vs. deliberate duplicate), continuing this file's existing audit-trail convention (`original_hw2_node`, `source: "bilal_hw2"`).

**Result: kidstube reachability breakdown is now 41/41 resolved, 0 unresolved, 0 structurally unreachable** (verified via `eval/reachability.py`, and baked into `tests/test_generation.py` as a regression check replacing the old "4 unresolved" assertion). `tests/test_kb.py`'s threat-count assertions updated to 41; both suites pass (32/32, 245-chunk index rebuilt; 148/148).

**Re-scored the existing Week 6 generated output against the new gold standard** — no new LLM calls needed, since generation itself is unaffected by a gold-standard change:

| | KidsTube grounded | KidsTube ungrounded |
|---|---|---|
| | Week 6 (36 gold) → Week 7 (41 gold) | Week 6 (36 gold) → Week 7 (41 gold) |
| TP / FP / FN | 25/105/11 → **33/97/8** | 21/92/15 → **28/85/13** |
| Precision / Recall / F1 | .19/.69/.30 → **.25/.80/.39** | .19/.58/.28 → **.25/.68/.36** |
| Recall, raw vs. reachable-adjusted | .69 vs .78 → **.80 vs .80** (now equal) | .58 vs .66 → **.68 vs .68** (now equal) |

This is a real improvement, not a metric-gaming artifact: the model's output is byte-for-byte identical to Week 6 — only the scoring became fair. Raw and reachable-adjusted recall converging to the same number confirms there's no remaining structural ceiling being silently absorbed into "missed."

**Re-checked positioning against PILLAR and PriMod4AI directly from their abstracts**, not from `REFERENCES.md`'s one-line summaries. Findings:

- **Independent citation verification looks like a genuine differentiator.** Neither paper's abstract describes anything resembling `verify.py` re-deriving ground truth from KB files independent of the LLM's own output — this project's traceability claim appears to be real prior-art whitespace, not just an unverified claim.
- **The "code → DFD" differentiator is still aspirational, not demonstrated.** It's the explicitly-flagged largest missing piece in `README.md`'s stage table. PILLAR already does an analogous (lower-bar) thing — natural-language description → DFD — so the honest framing is "this project targets a harder version of DFD synthesis neither paper does," not "this project already has it and they don't."
- **PriMod4AI has strictly broader scope in one direction**: AI-specific threats (membership inference, model inversion) that are entirely out of scope here. Worth citing as a real limitation, not omitting.
- **Three gaps between the current abstract framing and what's actually been tested**, independent of either paper: (1) "help a privacy expert" has only been tested via proxy (generated-vs-gold-standard comparison), never with an actual human expert in the loop; (2) "risk analysis" implies prioritization — `GeneratedThreat.severity`/`likelihood` are populated but never scored against gold, so this is closer to "threat elicitation" than full risk analysis; (3) this week's own finding (#10/#18 requiring duplication) is evidence the per-flow architecture has a real ceiling on *threat scope*, not just threat type — not yet reflected in the abstract.

**Investigated why the grounded-vs-ungrounded pattern reverses between scenarios** — KidsTube favors grounded (F1 .39 vs .36) but Genomic favors ungrounded (F1 .39 vs .31), the opposite direction. Partially explained, partially an open question:

- **Confirmed mechanism (partial):** grounded's mapping-table skip-gate only bites Genomic — it skips 6/39 flows outright (`structurally_unreachable` 27 vs. ungrounded's 10, since ungrounded never skips anything), while KidsTube has zero structurally unreachable flows in either mode. This can't be the whole story, though: Genomic's *reachable-adjusted* recall (which already excludes the skip-gate effect) still favors ungrounded, 0.77 vs. 0.64.
- **Two untested candidate explanations for the residual gap:** (a) NIST's gold `nist_node` values sometimes use a deeper LINDDUN tree revision than `threat_trees.json` (flagged since `WEEK2_REPORT.md`) — grounded's prompt restricts `tree_node` to an inlined menu that may not contain the node NIST actually used, while ungrounded is unconstrained; (b) **possible training-data contamination** — NIST SP 1800-43C is a public document (Aug 2025) a model may have seen in pretraining, while KidsTube's gold standard is unpublished HW2 analysis with no equivalent exposure path. The reversal appearing *only* on the public-source scenario is suspicious enough to flag before trusting Genomic's ungrounded numbers as evidence of good unaided reasoning — a real contamination probe (e.g. a pre-cutoff control model) would be needed to settle this, not yet done.
- **Regardless of cause, citation reliability still favors grounded in both scenarios** (Genomic `type_applicable_rate` 1.00 vs. 0.83) — so even where ungrounded numerically wins on F1, it's measurably less trustworthy. This caveat should travel with any headline recall/F1 number, not just the raw score.

**Built a 15-slide presentation deck** (interactive HTML + PDF + PPTX exports) covering pipeline mechanics, evaluation methodology, per-category results for both scenarios, and the scenario roadmap — for advisor/lab presentation use, not part of the eval pipeline itself.

## Open items / caveats

1. **The #10/#18 duplicate-scoring choice is a real methodological call, not a neutral fix** — flag explicitly if this goes in the paper. An alternative (recorded but not taken): leave #10/#18 unresolved and report KidsTube's ceiling as 39/41 rather than 41/41, treating cross-flow aggregation threats as a stated limitation the same way Genomic's mapping-table gap is stated. Revisit if reviewers push back on double-counting risk.
2. Precision's gold-standard-incompleteness caveat (Week 6 finding #3) still applies unchanged — the duplicate entries don't affect that concern either way.
3. Carried from Week 6/5: `effective_type` reclassification sign-off, `--strict` variants not yet run, manual spot-check of false positives not yet done.
4. **Possible training-data contamination on Genomic's ungrounded numbers is an open, unverified concern** (see above) — Genomic's gold standard derives from a public NIST document; KidsTube's does not. Until probed, any claim that "ungrounded reasons well unaided" on Genomic specifically should be treated with real skepticism.
5. The three abstract-vs-tested-scope gaps above (human-in-the-loop, risk prioritization, aggregate-threat ceiling) are not blockers but should inform how strongly the paper's claims are worded.

## Still pending with advisor (carried from Weeks 1–6)

Target paper/workshop venue; IP/publication scope; sign-off on the `effective_type` internal-staff reclassification; sign-off on the #10/#18 duplicate-scoring decision before citing 41/41 kidstube reachability in any paper claim; **and now: a view on whether the PriMod4AI AI-specific-threat gap and the "code→DFD not yet built" caveat should be stated explicitly in the abstract's related-work/limitations framing.**

## Plan for Week 8

Start Workstream 3 (new test scenarios) — Nextcloud (file-sharing/federation subsystem) first, per the existing roadmap. Author its gold standard with the multi-flow lesson from this week already in mind: check each candidate threat for cross-flow aggregation *before* finalizing, not after eval reveals it. If time allows, a small contamination probe on Genomic's ungrounded results (e.g. checking whether generated node choices suspiciously mirror NIST's own numbering) before the grounded-vs-ungrounded story goes into the paper.
