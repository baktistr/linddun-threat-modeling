# Week 9 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 9
**Author:** Bakti Satria Adhityatama

## Goal for Week 9

Turn Week 8's genomic `effective_type()` revert into a permanent structural fix instead of a
pending question, and build the manual FP-adjudication stage that's been carried as an open item
since Week 5: gold standards here are curated catalogs, not exhaustive enumerations, so automated
precision is a conservative lower bound, and there's been no way to see how much of a lower bound
until now.

## Completed

**Fixed genomic's DFD typing at the source instead of patching around it at lookup time.** Week 4
introduced a `role: "internal_staff"` annotation on genomic `ExternalEntity` elements plus an
`effective_type()` reclassification that treated them as `Process` for mapping-table lookups only
— a reinterpretation layered on top of the raw transcription, never signed off, reverted in Week 8
for lack of sign-off. This week: `scripts/build_genomic_dfd.py`'s element inventory now types the
staff who actually perform data-transforming work (lab technicians, clinicians, genetic
counselors/physicians, bioinformaticists, researchers — 11 elements) as `Process` directly, matching
what they structurally are under LINDDUN Pro's own definition of `ExternalEntity` ("outside the
system"), rather than typing them `ExternalEntity` and reclassifying them only for scoring. No
`role` field exists anywhere anymore, and `effective_type()` (`retrieval/interaction_context.py`)
is now permanently the identity function with nothing left to reclassify — the type-vs-effective-type
split this function existed to bridge is gone, not just dormant. Regenerated `dfd.json`; the 99-row
cross-check against `gold_standard_threats.json`'s `nist_node` still passes (99/99). Genomic's
structural reachability ceiling is 70/99 again — the same number Week 4's hack produced, but now a
fact about how the DFD is typed, not a scoring-time exception (verified directly: `reachable_but_missed=70,
structurally_unreachable=27, unresolved_location=2`). Cleaned up the now-dead role-handling code in
`generation/verify.py` and `scripts/render_dfd.py` (which colored `role=internal_staff` elements
differently; that color is now unreachable since no element carries that role, so the legend
dropped from 4 entries to 3). Re-rendered all four scenario DFD images (genomic, kidstube,
smart_home, family_location) and visually confirmed no regressions. Updated `README.md`/`PIPELINE.md`'s
stale 17/80 figures to the corrected 70/27 breakdown, with the mechanism history intact rather than
silently overwritten. `tests/test_generation.py`'s reachability assertion now expects 70/27/2.

**Built the manual FP-adjudication stage (`eval/adjudicate.py`), carried as an open item since
Week 5.** Automated precision (`tp / (tp + fp)`) treats every unmatched generated threat as wrong,
but our gold standards aren't exhaustive — some "false positives" are threats the model found that
the catalog simply never included (the "zero-slot FP" pattern documented since Week 6). There's no
deterministic KB lookup that can tell a spurious threat from a valid-but-uncatalogued one the way
`generation/verify.py` checks a citation; it's a human judgment call, so this stage is deliberately
**not** LLM-automated — a model grading its own (or another model's) output would just relocate the
self-report-vs-verified problem this whole project exists to address. Three pieces: `build_worklist()`
resolves every unmatched threat's flow/source/destination names and citation-verification result
from `dfd.json` and writes them to `storage/adjudication/<scenario>_<mode>.json` (reviews every FP
by default, or a reproducible seeded sample via `--n`; additive/resumable, so re-running with a
larger `--n` tops up the list without disturbing existing labels); `review_cli()` is a terminal
loop that labels each item spurious / valid_uncatalogued / borderline, saving after every answer;
`human_corrected_precision()` turns labels into a corrected point estimate (borderline split 50/50
for the single number, full breakdown reported alongside), extrapolated from a sample's split if
not every FP was reviewed, exact if it was. Wired into `python cli.py adjudicate --scenario X
--generated <path> [--n N] [--report-only]`, and `python cli.py eval` now auto-detects a matching
worklist and prints `precision_corrected` next to the existing `precision_raw` if any labels exist,
or the exact command to start one if not. 16 new offline tests (worklist build/resume, no-label vs.
full-review vs. sample-extrapolation precision math, hand-verified arithmetic) — no scenario has
actually been reviewed yet; this is tooling, not results.

**Full pipeline retest after both changes.** `tests/test_kb.py` (77) and `tests/test_generation.py`
(221) both pass — 298 total. Smoke-tested the CLI end to end: `cli.py build` (index rebuild, 411
chunks), `cli.py eval --framework panoptic` on genomic (unaffected by the DFD retype, as expected —
PANOPTIC mode has no Process-mediation gate to be sensitive to element types, confirmed by design
before assuming it), and `cli.py eval` on kidstube (confirms the new adjudication section renders
correctly, both the "not available" and the labeled cases — tested by hand-labeling a throwaway
sample against `kidstube_grounded.json`'s real 97 FPs, then deleting that scratch worklist since no
genuine review happened). No previously-generated/eval'd output on disk needed regenerating: genomic's
LINDDUN-mode results were already deleted in Week 8 (methodological pivot to PANOPTIC-only evaluation
for that scenario), and no other scenario's DFD has any `role`-tagged element, so nothing else was
affected by the retype.

## Open items / caveats

1. **No scenario has actually been through manual FP adjudication yet.** The tooling is built and
   tested, but every precision number in every stored eval report is still the automated
   lower-bound one. First real target: `kidstube_grounded.json` (97 FPs, the largest single FP set
   on disk) or a `--n`-sampled subset of it.
2. Carried from Week 8, still not done: coarse (category-level) PANOPTIC matching tier; PA04/PA06's
   zero-gold-coverage prompt fix; contamination probe on Genomic's ungrounded results; `--strict`
   variants not re-run since the RAG/PANOPTIC additions; Family Location's and Smart Home's
   gold standards still need independent human review before their numbers are cited anywhere.
3. `storage/adjudication/` is untracked in git so far (nothing real has been written to it) — same
   open question as `storage/generated/`'s gitignore mismatch (Week 8 open item #5): worth deciding
   deliberately whether adjudication worklists/labels become permanent repo artifacts once real
   reviews start, rather than by accident.

## Still pending with advisor (carried from Weeks 1–8)

Target paper/workshop venue; IP/publication scope; sign-off on the #10/#18 KidsTube
duplicate-scoring decision; a view on whether PriMod4AI's AI-specific-threat gap and the
code→DFD caveat should be stated explicitly in the abstract; a view on whether Family
Location/Smart Home should be treated as real evaluation scenarios pending human review or
reframed as illustrative/demo-only until reviewed. The `effective_type` internal-staff question
itself is now resolved unilaterally (structural fix, not a reclassification pending sign-off) —
flagged here for visibility, since the underlying "is this the right way to type NIST's human
actors" judgment call was never actually reviewed by the advisor, only escalated from a runtime
hack to a data-modeling decision.

## Plan for Week 10

Run a real adjudication pass — start with `kidstube_grounded.json`'s FPs — to get the first actual
human-corrected precision number instead of just the machinery to produce one. If time allows:
Family Location's/Smart Home's gold-standard review, and the longest-carried open items above
(coarse PANOPTIC tier, PA04/PA06 prompt fix).
