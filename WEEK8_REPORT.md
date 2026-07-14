# Week 8 Progress Report

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 8
**Author:** Bakti Satria Adhityatama

## Goal for Week 8

Resolve the terminology question raised at the end of Week 7 ("is grounded generation actually
RAG?" — no), build the real thing, follow that investigation into a full second framework
(MITRE PANOPTIC) once it became clear genomic's own ground truth wasn't purely LINDDUN, and grow
the evaluation surface beyond two scenarios.

## Completed

**Corrected the RAG/grounded distinction, then built a real three-way ablation.** `grounded`
mode was never retrieval-augmented generation — it's a deterministic, exhaustive lookup against
`mapping_table.json`/`threat_trees.json`, with no similarity search and therefore no way to
retrieve the wrong node. Added a genuine `rag` mode (`retrieval/index.py`'s hybrid dense+keyword
search, top-k over the `linddun` corpus, framed in the prompt as guidance rather than an
authoritative menu) alongside the existing `grounded`/`ungrounded`. Live-ran all three on both
KidsTube and Genomic. Headline finding: RAG's citation-validity advantage over no grounding is
real but **scenario-conditional** — it nearly matches deterministic grounding on KidsTube
(`all_valid_rate` 0.99 vs. 1.00, both far above ungrounded's 0.95), but on Genomic it barely
beats ungrounded (0.85 vs. 0.79), because RAG has no gate and gets pulled into the same
structurally-invalid flows ungrounded does, and similarity search doesn't reliably steer it away
from asserting an invalid type there the way the deterministic table does.

**Found and reverted an un-signed-off methodology decision.** Week 4's `effective_type()`
reclassification (treating `role: "internal_staff"` `ExternalEntity` elements as `Process` for
mapping-table lookups, which raised genomic's structural reachability ceiling from 17/99 to
70/99) was flagged as pending advisor sign-off every week since Week 4 and never resolved.
Reverted it this week — `effective_type()` is now the identity function on `element["type"]`.
This is a large swing: genomic's ceiling drops back to the original 17/99, and re-scoring the
existing grounded output under the stricter rule showed the previously-generated content had
been judged against a goalpost that moved after generation (grounded's `type_applicable_rate`
crashes from 1.00 to 0.33 when re-scored — not a real quality drop, an artifact of scoring old
output under new rules; RAG/ungrounded's re-scores are legitimate since their generation was
never gated by this function to begin with).

**Traced why NIST's genomic DFD includes interactions the LINDDUN Pro tutorial calls invalid —
and it isn't a transcription problem.** Read NIST SP 1800-43C Appendix D's actual methodology
(not just its abstract): LINDDUN threat-tree elicitation runs per DFD segment, and PANOPTIC
Privacy Activities mapping runs separately per use case; a threat survives only if validated by
**both**, cross-checked via a general PANOPTIC↔LINDDUN crosswalk (Appendix G Figures 19/19b) —
never via `mapping_table.json`'s Table 4.1 gate, which is specific to the lighter tutorial this
repo separately transcribes. Vision-transcribed that crosswalk (`knowledge_base/linddun/
panoptic_crosswalk.json`, 13 PANOPTIC categories ↔ 7 LINDDUN types, cross-checked between both
transcription directions — 12/13 categories agreed exactly, the one asymmetry documented rather
than silently resolved) and audited all 99 genomic gold threats' `(threat_type, panoptic_actions)`
pairing against it: **99/99 consistent, 0 mismatches** — a new, independent integrity check for
the genomic scenario's central asset.

**Built a full parallel PANOPTIC framework, not just a crosswalk.** Transcribed MITRE PANOPTIC's
complete taxonomy (5 Contextual Domains + 13 Privacy Activities + 100 sub-activities —
category-level from NIST's plain-text appendix, high confidence; sub-activity detail vision-
transcribed from Figure 19, with one region three sub-activities wide flagged `confidence: "low"`
after a re-check surfaced a genuine wording error and an unresolvable ambiguity between two
independent reads) into `knowledge_base/panoptic/taxonomy.json`. Added `panoptic_grounded`/
`panoptic_rag`/`panoptic_ungrounded` generation modes (mirroring LINDDUN's three, composed via
`resolve_mode(rag, ungrounded, framework)` so the two axes are orthogonal on the CLI) and a
PANOPTIC-native evaluator (`match_threats_panoptic()`, matching on `panoptic_action` membership
in the gold threat's own `panoptic_actions` list + flow location — reuses the existing 99-threat
genomic gold standard as-is, no new ground truth needed). Live-ran all three PANOPTIC modes on
genomic. Two findings: (1) PANOPTIC-native scores (F1 0.11–0.17) are much lower than the LINDDUN-
framework numbers, mostly because exact-sub-activity-id matching is a far stricter target (100
possible ids, ~2.5 correct per gold threat on average) than LINDDUN's coarse type+flow tier — not
evidence PANOPTIC mode is worse. (2) Two entire categories (PA04 Insecurity, PA06 Quality
Assurance — 19 of 100 sub-activities) are cited by **zero** of the 99 gold threats, yet the model
reaches for them constantly since they sound plausible for any data flow; these two categories
alone account for 65% of `panoptic_grounded`'s false positives. A coarse (category-level, not
exact-id) PANOPTIC matching tier — the PANOPTIC analogue of LINDDUN's `--strict` split — is a
clear next step, not yet built.

**Added two new evaluation scenarios: Family Location Sharing App and Smart Home Security
System.** Family Location is new (8 elements/13 flows, 20 gold threats); Smart Home upgrades the
existing Week 4 demo DFD (which explicitly had no gold standard) into a scored scenario (18
threats). Both hand-authored for this repo from short product briefs, all flows Process-mediated
by design (0 structurally unreachable, verified against the real `eval/reachability.py` tooling,
not just eyeballed), every `tree_node` a real verified node, every `dfd_source_id`/
`dfd_destination_id` pair checked against a real flow. **Explicitly flagged as weaker
evidentiary status than KidsTube (human HW2) or Genomic (NIST) in both scenarios' own `_meta`** —
LLM-authored and not independently reviewed. That caveat mattered immediately: live-running the
LINDDUN 3-way ablation on both showed Family Location's `grounded` mode hitting **20/20 raw
recall — a perfect sweep that never happened on KidsTube or Genomic under any mode**, plausibly
the same model family recognizing/reproducing its own reasoning from authoring the gold standard
rather than genuine pipeline superiority. Flagged as needing human review before either
scenario's numbers are cited as comparable to the other two.

**Deleted genomic's LINDDUN-framework generated results.** Per direction this week: genomic's
own ground truth is fundamentally PANOPTIC-validated (cross-checked against LINDDUN, not derived
from the LINDDUN Pro tutorial's own methodology), so its LINDDUN-mode `grounded`/`rag`/
`ungrounded` generated JSONs and eval reports were removed from `storage/generated/`. KidsTube's
LINDDUN results and genomic's new PANOPTIC-mode results are unaffected. 4 of the 6 deleted files
were previously committed (Week 6); the deletion is included in this week's commit.

**Rendered DFD images for every scenario that lacked one.** `scripts/render_dfd.py` (previously
only drew `smart_home`) now also renders KidsTube and Family Location with hand-placed layouts,
and Genomic with a new content-width-aware auto-grid layout (32 elements was too large to
hand-place; a fixed column spacing overlapped Genomic's longer element names, so columns are now
packed by each element's actual rendered width). Iterated on real rendering bugs across two
passes each — a clipped element name, a datastore box overlapping a process ellipse, several
crossed edge labels — rather than accepting the first render.

## Open items / caveats

1. **Family Location's and Smart Home's gold standards need independent human review before
   their numbers are cited anywhere**, per the recall-inflation finding above — this is now the
   single most important open item, more pressing than the older ones below.
2. **No coarse (category-level) PANOPTIC matching tier exists yet** — only exact-sub-activity-id
   matching, which conflates "wrong reasoning" with "right category, wrong specific id."
3. **PA04/PA06's zero-gold-coverage problem is unaddressed in the prompt** — nothing currently
   tells `panoptic_*` modes these categories don't apply to this kind of system, so they'll keep
   generating guaranteed-false-positive citations in those two categories.
4. Carried from Weeks 5–7, still not done: manual spot-check of a sample of "false positive"
   generated threats (distinguishes real errors from gold-standard incompleteness); the
   contamination probe on Genomic's ungrounded results (public NIST document vs. unpublished
   KidsTube HW2); `--strict` (exact tree_node) variants not re-run since the RAG/PANOPTIC
   additions.
5. `.gitignore` claims `storage/generated/` is ignored (per README's architecture notes) but it
   isn't — most of it is tracked in git. Left as-is this week (out of scope), but worth deciding
   deliberately rather than by accident, since it means every live run's output becomes a
   permanent repo artifact unless intentionally excluded.

## Still pending with advisor (carried from Weeks 1–7)

Target paper/workshop venue; IP/publication scope; sign-off on the `effective_type`
internal-staff reclassification (now moot — reverted unilaterally this week without sign-off
ever having been given, flagged here for visibility, not as a substitute for it); sign-off on
the #10/#18 KidsTube duplicate-scoring decision; a view on whether PriMod4AI's AI-specific-threat
gap and the code→DFD caveat should be stated explicitly in the abstract; and now: a view on
whether Family Location/Smart Home should be treated as real evaluation scenarios pending human
review, or reframed as illustrative/demo-only until reviewed (same status `smart_home` had before
this week).

## Plan for Week 9

Human review pass on Family Location's and Smart Home's gold standards before trusting their
recall/precision numbers further. If time allows: a coarse PANOPTIC matching tier, and finally
the manual FP spot-check that's been carried for three weeks.
