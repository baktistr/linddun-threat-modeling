"""Reachability-status breakdown: distinguishes a real recall failure from a gold threat the
per-flow generation loop never had a chance to catch.

generation/generate.py skips any flow whose effective_type(src)->effective_type(dst) interaction
isn't in mapping_table.json (`if not ctx.valid: continue`) *before* ever calling the LLM. A gold
threat sitting on such a flow was never generated and can never be matched, independent of model
quality -- that's a structural ceiling, not a recall failure. This module reuses the exact same
effective_type/get_interaction_context check generate.py uses (not a re-derived approximation),
and eval/match.py's resolve_gold_flow(), so its notion of "unreachable" can't silently drift from
what the pipeline actually skips or from what the matcher considers "the same flow".
"""
from __future__ import annotations
from dataclasses import dataclass

from retrieval.interaction_context import get_interaction_context, effective_type
from eval.match import gold_location_convention, resolve_gold_flow

UNRESOLVED_LOCATION = "unresolved_location"
STRUCTURALLY_UNREACHABLE = "structurally_unreachable"
REACHABLE_BUT_MISSED = "reachable_but_missed"


@dataclass
class ReachabilityCounts:
    matched: int
    reachable_but_missed: int
    structurally_unreachable: int
    unresolved_location: int

    @property
    def reachable_recall(self) -> float:
        """Recall against only the gold threats the pipeline could ever have produced."""
        denom = self.matched + self.reachable_but_missed
        return self.matched / denom if denom else 0.0


def classify_gold_threat(gold_threat: dict, scenario: str, dfd: dict, flows_by_id: dict,
                         convention: str | None = None) -> str:
    """Classify one unmatched gold threat. Call only for threats not already in matched_gold_ids.

    unresolved_location means resolve_gold_flow() couldn't anchor the threat to a single flow.
    Two live causes: genomic's untranscribed/ambiguous locations (dfd_location_confidence ==
    "unresolved"), and gold threats deliberately left unanchored because the flow they describe
    does not exist in the DFD being scored against -- kidstube_derived's re-anchored gold does
    this for the 2 threats on DF13/DF14, whose endpoints are planned features present in no code.
    Historically it also covered KidsTube threats whose `interaction` spanned multiple flows at
    once (e.g. "P3-DS2 [DF7/DF10]"); Week 7 resolved those to single flows, so all 41 now anchor.

    `convention` is threaded through from the catalog-level detection so a threat that simply has
    no anchor isn't mistaken for a catalog using the other convention.
    """
    flow = resolve_gold_flow(gold_threat, scenario, dfd, flows_by_id, convention)
    if flow is None:
        return UNRESOLVED_LOCATION
    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    src = elements_by_id.get(flow["source"])
    dst = elements_by_id.get(flow["destination"])
    if src is None or dst is None:
        return UNRESOLVED_LOCATION
    ctx = get_interaction_context(effective_type(src), effective_type(dst))
    return REACHABLE_BUT_MISSED if ctx.valid else STRUCTURALLY_UNREACHABLE


def reachability_breakdown(gold: list[dict], scenario: str, dfd: dict,
                            matched_gold_ids: set[int]) -> ReachabilityCounts:
    flows_by_id = {f["id"]: f for f in dfd["flows"]}
    convention = gold_location_convention(gold)
    counts = {REACHABLE_BUT_MISSED: 0, STRUCTURALLY_UNREACHABLE: 0, UNRESOLVED_LOCATION: 0}
    for g in gold:
        if g["id"] in matched_gold_ids:
            continue
        counts[classify_gold_threat(g, scenario, dfd, flows_by_id, convention)] += 1
    return ReachabilityCounts(matched=len(matched_gold_ids), **counts)


def reachability_breakdown_panoptic(gold: list[dict], scenario: str, dfd: dict,
                                    matched_gold_ids: set[int]) -> ReachabilityCounts:
    """PANOPTIC mode's reachability story is simpler than LINDDUN's: generate.py never gates
    panoptic-mode flows on mapping_table.json validity (PANOPTIC has no Process-mediation
    restriction at all -- see build_panoptic_prompt()'s docstring), so there is no
    structurally_unreachable concept for it. An unmatched gold threat is either a genuine recall
    failure (its flow resolves fine) or unresolved_location (the same 2/99 genomic threats with
    no confidently-transcribed DFD location that the LINDDUN reachability breakdown also excludes)
    -- structurally_unreachable is always 0 here, kept in the same ReachabilityCounts shape only
    so both breakdowns can be reported side by side without a second dataclass.
    """
    flows_by_id = {f["id"]: f for f in dfd["flows"]}
    convention = gold_location_convention(gold)
    reachable_but_missed = unresolved_location = 0
    for g in gold:
        if g["id"] in matched_gold_ids:
            continue
        flow = resolve_gold_flow(g, scenario, dfd, flows_by_id, convention)
        if flow is None:
            unresolved_location += 1
        else:
            reachable_but_missed += 1
    return ReachabilityCounts(matched=len(matched_gold_ids), reachable_but_missed=reachable_but_missed,
                              structurally_unreachable=0, unresolved_location=unresolved_location)
