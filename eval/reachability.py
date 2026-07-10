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
from eval.match import resolve_gold_flow

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


def classify_gold_threat(gold_threat: dict, scenario: str, dfd: dict, flows_by_id: dict) -> str:
    """Classify one unmatched gold threat. Call only for threats not already in matched_gold_ids.

    unresolved_location covers two distinct causes, both meaning resolve_gold_flow() couldn't
    anchor the threat to a single flow: genomic's untranscribed/ambiguous locations (2/99,
    dfd_location_confidence=="unresolved"), and KidsTube gold threats whose `interaction` spans
    multiple flows at once (e.g. "P3-DS2 [DF7/DF10]") -- 4/36, a genuine structural ceiling for
    the current per-flow generation loop discovered by running this classifier, since no single
    per-flow LLM call could ever produce a threat anchored to more than one flow_id.
    """
    flow = resolve_gold_flow(gold_threat, scenario, dfd, flows_by_id)
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
    counts = {REACHABLE_BUT_MISSED: 0, STRUCTURALLY_UNREACHABLE: 0, UNRESOLVED_LOCATION: 0}
    for g in gold:
        if g["id"] in matched_gold_ids:
            continue
        counts[classify_gold_threat(g, scenario, dfd, flows_by_id)] += 1
    return ReachabilityCounts(matched=len(matched_gold_ids), **counts)
