"""Match generated threats against a gold-standard catalog.

KidsTube gold threats are anchored to a DFD flow id embedded in `interaction` (e.g.
"EE1-P1 [DF1]"), so matching there requires the same flow. Genomic gold threats instead carry
explicit `dfd_source_id`/`dfd_destination_id` fields (added in Week 3 from Appendix F Figure 11 --
see scripts/build_genomic_dfd.py), so matching there requires the generated threat's flow to
resolve to that same (source, destination) pair via the scenario's dfd.json. A small number of
genomic gold threats (dfd_location_confidence == "unresolved") have no transcribed location at
all and can never be matched on location -- this is intentional (see WEEK3_REPORT.md), not a bug.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from generation.schema import GeneratedThreat

FLOW_ID_RE = re.compile(r"\[(DF\d+)\]")


def gold_flow_id(gold_threat: dict) -> str | None:
    m = FLOW_ID_RE.search(gold_threat.get("interaction", ""))
    return m.group(1) if m else None


def resolve_gold_flow(gold_threat: dict, scenario: str, dfd: dict | None,
                       flows_by_id: dict) -> dict | None:
    """Resolve a gold threat's own flow in dfd.json, independent of what any generated threat
    claims -- shared by match_threats() and eval/reachability.py so the two can't develop
    different notions of "which flow is this gold threat located on".

    kidstube: the flow id embedded in `interaction` (e.g. "[DF1]"), looked up by id.
    other scenarios: the flow whose (source, destination) matches dfd_source_id/dfd_destination_id.
    Returns None if unresolvable (no dfd, no embedded/transcribed location, or a
    dfd_location_confidence == "unresolved" gold threat) -- by design, not a bug.
    """
    if scenario == "kidstube":
        gflow_id = gold_flow_id(gold_threat)
        return flows_by_id.get(gflow_id) if gflow_id else None
    if dfd is None:
        return None
    gsrc = gold_threat.get("dfd_source_id")
    gdst = gold_threat.get("dfd_destination_id")
    if gsrc is None or gdst is None:
        return None
    return next((f for f in dfd["flows"] if f["source"] == gsrc and f["destination"] == gdst), None)


@dataclass
class MatchResult:
    gen_to_gold: dict[int, int]       # generated list index -> matched gold threat id
    matched_gold_ids: set[int]
    tp: int
    fp: int
    fn: int


def match_threats(generated: list[GeneratedThreat], gold: list[dict], scenario: str,
                   dfd: dict | None = None, strict: bool = False) -> MatchResult:
    """strict=True additionally requires exact tree_node agreement (the stricter eval tier).

    `dfd` (the scenario's parsed dfd.json) is required for genomic's location-based matching;
    without it, genomic falls back to threat-type-only matching (coarser, but still usable for a
    quick check)."""
    flow_anchored = scenario == "kidstube"
    location_anchored = scenario != "kidstube" and dfd is not None
    flows_by_id = {f["id"]: f for f in dfd["flows"]} if dfd else {}

    matched_gold_ids: set[int] = set()
    gen_to_gold: dict[int, int] = {}

    for gi, g in enumerate(generated):
        gen_flow = flows_by_id.get(g.flow_id)
        for gold_t in gold:
            if gold_t["id"] in matched_gold_ids:
                continue
            if g.threat_type != gold_t["threat_type"]:
                continue
            if flow_anchored:
                gflow = gold_flow_id(gold_t)
                if gflow is None or gflow != g.flow_id:
                    continue
            elif location_anchored:
                gold_flow = resolve_gold_flow(gold_t, scenario, dfd, flows_by_id)
                if gold_flow is None:
                    continue  # unresolved gold location -- cannot be matched, by design
                if gen_flow is None or gen_flow["id"] != gold_flow["id"]:
                    continue
            if strict and g.tree_node != gold_t["tree_node"]:
                continue
            matched_gold_ids.add(gold_t["id"])
            gen_to_gold[gi] = gold_t["id"]
            break

    tp = len(gen_to_gold)
    fp = len(generated) - tp
    fn = len(gold) - len(matched_gold_ids)
    return MatchResult(gen_to_gold=gen_to_gold, matched_gold_ids=matched_gold_ids,
                        tp=tp, fp=fp, fn=fn)


def match_threats_panoptic(generated: list[GeneratedThreat], gold: list[dict], scenario: str,
                           dfd: dict) -> MatchResult:
    """PANOPTIC-native matching, for mode="panoptic" output: a generated threat matches a gold
    threat if (a) its panoptic_action appears in that gold threat's own panoptic_actions list,
    and (b) the generated threat's flow resolves to the same location as the gold threat's --
    reusing resolve_gold_flow() so this can't develop a different notion of "same flow" than the
    LINDDUN matcher above. Generated threats with no panoptic_action (i.e. from a non-panoptic
    mode) are excluded from both the numerator and denominator here -- use match_threats() for
    those; this function only scores panoptic-mode output.
    """
    flows_by_id = {f["id"]: f for f in dfd["flows"]}
    matched_gold_ids: set[int] = set()
    gen_to_gold: dict[int, int] = {}

    panoptic_generated = [(gi, g) for gi, g in enumerate(generated) if g.panoptic_action]
    for gi, g in panoptic_generated:
        gen_flow = flows_by_id.get(g.flow_id)
        for gold_t in gold:
            if gold_t["id"] in matched_gold_ids:
                continue
            if g.panoptic_action not in gold_t.get("panoptic_actions", []):
                continue
            gold_flow = resolve_gold_flow(gold_t, scenario, dfd, flows_by_id)
            if gold_flow is None:
                continue  # unresolved gold location -- cannot be matched, by design
            if gen_flow is None or gen_flow["id"] != gold_flow["id"]:
                continue
            matched_gold_ids.add(gold_t["id"])
            gen_to_gold[gi] = gold_t["id"]
            break

    tp = len(gen_to_gold)
    fp = len(panoptic_generated) - tp
    fn = len(gold) - len(matched_gold_ids)
    return MatchResult(gen_to_gold=gen_to_gold, matched_gold_ids=matched_gold_ids,
                        tp=tp, fp=fp, fn=fn)
