"""Match generated threats against a gold-standard catalog.

Gold catalogs anchor threats to a DFD location in one of two conventions, and which one is in
force is a property of the *catalog*, not of the scenario's name:

  flow-anchored     -- the flow id is embedded in `interaction` (e.g. "EE1-P1 [DF1]"), so
                       matching requires the same flow id. KidsTube's 41 threats.
  location-anchored -- explicit `dfd_source_id`/`dfd_destination_id` fields (added in Week 3 from
                       Appendix F Figure 11 -- see scripts/build_genomic_dfd.py), so matching
                       requires the generated threat's flow to resolve to that same
                       (source, destination) pair via the scenario's dfd.json. Genomic's 99,
                       family_location's 20, smart_home's 18.

`gold_location_convention()` detects which by looking at the catalog. Until Week 10 this was
`scenario == "kidstube"`, which quietly assumed the only flow-anchored catalog would ever be the
one named "kidstube". Any new scenario built on the same convention -- notably `kidstube_derived`,
whose gold is KidsTube's re-anchored through the adapter's alignment map -- took the
location-anchored branch instead, found no dfd_source_id on any of its 41 threats, resolved every
one to None, and scored a silent P=R=F1=0.00 with no error raised. Detecting from the data closes
that off and makes the docstring's long-standing claim ("generalizes to any other scenario with a
dfd.json", README) actually true.

A small number of genomic gold threats (dfd_location_confidence == "unresolved") have no
transcribed location at all and can never be matched on location -- this is intentional (see
WEEK3_REPORT.md), not a bug.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from generation.schema import GeneratedThreat

FLOW_ID_RE = re.compile(r"\[(DF\d+)\]")

FLOW_ANCHORED = "flow_anchored"
LOCATION_ANCHORED = "location_anchored"


def gold_flow_id(gold_threat: dict) -> str | None:
    m = FLOW_ID_RE.search(gold_threat.get("interaction") or "")
    return m.group(1) if m else None


def gold_location_convention(gold: list[dict]) -> str:
    """Which anchoring convention this gold catalog uses, read off the catalog itself.

    `any` rather than `all`: a catalog is flow-anchored if it anchors *any* threat that way. A
    threat with no resolvable location is already handled downstream (resolve_gold_flow returns
    None -> unresolved_location), so a partially-tagged catalog must not silently fall through to
    the wrong branch for the threats that ARE tagged.
    """
    return FLOW_ANCHORED if any(gold_flow_id(g) for g in gold) else LOCATION_ANCHORED


def resolve_gold_flow(gold_threat: dict, scenario: str, dfd: dict | None,
                       flows_by_id: dict, convention: str | None = None) -> dict | None:
    """Resolve a gold threat's own flow in dfd.json, independent of what any generated threat
    claims -- shared by match_threats() and eval/reachability.py so the two can't develop
    different notions of "which flow is this gold threat located on".

    flow-anchored: the flow id embedded in `interaction` (e.g. "[DF1]"), looked up by id.
    location-anchored: the flow whose (source, destination) matches dfd_source_id/dfd_destination_id.
    Returns None if unresolvable (no dfd, no embedded/transcribed location, or a
    dfd_location_confidence == "unresolved" gold threat) -- by design, not a bug.

    `convention` is passed by callers that already computed it for the whole catalog; when
    omitted it is inferred per-threat, which is equivalent for a catalog that is internally
    consistent and is what the single-threat callers want.
    """
    if convention is None:
        convention = FLOW_ANCHORED if gold_flow_id(gold_threat) else LOCATION_ANCHORED
    if convention == FLOW_ANCHORED:
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

    `dfd` (the scenario's parsed dfd.json) is required for location-anchored matching; without
    it, a location-anchored catalog falls back to threat-type-only matching (coarser, but still
    usable for a quick check)."""
    convention = gold_location_convention(gold)
    flow_anchored = convention == FLOW_ANCHORED
    location_anchored = not flow_anchored and dfd is not None
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
                gold_flow = resolve_gold_flow(gold_t, scenario, dfd, flows_by_id, convention)
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
    convention = gold_location_convention(gold)
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
            gold_flow = resolve_gold_flow(gold_t, scenario, dfd, flows_by_id, convention)
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
