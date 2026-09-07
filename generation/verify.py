"""Citation verifier: independently checks whether a generated threat's citations are real.

This is the concrete implementation of the abstract's central claim -- traceability that is
*verified*, not merely asserted by the model. No LLM calls happen here; every check is a lookup
against the knowledge base files themselves, so it can't be fooled by a confident-sounding but
fabricated citation.

Two independent checks per GeneratedThreat:
  - node_valid / type_applicable : tree_node exists under threat_type in threat_trees.json, and
    threat_type is actually applicable at this flow's element-type interaction per mapping_table.json.
  - location_valid               : the (position, originator_id) pair names a real place on THIS flow --
    "S" with the flow's source id, "D" with its destination id, "fl" with the flow's own id.
  - position_applicable          : the cited position is one mapping_table.json allows for this threat
    type at this interaction. A third closed-vocabulary citation, checked the way tree_node is.

WHY POSITION EXISTS. LINDDUN Pro elicits at three positions -- source, data flow, destination -- and
the tutorial's Table 4.1 lists all three for every threat type on every valid interaction. Until this
field, a threat could only be located at an ELEMENT, so a data-flow threat ("meta-data about the
parties used to link them", the tutorial's own example) had nowhere to go: models either coerced it
onto an endpoint or answered "fl", the token the prompt itself teaches, and were scored as having
fabricated a citation. The coercion was silent and applied to every model in this project.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field

import config
from retrieval.interaction_context import get_interaction_context, effective_type
from generation.schema import GeneratedThreat


LEGACY_POSITION = ""           # artifacts written before `position` existed


@dataclass
class VerificationResult:
    node_valid: bool
    type_applicable: bool
    location_valid: bool
    position_applicable: object = True   # True | False | None (not cited, i.e. a pre-position artifact)
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        # position_applicable is None for artifacts predating the field; an unrunnable check must
        # not be able to fail a threat, and equally must not manufacture a pass -- it is simply
        # excluded, the same convention verify_dfd.py uses for its NOT_CHECKED verdicts.
        pos_ok = self.position_applicable is not False
        return self.node_valid and self.type_applicable and self.location_valid and pos_ok


def _load_json(path) -> dict:
    return json.loads(path.read_text())


def verify_threat(threat: GeneratedThreat, dfd: dict) -> VerificationResult:
    reasons: list[str] = []

    trees = _load_json(config.KB_DIR / "linddun" / "threat_trees.json")["threat_types"]
    nodes = trees.get(threat.threat_type, {}).get("nodes", {})
    node_valid = threat.tree_node in nodes
    if not node_valid:
        reasons.append(f"tree_node '{threat.tree_node}' not found under type '{threat.threat_type}'")

    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    flow = next((f for f in dfd["flows"] if f["id"] == threat.flow_id), None)
    type_applicable = False
    ctx = None
    if flow is None:
        reasons.append(f"flow_id '{threat.flow_id}' not found in dfd.json")
    else:
        src = elements_by_id.get(flow["source"])
        dst = elements_by_id.get(flow["destination"])
        if src and dst:
            src_eff, dst_eff = effective_type(src), effective_type(dst)
            ctx = get_interaction_context(src_eff, dst_eff)
            type_applicable = ctx.valid and threat.threat_type in ctx.applicable
            if not type_applicable:
                reasons.append(f"threat_type '{threat.threat_type}' not applicable at "
                                f"{src['type']}->{dst['type']} per mapping_table.json")

    # Location. With a position cited, the pair must agree: the id has to name the very place the
    # position points at, on THIS flow. Without one (a pre-position artifact) fall back to the old
    # rule so historical numbers stay reproducible -- see LEGACY_POSITION.
    position = (threat.position or LEGACY_POSITION).strip()
    position_applicable: object = None
    if flow is None:
        location_valid = False
        reasons.append(f"flow_id '{threat.flow_id}' not found in dfd.json")
    elif position == LEGACY_POSITION:
        location_valid = (threat.originator_id in elements_by_id
                          or threat.originator_id in (flow["source"], flow["destination"]))
        if not location_valid:
            reasons.append(f"originator_id '{threat.originator_id}' not found in dfd.json "
                           f"elements/flow")
    else:
        expected = {"S": flow["source"], "D": flow["destination"], "fl": flow["id"]}.get(position)
        if expected is None:
            location_valid = False
            reasons.append(f"position '{position}' is not one of S / fl / D")
        else:
            location_valid = threat.originator_id == expected
            if not location_valid:
                reasons.append(f"position '{position}' on flow {flow['id']} names "
                               f"'{expected}', but originator_id is '{threat.originator_id}'")
        # Applicability is a separate question from wellformedness: a syntactically fine "S" can
        # still be a position the mapping table does not list for this threat type.
        if ctx is not None and ctx.valid:
            allowed = ctx.applicable.get(threat.threat_type, [])
            position_applicable = position in allowed
            if not position_applicable:
                reasons.append(f"position '{position}' not applicable for threat_type "
                               f"'{threat.threat_type}' at this interaction (allowed: {allowed})")

    return VerificationResult(node_valid=node_valid, type_applicable=type_applicable,
                               location_valid=location_valid,
                               position_applicable=position_applicable, reasons=reasons)
