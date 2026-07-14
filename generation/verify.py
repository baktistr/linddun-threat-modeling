"""Citation verifier: independently checks whether a generated threat's citations are real.

This is the concrete implementation of the abstract's central claim -- traceability that is
*verified*, not merely asserted by the model. No LLM calls happen here; every check is a lookup
against the knowledge base files themselves, so it can't be fooled by a confident-sounding but
fabricated citation.

Two independent checks per GeneratedThreat:
  - node_valid / type_applicable : tree_node exists under threat_type in threat_trees.json, and
    threat_type is actually applicable at this flow's element-type interaction per mapping_table.json.
  - location_valid               : originator_id resolves to a real element or flow id in dfd.json.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field

import config
from retrieval.interaction_context import get_interaction_context, effective_type
from generation.schema import GeneratedThreat


@dataclass
class VerificationResult:
    node_valid: bool
    type_applicable: bool
    location_valid: bool
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return self.node_valid and self.type_applicable and self.location_valid


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

    location_valid = threat.originator_id in elements_by_id
    if not location_valid and flow is not None:
        location_valid = threat.originator_id in (flow["source"], flow["destination"])
    if not location_valid:
        reasons.append(f"originator_id '{threat.originator_id}' not found in dfd.json elements/flow")

    return VerificationResult(node_valid=node_valid, type_applicable=type_applicable,
                               location_valid=location_valid, reasons=reasons)
