"""Interaction-context assembler: the bridge from retrieval to threat elicitation.

Given a DFD interaction (source element type, destination element type), return
the LINDDUN methodology context needed to elicit threats for it:
  - which threat types apply at which positions (from the mapping table)
  - the relevant threat-tree nodes for those types
  - the position interpretations (S/fl/D)

In Week 2 this context feeds the per-interaction threat-generation prompt.
"""
from __future__ import annotations
import json
from dataclasses import dataclass

import config


@dataclass
class InteractionContext:
    source_type: str
    dest_type: str
    applicable: dict           # threat_type -> [positions]
    tree_nodes: dict           # threat_type -> {node_id: {title, description}}
    valid: bool
    note: str = ""

    def as_prompt_block(self) -> str:
        if not self.valid:
            return f"Interaction {self.source_type}->{self.dest_type} is INVALID: {self.note}"
        lines = [f"Interaction: {self.source_type} -> data flow -> {self.dest_type}",
                 "Applicable LINDDUN threat types and positions (S=source, fl=flow, D=destination):"]
        type_names = _type_names()
        for tt, pos in self.applicable.items():
            lines.append(f"  - {tt} ({type_names.get(tt, tt)}): assess at {', '.join(pos)}")
        lines.append("\nRelevant threat-tree nodes to consider:")
        for tt, nodes in self.tree_nodes.items():
            lines.append(f"  {tt} ({type_names.get(tt, tt)}):")
            for nid, n in nodes.items():
                lines.append(f"    {nid} — {n['title']}: {n['description']}")
        return "\n".join(lines)


def _load(name: str) -> dict:
    return json.loads((config.KB_DIR / "linddun" / name).read_text())


def _type_names() -> dict:
    trees = _load("threat_trees.json")
    return {tt: info["name"] for tt, info in trees["threat_types"].items()}


def get_interaction_context(source_type: str, dest_type: str) -> InteractionContext:
    mapping = _load("mapping_table.json")
    trees = _load("threat_trees.json")["threat_types"]

    # invalid?
    for inv in mapping.get("invalid_interactions", []):
        if inv["source"] == source_type and inv["destination"] == dest_type:
            return InteractionContext(source_type, dest_type, {}, {}, valid=False, note=inv["reason"])

    row = next((r for r in mapping["interactions"]
                if r["source"] == source_type and r["destination"] == dest_type), None)
    if row is None:
        return InteractionContext(source_type, dest_type, {}, {}, valid=False,
                                  note="No mapping-table row for this interaction.")

    applicable = row["applicable_threats"]
    tree_nodes = {}
    for tt in applicable:
        nodes = trees.get(tt, {}).get("nodes", {})
        tree_nodes[tt] = {nid: {"title": n["title"], "description": n["description"]}
                          for nid, n in nodes.items()}
    return InteractionContext(source_type, dest_type, applicable, tree_nodes, valid=True)


# valid DFD element types
ELEMENT_TYPES = {"ExternalEntity", "Process", "DataStore"}


def effective_type(element: dict) -> str:
    """Type to use for mapping-table lookups.

    Week 4 introduced a reinterpretation here: since NIST's own DFDs type every human actor as
    ExternalEntity regardless of whether they're internal staff or a genuinely external party,
    elements tagged role=="internal_staff" (an annotation this repo adds -- see
    scripts/build_genomic_dfd.py) were treated as Process for this lookup, raising genomic
    reachability from 17/99 to 70/99 gold threats. That reclassification was never signed off by
    the advisor (flagged as a pending open item every week since Week 4) and is reverted here
    (Week 8): `role` is no longer consulted, so this is now the identity function on
    `element["type"]`. `dfd.json`'s `role: "internal_staff"` annotations are left in place as
    inert provenance rather than stripped -- they document a reclassification this repo tried and
    backed out of, not current pipeline behavior. Reverting this restores the original Week 3
    finding: only 17/99 genomic gold threats are structurally reachable by the mapping-table-gated
    per-flow generation loop, independent of model quality; see WEEK3_REPORT.md and
    knowledge_base/linddun/panoptic_crosswalk.json (Week 8) for why NIST's own analysis isn't
    bound by this same restriction in the first place."""
    return element.get("type")


if __name__ == "__main__":
    # demo: the EE->P interaction that DF1 (parent registration) belongs to
    ctx = get_interaction_context("ExternalEntity", "Process")
    print(ctx.as_prompt_block()[:1200])
    print("\n--- invalid example ---")
    print(get_interaction_context("DataStore", "DataStore").as_prompt_block())
