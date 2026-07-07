"""Per-flow prompt construction for threat generation.

Grounded prompts reuse retrieval/interaction_context.py (applicable LINDDUN types/positions/tree
nodes for the flow's element-type pair) plus top regulatory hits retrieved for the flow's own
description. Ungrounded prompts (the ablation baseline) give the model only the bare flow/element
info and no methodology or regulatory context, so any citations it produces come from its own
training knowledge rather than this repo's knowledge base.
"""
from __future__ import annotations

from retrieval.interaction_context import InteractionContext


def _element_line(elements_by_id: dict, eid: str) -> str:
    e = elements_by_id[eid]
    return f"{e['name']} ({e['type']}, id {e['id']})"


def build_grounded_prompt(flow: dict, elements_by_id: dict, ctx: InteractionContext, reg_hits: list) -> str:
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])
    if reg_hits:
        reg_block = "\n".join(f"- [{h.chunk.section}] {h.chunk.text}" for h in reg_hits)
    else:
        reg_block = "(no regulatory hits retrieved for this flow)"

    return f"""You are a LINDDUN Pro privacy-threat-modeling assistant analyzing one DFD data flow.

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

{ctx.as_prompt_block()}

Relevant regulatory context (cite the exact bracketed section label if a threat implicates it, or leave regulatory_citation empty if none apply):
{reg_block}

Instructions:
- For each applicable threat type listed above, decide whether a genuine threat exists for THIS flow, using only the flow description and context given. Do not pad the list to cover every type -- omit types with no real evidence.
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}" (whichever element the threat is actually located at).
- tree_node must be one of the node ids listed above under the chosen threat_type.
- regulatory_citation must be an exact section label from the regulatory context above (e.g. "COPPA § 312.5"), or "" if none apply.
- If you are not confident in a citation, say so in uncertainty_note rather than asserting it silently.
Respond using the emit_threats tool."""


def build_ungrounded_prompt(flow: dict, elements_by_id: dict) -> str:
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])
    return f"""You are a privacy-threat-modeling assistant analyzing one DFD data flow using the LINDDUN methodology from your own knowledge (no reference material is provided).

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

Identify any privacy threats for this flow. For each, classify it under a LINDDUN threat type (L, I, Nr, D, Dd, U, or Nc), give your best LINDDUN Pro threat-tree node id, and cite a regulatory provision if one applies (empty string if none).
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}".
- If you are not confident in a node id or citation, say so in uncertainty_note rather than asserting it silently.
Respond using the emit_threats tool."""
