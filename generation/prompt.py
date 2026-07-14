"""Per-flow prompt construction for threat generation.

Two frameworks (LINDDUN and PANOPTIC), each with the same three grounding mechanisms, composed
into generation/generate.py's `mode` string as {grounded,rag,ungrounded} for LINDDUN and
{panoptic_grounded,panoptic_rag,panoptic_ungrounded} for PANOPTIC (see resolve_mode()):
  - grounded:   reuses retrieval/interaction_context.py -- a deterministic, exhaustive lookup
                against mapping_table.json/threat_trees.json for the flow's element-type pair.
                Not retrieval: there's no similarity search, so it can't retrieve the wrong node.
  - rag:        genuine retrieval-augmented generation -- retrieval/index.py's hybrid
                dense+keyword vector search over the KB, top-k chunks by semantic similarity to
                the flow's own description. Can miss the most relevant passage, unlike the
                deterministic mode; that's the variable this ablation isolates.
  - ungrounded: no KB context at all (the baseline). Any node/action ids it produces come from
                the model's own training knowledge rather than this repo's knowledge base.
  - panoptic_*: same three mechanisms, but grounded in knowledge_base/panoptic/taxonomy.json
                (MITRE PANOPTIC) instead of LINDDUN's KB, citing panoptic_action instead of (in
                addition to) tree_node. No Process-mediation gate -- PANOPTIC doesn't have one.
"""
from __future__ import annotations

from retrieval.interaction_context import InteractionContext


def _element_line(elements_by_id: dict, eid: str) -> str:
    e = elements_by_id[eid]
    return f"{e['name']} ({e['type']}, id {e['id']})"


def build_flow_query(flow: dict, elements_by_id: dict) -> str:
    """Turn a DFD flow into the text query used to retrieve RAG context for it -- the same
    source/destination/description information every prompt mode is given, just phrased as a
    retrieval query instead of inlined prompt text."""
    src = elements_by_id[flow["source"]]
    dst = elements_by_id[flow["destination"]]
    return f"{src['name']} ({src['type']}) -> {dst['name']} ({dst['type']}): {flow['description']}"


def build_grounded_prompt(flow: dict, elements_by_id: dict, ctx: InteractionContext) -> str:
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])

    return f"""You are a LINDDUN Pro privacy-threat-modeling assistant analyzing one DFD data flow.

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

{ctx.as_prompt_block()}

Instructions:
- For each applicable threat type listed above, decide whether a genuine threat exists for THIS flow, using only the flow description and context given. Do not pad the list to cover every type -- omit types with no real evidence.
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}" (whichever element the threat is actually located at).
- tree_node must be one of the node ids listed above under the chosen threat_type.
- If you are not confident in a citation, say so in uncertainty_note rather than asserting it silently.
Respond using the emit_threats tool."""


def build_rag_prompt(flow: dict, elements_by_id: dict, hits: list) -> str:
    """RAG ablation: same task as build_grounded_prompt, but the context is top-k semantically
    retrieved chunks (retrieval/index.py's Hit objects) rather than an exhaustive deterministic
    lookup. Retrieval can miss the right passage, so -- unlike the deterministic prompt, which
    tells the model tree_node MUST come from the listed set -- this one frames the context as
    guidance, not an authoritative menu (mirroring how PriMod4AI's own RAG prompt template treats
    retrieved context as guidance the model combines with its own expertise, not a hard constraint)."""
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])

    if hits:
        context = "\n\n".join(
            f"[{i + 1}] ({h.chunk.source}/{h.chunk.doc} §{h.chunk.section})\n{h.chunk.text}"
            for i, h in enumerate(hits)
        )
    else:
        context = "(no relevant knowledge-base passages retrieved)"

    return f"""You are a LINDDUN Pro privacy-threat-modeling assistant analyzing one DFD data flow.

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

Retrieved knowledge-base context (top-{len(hits)} semantic+keyword matches; may be incomplete or approximate):
{context}

Instructions:
- Use the retrieved context above as guidance together with your own LINDDUN knowledge -- it was
  found by similarity search and may not cover the most relevant methodology passage for this flow.
- Identify any genuine privacy threats for THIS flow, classified under one of LINDDUN's seven
  threat types (L, I, Nr, D, Dd, U, Nc). Do not pad the list -- omit types with no real evidence.
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}" (whichever element the threat is actually located at).
- tree_node should be a LINDDUN Pro threat-tree node id (e.g. "Dd.1.1"): use one from the retrieved
  context if it genuinely applies, or your own best judgement if the context doesn't cover it.
- If you are not confident in a citation, say so in uncertainty_note rather than asserting it silently.
Respond using the emit_threats tool."""


def _panoptic_menu(taxonomy: dict) -> str:
    lines = ["PANOPTIC Privacy Activities (MITRE PANOPTIC taxonomy):"]
    for pa in taxonomy["privacy_activities"]:
        lt = ", ".join(pa.get("linddun_types", []))
        lines.append(f"\n{pa['id']} {pa['name']} (LINDDUN types: {lt}):")
        for sub in pa.get("sub_activities", []):
            lines.append(f"  {sub['id']} — {sub['name']}: {sub.get('description', '')}")
    return "\n".join(lines)


def build_panoptic_prompt(flow: dict, elements_by_id: dict, taxonomy: dict) -> str:
    """PANOPTIC mode: grounds the model in MITRE PANOPTIC's own taxonomy (Privacy Activities +
    sub-activities) instead of LINDDUN's threat trees/mapping table. Like rag/ungrounded, every
    flow is attempted -- PANOPTIC has no Process-mediation restriction the way LINDDUN Pro's
    Table 4.1 does, so it's not gated the way grounded mode is. Asks for a panoptic_action
    citation as the primary grounding, plus a best-effort threat_type/tree_node (constrained to
    the LINDDUN types the chosen activity's parent maps to per panoptic_crosswalk.json) so output
    remains scoreable against the standard per-LINDDUN-category metrics too."""
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])
    menu = _panoptic_menu(taxonomy)

    return f"""You are a privacy-threat-modeling assistant analyzing one DFD data flow using the MITRE PANOPTIC framework (Pattern and Action Nomenclature Of Privacy Threats In Context) instead of LINDDUN's own DFD-position methodology.

PANOPTIC identifies privacy attacks as real-world action patterns (Privacy Activities) rather than requiring a mediating Process the way LINDDUN Pro's interaction table does -- so every flow, including direct entity-to-store, store-to-store, and entity-to-entity interactions, is in scope for this analysis.

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

{menu}

Instructions:
- Identify any genuine privacy threats for THIS flow by finding which PANOPTIC Privacy Activity sub-item(s) above actually apply. Do not pad the list -- omit activities with no real evidence.
- panoptic_action must be one of the sub-activity ids listed above (e.g. "PA03.09").
- Also provide your best-effort threat_type: pick a LINDDUN type from the "LINDDUN types" listed for the chosen panoptic_action's parent activity.
- tree_node: give your best LINDDUN Pro threat-tree node id for that type. If you're not confident, say so in uncertainty_note rather than asserting it silently.
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}" (whichever element the threat is actually located at).
Respond using the emit_threats tool."""


def build_panoptic_rag_prompt(flow: dict, elements_by_id: dict, hits: list) -> str:
    """PANOPTIC RAG ablation: same task as build_panoptic_prompt, but the context is top-k
    semantically retrieved chunks from the "panoptic" corpus (retrieval/index.py) instead of the
    full 100-sub-activity taxonomy. Mirrors build_rag_prompt()'s framing -- retrieved context is
    guidance, not an exhaustive menu -- for the same reason: retrieval can miss the right passage."""
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])

    if hits:
        context = "\n\n".join(
            f"[{i + 1}] ({h.chunk.source}/{h.chunk.doc} §{h.chunk.section})\n{h.chunk.text}"
            for i, h in enumerate(hits)
        )
    else:
        context = "(no relevant knowledge-base passages retrieved)"

    return f"""You are a privacy-threat-modeling assistant analyzing one DFD data flow using the MITRE PANOPTIC framework (Pattern and Action Nomenclature Of Privacy Threats In Context) instead of LINDDUN's own DFD-position methodology.

PANOPTIC identifies privacy attacks as real-world action patterns (Privacy Activities) rather than requiring a mediating Process -- so every flow, including direct entity-to-store, store-to-store, and entity-to-entity interactions, is in scope for this analysis.

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

Retrieved PANOPTIC knowledge-base context (top-{len(hits)} semantic+keyword matches; may be incomplete or approximate):
{context}

Instructions:
- Use the retrieved context above as guidance together with your own knowledge of PANOPTIC -- it was found by similarity search and may not cover the most relevant activity for this flow.
- Identify any genuine privacy threats for THIS flow by finding which PANOPTIC Privacy Activity sub-item(s) apply. Do not pad the list -- omit activities with no real evidence.
- panoptic_action should be a PANOPTIC sub-activity id (e.g. "PA03.09"): use one from the retrieved context if it genuinely applies, or your own best judgement if the context doesn't cover it.
- Also provide your best-effort threat_type (a LINDDUN type) and tree_node.
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}" (whichever element the threat is actually located at).
- If you are not confident in a citation, say so in uncertainty_note rather than asserting it silently.
Respond using the emit_threats tool."""


def build_panoptic_ungrounded_prompt(flow: dict, elements_by_id: dict) -> str:
    """PANOPTIC ablation baseline: no PANOPTIC taxonomy context at all. Whatever panoptic_action
    id the model produces comes entirely from its own training knowledge of PANOPTIC, not this
    repo's knowledge base -- the PANOPTIC analogue of build_ungrounded_prompt()."""
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])
    return f"""You are a privacy-threat-modeling assistant analyzing one DFD data flow using the MITRE PANOPTIC framework (Pattern and Action Nomenclature Of Privacy Threats In Context) from your own knowledge (no reference material is provided).

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

Identify any privacy threats for this flow. For each, give your best PANOPTIC sub-activity id (panoptic_action) and your best-effort LINDDUN threat_type and tree_node.
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}".
- If you are not confident in a panoptic_action id, say so in uncertainty_note rather than asserting it silently.
Respond using the emit_threats tool."""


def build_ungrounded_prompt(flow: dict, elements_by_id: dict) -> str:
    src_line = _element_line(elements_by_id, flow["source"])
    dst_line = _element_line(elements_by_id, flow["destination"])
    return f"""You are a privacy-threat-modeling assistant analyzing one DFD data flow using the LINDDUN methodology from your own knowledge (no reference material is provided).

Flow {flow['id']}: {src_line} -> {dst_line}
Flow description: {flow['description']}

Identify any privacy threats for this flow. For each, classify it under a LINDDUN threat type (L, I, Nr, D, Dd, U, or Nc) and give your best LINDDUN Pro threat-tree node id.
- originator_id must be exactly "{flow['source']}" or "{flow['destination']}".
- If you are not confident in a node id, say so in uncertainty_note rather than asserting it silently.
Respond using the emit_threats tool."""
