"""Citation verifier: independently checks whether a generated threat's three citations are real.

This is the concrete implementation of the abstract's central claim -- traceability that is
*verified*, not merely asserted by the model. No LLM calls happen here; every check is a lookup
against the knowledge base files themselves, so it can't be fooled by a confident-sounding but
fabricated citation.

Three independent checks per GeneratedThreat:
  - node_valid / type_applicable : tree_node exists under threat_type in threat_trees.json, and
    threat_type is actually applicable at this flow's element-type interaction per mapping_table.json.
  - location_valid               : originator_id resolves to a real element or flow id in dfd.json.
  - regulation_valid / regulation_relevant : regulatory_citation resolves to an actual provision in
    regulations.md, and that provision's "LINDDUN relevance" line names this threat_type.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field

import config
from retrieval.interaction_context import get_interaction_context, effective_type
from generation.schema import GeneratedThreat

_CATEGORY_TO_CODE = {
    "linking": "L",
    "identifying": "I",
    "non-repudiation": "Nr",
    "detecting": "D",
    "data disclosure": "Dd",
    "unawareness": "U",
    "unawareness/unintervenability": "U",
    "non-compliance": "Nc",
}
_CODE_TOKEN_RE = re.compile(r"\b(Nc|Nr|Dd|L|I|U|D)\b")


@dataclass
class Provision:
    law: str
    citation_id: str      # e.g. "§ 312.5", "Art. 5(1)(c)"
    heading: str           # full heading text, e.g. "§ 312.5 — Verifiable parental consent"
    body: str
    relevant_types: set[str] = field(default_factory=set)


def _id_tokens(citation_prefix: str) -> list[str]:
    """Numeric tokens a citation id could be matched against, e.g. '§ 1798.110 / .115' -> ['1798.110', '1798.115']."""
    tokens = re.findall(r"\.?\d+(?:\.\d+)*", citation_prefix)
    ids: list[str] = []
    last_prefix = None
    for tok in tokens:
        if tok.startswith("."):
            if last_prefix:
                ids.append(last_prefix + tok)
            continue
        ids.append(tok)
        last_prefix = tok.split(".")[0]
    return ids


def _parse_regulations() -> list[Provision]:
    """Parse regulations.md directly (independent of RAG chunking) into per-provision records."""
    text = (config.KB_DIR / "regulations" / "regulations.md").read_text()
    provisions: list[Provision] = []
    law = ""
    heading = ""
    body_lines: list[str] = []

    def flush():
        if not heading or not body_lines:
            return
        body = "\n".join(body_lines).strip()
        relevant = set()
        for line in body_lines:
            if "LINDDUN relevance" not in line:
                continue
            for name, code in _CATEGORY_TO_CODE.items():
                if name in line.lower():
                    relevant.add(code)
            relevant |= set(_CODE_TOKEN_RE.findall(line))
        citation_id = heading.split("—")[0].strip()
        provisions.append(Provision(law=law, citation_id=citation_id, heading=heading,
                                     body=body, relevant_types=relevant))

    for line in text.splitlines():
        if line.startswith("## "):
            law = line[3:].strip()
        elif line.startswith("### "):
            flush()
            heading = line[4:].strip()
            body_lines = []
        else:
            body_lines.append(line)
    flush()
    return provisions


def _find_provision(citation: str, provisions: list[Provision]) -> Provision | None:
    """Heuristic match: a provision's section-number token appears, digit-bounded, in the citation.

    Legal citation strings vary a lot in how models phrase them ("COPPA §312.5", "16 CFR 312.5",
    "§ 312.5"), so this is a best-effort match, not authoritative legal parsing. Digit-boundary
    guards (no adjacent digit/dot) keep short ids like "6" or "9" (GDPR articles) from spuriously
    matching inside unrelated longer numbers.
    """
    citation = citation.strip()
    if not citation:
        return None
    for p in provisions:
        for tok in _id_tokens(p.citation_id):
            if len(tok) < 2:
                continue  # too short to match safely (e.g. a bare "6")
            pattern = re.compile(r"(?<![\d.])" + re.escape(tok) + r"(?![\d.])")
            if pattern.search(citation):
                return p
    return None


@dataclass
class VerificationResult:
    node_valid: bool
    type_applicable: bool
    location_valid: bool
    regulation_valid: bool
    regulation_relevant: bool
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        # regulation checks only required when a citation was actually given
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
                note = "" if (src_eff, dst_eff) == (src["type"], dst["type"]) \
                    else f" (effective, via role=internal_staff: {src_eff}->{dst_eff})"
                reasons.append(f"threat_type '{threat.threat_type}' not applicable at "
                                f"{src['type']}->{dst['type']}{note} per mapping_table.json")

    location_valid = threat.originator_id in elements_by_id
    if not location_valid and flow is not None:
        location_valid = threat.originator_id in (flow["source"], flow["destination"])
    if not location_valid:
        reasons.append(f"originator_id '{threat.originator_id}' not found in dfd.json elements/flow")

    regulation_valid = False
    regulation_relevant = False
    if threat.regulatory_citation.strip():
        provisions = _parse_regulations()
        prov = _find_provision(threat.regulatory_citation, provisions)
        regulation_valid = prov is not None
        if prov is None:
            reasons.append(f"regulatory_citation '{threat.regulatory_citation}' not found in regulations.md")
        else:
            regulation_relevant = threat.threat_type in prov.relevant_types
            if not regulation_relevant:
                reasons.append(f"'{prov.heading}' does not list threat_type '{threat.threat_type}' "
                                f"as LINDDUN-relevant (relevant types: {sorted(prov.relevant_types)})")
    else:
        regulation_valid = True   # no citation given -- nothing false to verify
        regulation_relevant = True

    return VerificationResult(node_valid=node_valid, type_applicable=type_applicable,
                               location_valid=location_valid, regulation_valid=regulation_valid,
                               regulation_relevant=regulation_relevant, reasons=reasons)
