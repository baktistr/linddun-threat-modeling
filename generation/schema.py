"""Structured schema for LLM-generated LINDDUN threats.

Mirrors the gold-standard threat shape (knowledge_base/scenarios/*/gold_standard_threats.json:
interaction, originator_id, tree_node, threat_type, title, description, assumptions, severity,
likelihood) plus the citation the abstract's traceability claim adds on top of tree_node:
originator_id doubles as the DFD-location citation (verified against dfd.json instead of trusted).
uncertainty_note lets the model flag low confidence instead of asserting a citation it isn't sure
about.
"""
from __future__ import annotations
from dataclasses import dataclass, field, fields, asdict


@dataclass
class GeneratedThreat:
    flow_id: str                  # the dfd.json flow id this threat was generated for, e.g. "DF1"
    originator_id: str            # DFD element id the threat is located at -- the location citation
    threat_type: str              # one of L, I, Nr, D, Dd, U, Nc
    tree_node: str                # LINDDUN Pro threat-tree node id, e.g. "Dd.1.1" -- the methodology citation
    title: str
    description: str
    assumptions: str = ""
    severity: str = ""
    likelihood: str = ""
    uncertainty_note: str = ""
    grounded: bool = True         # whether this threat came from the grounded or ungrounded (ablation) pipeline

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def field_names(cls) -> set[str]:
        return {f.name for f in fields(cls)}

    @classmethod
    def from_dict(cls, d: dict) -> "GeneratedThreat":
        known = cls.field_names()
        return cls(**{k: v for k, v in d.items() if k in known})


# Claude tool-use schema: forces structured output instead of parsing free text.
THREAT_TOOL_SCHEMA = {
    "name": "emit_threats",
    "description": "Emit zero or more LINDDUN Pro privacy threats identified for this DFD data flow.",
    "input_schema": {
        "type": "object",
        "properties": {
            "threats": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "originator_id": {
                            "type": "string",
                            "description": "The DFD element id (from the provided element list) where this threat is located.",
                        },
                        "threat_type": {
                            "type": "string",
                            "enum": ["L", "I", "Nr", "D", "Dd", "U", "Nc"],
                        },
                        "tree_node": {
                            "type": "string",
                            "description": "LINDDUN Pro threat-tree node id chosen from the applicable nodes provided, e.g. 'Dd.1.1'.",
                        },
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "assumptions": {"type": "string"},
                        "severity": {"type": "string", "enum": ["Low", "Med", "High"]},
                        "likelihood": {"type": "string", "enum": ["Low", "Med", "High"]},
                        "uncertainty_note": {
                            "type": "string",
                            "description": "If you are not confident this threat applies, or a citation is approximate, say so here instead of asserting it silently. Empty string if fully confident.",
                        },
                    },
                    "required": ["originator_id", "threat_type", "tree_node", "title", "description"],
                },
            }
        },
        "required": ["threats"],
    },
}
