#!/usr/bin/env python3
"""Generate the Genomic Sequencing gold-standard threat catalog as structured JSON.

Source: NIST SP 1800-43C (DRAFT, August 2025), "Genomic Data Threat Modeling:
Privacy — An Implementation for Genomic Data Sequencing and Analysis" (NCCoE).
URL: https://www.nccoe.nist.gov/projects/cybersecurity-and-privacy-genomic-data

This is the **complete example** (~99 itemized LINDDUN threats across the clinical
and research sequencing pipelines plus their shared backbone), not just the small
core example presented in the PDF body. The complete analysis is published by NIST
only in the external HTML appendices (pages.nist.gov/.../Vol_C/Appendix) and there
ONLY as raster figures — there is no machine-readable table anywhere. The threats
here were therefore transcribed by vision-reading those figures:

  - Appendix G, "Threat Validations and Ranking Attributes" (Figure 20) -> node,
    scenario, PANOPTIC actions, LINDDUN analysis text, impacted PEOs, feasibility,
    attack difficulty.
  - Appendix G, "Ranked Threats" (Figure 24) -> the ranking value per threat.

The two figures were transcribed independently and cross-checked; they corroborate
each other on node / scenario / feasibility / difficulty. The raw transcription is
committed alongside this script at scripts/data/genomic_complete_raw.json so the
derivation is auditable. Because the data originates from OCR of a DRAFT figure,
treat per-threat details as transcription-confidence, not authoritative — verify
against the source figures before relying on any single row. Threat #27's
description was not legible in Figure 20 and is flagged low-confidence.

Node-ID handling: NIST's LINDDUN tree is a newer/deeper revision than this repo's
threat_trees.json. NIST nodes that do not exist in this repo's tree are mapped to
their nearest existing ancestor, with the verbatim NIST node preserved in
`nist_node` and a `mapping_note` recorded. Examples: I.2.3 -> I.2, I.2.1.1 -> I.2.1,
U.2.2/U.2.3 -> U.2, and (no ancestor in this repo's tree) Nr.2 -> Nr.1, Nc.2/Nc.4 ->
Nc.1. "DD" is normalized to this repo's "Dd".

The ten threats of the NIST *core example* (the shared pipeline subset documented in
the PDF body, attack numbers 1,3,4,5,14,15,26,55,65 + 2) are tagged
`in_core_example: true`.

severity/likelihood are convenience projections onto the KidsTube qualitative scale
(see field_notes); feasibility, difficulty, and ranking_value are the NIST values.
"""
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent.parent
RAW = Path(__file__).parent / "data" / "genomic_complete_raw.json"

# Ranking values transcribed from Appendix G "Ranked Threats" (Figure 24), keyed by
# NIST attack number. Plausible+Negligible difficulty ranks highest (1.0 * type weight).
RANK = {1:0.42,2:0.28,3:0.42,4:0.42,5:0.56,6:0.28,7:0.42,8:0.42,9:0.28,10:0.42,11:0.42,
        12:0.28,13:0.42,14:0.42,15:0.42,16:0.7,17:0.7,18:0.51,19:0.34,20:0.51,21:0.51,
        22:0.51,23:0.51,24:0.34,25:0.51,26:0.51,27:0.51,28:0.68,29:0.68,30:0.68,31:0.68,
        32:0.04,33:0.04,34:0.04,35:0.08,36:0.04,37:0.04,38:0.08,39:0.08,40:0.0,41:0.0,
        42:0.12,43:0.12,44:0.0,45:0.12,46:0.12,47:0.12,48:0.12,49:0.12,50:0.6,51:0.8,
        52:0.6,53:0.6,54:0.6,55:0.8,56:0.8,57:0.8,58:0.8,59:0.1,60:0.1,61:0.1,62:0.1,
        63:0.1,64:0.1,65:0.4,66:0.4,67:0.4,68:0.4,69:0.4,70:0.4,71:0.4,72:0.4,73:0.4,
        74:0.4,75:0.4,76:0.4,77:0.4,78:0.4,79:0.4,80:0.5,81:0.5,82:0.5,83:0.4,84:0.2,
        85:0.2,86:0.2,87:0.2,88:0.2,89:0.2,90:0.2,91:0.3,92:0.3,93:0.3,94:0.3,95:0.4,
        96:0.2,97:0.3,98:0.3,99:0.2}

# NIST core-example attack numbers (the shared-pipeline subset documented in the PDF body)
CORE_EXAMPLE = {1, 2, 3, 4, 5, 14, 15, 26, 55, 65}

# Explicit fallback for NIST nodes with no ancestor in this repo's tree (repo lacks
# the bare Nr.* / Nc.* branches NIST uses here). Maps NIST node -> nearest repo node.
HARD_REMAP = {"Nr.2": "Nr.1", "Nc.2": "Nc.1", "Nc.4": "Nc.1"}

LIKELIHOOD_FROM_FEASIBILITY = {"Plausible": "High", "Indeterminate": "Med", "Implausible": "Low"}
SEVERITY_FROM_DIFFICULTY = {"Negligible": "High", "Minor": "High", "Moderate": "Med",
                            "Significant": "Low", "Severe": "Low"}
TYPE_FROM_PREFIX = {"L": "L", "I": "I", "Nr": "Nr", "D": "D", "DD": "Dd", "Dd": "Dd",
                    "U": "U", "Nc": "Nc"}


def load_tree_nodes():
    trees = json.loads((ROOT / "knowledge_base" / "linddun" / "threat_trees.json").read_text())
    titles = {}
    for tt in trees["threat_types"].values():
        for nid, node in tt["nodes"].items():
            titles[nid] = node.get("title", "")
    return titles


def normalize_node(raw):
    n = raw.strip().replace("DD.", "Dd.")
    return "Dd" if n == "DD" else n


def nearest_ancestor(node, tree_nodes):
    parts = node.split(".")
    for i in range(len(parts), 0, -1):
        cand = ".".join(parts[:i])
        if cand in tree_nodes:
            return cand
    return None


def split_list(s):
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def short_title(node_title, analysis):
    a = analysis.split("[")[0].strip().rstrip(".")
    if len(a) > 90:
        a = a[:87].rsplit(" ", 1)[0] + "…"
    return f"{node_title}: {a}" if node_title else a


def main():
    titles = load_tree_nodes()
    tree_nodes = set(titles)
    raw = json.loads(RAW.read_text())

    threats = []
    remaps = 0
    low_conf = 0
    for r in sorted(raw, key=lambda x: x["attack_no"]):
        aid = r["attack_no"]
        nist_node = normalize_node(r["node"])
        ttype = TYPE_FROM_PREFIX.get(nist_node.split(".")[0], nist_node.split(".")[0])
        resolved = HARD_REMAP.get(nist_node) or nearest_ancestor(nist_node, tree_nodes)
        threat = {
            "id": aid,
            "interaction": r["scenario_id"],            # NIST PANOPTIC scenario id
            "originator_id": "",                          # DFD element not transcribed (see Fig 11)
            "tree_node": resolved,
            "nist_node": nist_node,
            "threat_type": ttype,
            "title": short_title(titles.get(resolved, ""), r["analysis"]),
            "description": r["analysis"],
            "assumptions": "",
            "severity": SEVERITY_FROM_DIFFICULTY.get(r["attack_difficulty"], "Med"),
            "likelihood": LIKELIHOOD_FROM_FEASIBILITY.get(r["feasibility"], "Med"),
            "scenario_id": r["scenario_id"],
            "panoptic_actions": split_list(r["panoptic"]),
            "feasibility": r["feasibility"],
            "difficulty": r["attack_difficulty"],
            "ranking_value": RANK.get(aid),
            "impacted_peos": split_list(r["peos"]),
            "in_core_example": aid in CORE_EXAMPLE,
        }
        if resolved != nist_node:
            remaps += 1
            threat["mapping_note"] = (
                f"NIST node {nist_node} is not in this repo's threat tree (NIST uses a deeper/newer "
                f"LINDDUN revision); mapped to nearest ancestor {resolved}.")
        if r.get("_transcription") == "low_confidence":
            low_conf += 1
            threat["transcription_confidence"] = "low"
        threats.append(threat)

    catalog = {
        "_meta": {
            "scenario": "Genomic Sequencing (NIST SP 1800-43C complete example)",
            "source": ("NIST SP 1800-43C (DRAFT, August 2025), 'Genomic Data Threat Modeling: Privacy — "
                       "An Implementation for Genomic Data Sequencing and Analysis', NCCoE. Complete-example "
                       "threats transcribed (vision OCR) from Appendix G Figures 20 (validations) and 24 "
                       "(ranked threats): https://pages.nist.gov/nccoe-genomic-data-threat-modeling/Vol_C/Appendix/appendixG.html"),
            "role": "authoritative gold-standard baseline for evaluation (second scenario alongside KidsTube)",
            "revision": "v2 — complete example (~99 itemized LINDDUN threats); supersedes the v1 10-threat core-example subset",
            "threat_count": len(threats),
            "core_example_count": sum(t["in_core_example"] for t in threats),
            "node_remaps": remaps,
            "low_confidence_rows": low_conf,
            "provenance_note": ("The complete example is published by NIST ONLY as raster figures in the "
                                "external HTML appendices (no machine-readable table exists). These threats "
                                "were transcribed by vision-reading Figures 20 and 24, which were transcribed "
                                "independently and cross-checked. Raw transcription: "
                                "scripts/data/genomic_complete_raw.json. TREAT PER-THREAT DETAILS AS "
                                "TRANSCRIPTION-CONFIDENCE (OCR of a DRAFT figure), not authoritative; verify "
                                "against the source figures before relying on a single row. scripts/verify_genomic.py "
                                "cross-checks every row against Figure 24 + NIST's ranking formula (Tables 18/19): "
                                "97/99 corroborated, all 99 formula-consistent. Rows 23/24 feasibility and #27's "
                                "description were corrected against the source; the only cell not independently "
                                "re-confirmed is #24's node (I.1.2)."),
            "node_mapping_note": ("NIST's LINDDUN tree is a newer/deeper revision than this repo's "
                                  "threat_trees.json. nist_node is the verbatim NIST node; tree_node is the "
                                  "nearest ancestor present in this repo's tree (I.2.3->I.2, I.2.1.1->I.2.1, "
                                  "U.2.2/U.2.3->U.2, Nr.2->Nr.1, Nc.2/Nc.4->Nc.1, DD->Dd). A follow-up could "
                                  "instead extend the canonical tree with the missing official nodes."),
            "field_notes": ("interaction/scenario_id is the NIST PANOPTIC scenario id (the per-threat DFD "
                            "source/destination live in NIST Figure 11 and were not transcribed at high "
                            "confidence, so originator_id is left blank). feasibility, difficulty, "
                            "ranking_value, panoptic_actions, and impacted_peos are the NIST values. severity "
                            "and likelihood are convenience projections: likelihood<-feasibility "
                            "(Plausible=High, Indeterminate=Med, Implausible=Low); severity<-difficulty per "
                            "NIST Table 16 data-state sensitivity (Negligible/Minor=High, Moderate=Med, "
                            "Significant/Severe=Low). in_core_example flags the NIST core-example subset. "
                            "title is synthesized from the LINDDUN node title + analysis."),
        },
        "threats": threats,
    }
    out = ROOT / "knowledge_base" / "scenarios" / "genomic" / "gold_standard_threats.json"
    out.write_text(json.dumps(catalog, indent=2))
    print(f"Wrote {len(threats)} threats to {out}")

    ids = [t["id"] for t in threats]
    assert ids == list(range(1, len(threats) + 1)), f"ids must be 1..N contiguous; got gaps"
    types = {t["threat_type"] for t in threats}
    assert types == {"L", "I", "Nr", "D", "Dd", "U", "Nc"}, f"expected all 7 types; got {sorted(types)}"
    assert all(t["tree_node"] for t in threats), "every threat must resolve to a tree node"
    uncovered = sorted({t["tree_node"] for t in threats if t["tree_node"] not in tree_nodes})
    assert not uncovered, f"unresolved tree nodes: {uncovered}"
    print(f"Node re-maps: {remaps} | low-confidence rows: {low_conf} | core-example: {catalog['_meta']['core_example_count']}")
    print("Per-type counts:", dict(Counter(t["threat_type"] for t in threats)))
    print("All node IDs resolve against the threat trees.")


if __name__ == "__main__":
    main()
