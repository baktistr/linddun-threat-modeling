"""Audits every genomic gold threat's (threat_type, panoptic_actions) pairing against the
category-level PANOPTIC<->LINDDUN crosswalk (knowledge_base/linddun/panoptic_crosswalk.json,
built from NIST SP 1800-43C Appendix G Figures 19/19b -- see build_panoptic_crosswalk.py).

This does NOT re-derive the gold standard's own pairing -- that's NIST's own validated analysis
(Appendix D step 10a). It checks whether this repo's *transcription* of that pairing is internally
consistent with the general crosswalk NIST itself says was used to perform that validation: for
each gold threat, is its threat_type a LINDDUN type the crosswalk actually allows for at least one
of its panoptic_actions' parent PANOPTIC categories (e.g. "PA03.09" -> parent category "PA03")?
"""
from __future__ import annotations
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CROSSWALK_PATH = ROOT / "knowledge_base" / "linddun" / "panoptic_crosswalk.json"
GOLD_PATH = ROOT / "knowledge_base" / "scenarios" / "genomic" / "gold_standard_threats.json"

PARENT_RE = re.compile(r"^(PA\d{2})")


def parent_category(panoptic_action: str) -> str | None:
    m = PARENT_RE.match(panoptic_action)
    return m.group(1) if m else None


def audit() -> dict:
    crosswalk = json.loads(CROSSWALK_PATH.read_text())
    panoptic_to_linddun = crosswalk["panoptic_to_linddun"]
    gold = json.loads(GOLD_PATH.read_text())["threats"]

    consistent, inconsistent, no_categories = [], [], []
    for t in gold:
        cats = {parent_category(a) for a in t.get("panoptic_actions", [])}
        cats.discard(None)
        if not cats:
            no_categories.append(t["id"])
            continue
        allowed_types = {lt for c in cats for lt in panoptic_to_linddun.get(c, [])}
        if t["threat_type"] in allowed_types:
            consistent.append(t["id"])
        else:
            inconsistent.append({
                "id": t["id"], "threat_type": t["threat_type"], "panoptic_actions": t["panoptic_actions"],
                "parent_categories": sorted(cats), "crosswalk_allows": sorted(allowed_types),
            })
    return {
        "n_total": len(gold), "n_consistent": len(consistent), "n_inconsistent": len(inconsistent),
        "n_no_categories": len(no_categories), "inconsistent": inconsistent,
    }


def main():
    report = audit()
    print(f"Audited {report['n_total']} genomic gold threats against the PANOPTIC<->LINDDUN crosswalk")
    print(f"  consistent:                 {report['n_consistent']}")
    print(f"  inconsistent:                {report['n_inconsistent']}")
    print(f"  no panoptic_actions parsed:  {report['n_no_categories']}")
    if report["inconsistent"]:
        print("\nInconsistent threats:")
        for row in report["inconsistent"]:
            print(f"  #{row['id']}: type={row['threat_type']}  panoptic={row['panoptic_actions']}")
            print(f"        parent categories {row['parent_categories']} only allow {row['crosswalk_allows']}")


if __name__ == "__main__":
    main()
