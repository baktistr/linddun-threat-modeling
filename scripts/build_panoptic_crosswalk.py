"""Builds knowledge_base/linddun/panoptic_crosswalk.json from a vision-transcription of NIST SP
1800-43C Appendix G, Figures 19 (PANOPTIC-indexed) and 19b (LINDDUN-indexed) -- the general
taxonomy-level PANOPTIC<->LINDDUN crosswalk Appendix D step 10a describes using to mutually
validate threats ("Leveraging the PANOPTIC-LINDDUN mapping, confirm that there is at least one
entry in the combined LINDDUN analysis table related to each PANOPTIC attack... Eliminate...
LINDDUN threats unrelated to any PANOPTIC attack"). NIST's own methodology (Appendix D steps 7-10)
runs LINDDUN threat-tree elicitation per DFD segment and PANOPTIC Privacy Activities mapping per
use case as two separate passes, then keeps only threats present in both -- this crosswalk is the
static reference table that validation step uses, not itself a list of per-threat pairings.

This is a *category-level* crosswalk (13 PANOPTIC Privacy Activities <-> 7 LINDDUN threat types).
Figures 19/19b are also readable at a finer PANOPTIC-sub-activity / LINDDUN-tree-node granularity,
but that level wasn't cross-verified against two independent transcriptions the way the rest of
this repo's genomic data is (see verify_genomic.py) -- deliberately left out here rather than risk
baking in an unverified fine-grained pairing.

Cross-checked both transcription directions against each other (fig19's PANOPTIC->LINDDUN column
vs fig19b's LINDDUN->PANOPTIC column): 12/13 categories agree exactly in both directions. The one
exception is PA12 (Retention & Destruction): fig19 tags it only "Dd", but fig19b's Non-Compliance
section also cites PA12. Kept as the union (Dd + Nc) rather than silently discarding the
asymmetric reading -- recorded in _meta.asymmetries below so it isn't re-litigated later.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_PATH = ROOT / "scripts" / "data" / "panoptic_crosswalk_raw.json"
OUT_PATH = ROOT / "knowledge_base" / "linddun" / "panoptic_crosswalk.json"


def build() -> dict:
    raw = json.loads(RAW_PATH.read_text())
    fig19 = {r["panoptic_category"]: r for r in raw["fig19_panoptic_to_linddun"]}
    fig19b = {r["linddun_type"]: r for r in raw["fig19b_linddun_to_panoptic"]}

    panoptic_to_linddun: dict[str, set[str]] = {}
    for cat, row in fig19.items():
        panoptic_to_linddun.setdefault(cat, set()).update(row["linddun_types"])
    for lt, row in fig19b.items():
        for cat in row["panoptic_categories"]:
            panoptic_to_linddun.setdefault(cat, set()).add(lt)

    linddun_to_panoptic: dict[str, set[str]] = {}
    for lt, row in fig19b.items():
        linddun_to_panoptic.setdefault(lt, set()).update(row["panoptic_categories"])
    for cat, row in fig19.items():
        for lt in row["linddun_types"]:
            linddun_to_panoptic.setdefault(lt, set()).add(cat)

    asymmetries = []
    for cat in fig19:
        f19_types = set(fig19[cat]["linddun_types"])
        f19b_types = {lt for lt, row in fig19b.items() if cat in row["panoptic_categories"]}
        if f19_types != f19b_types:
            asymmetries.append({"panoptic_category": cat, "fig19_linddun_types": sorted(f19_types),
                                 "fig19b_linddun_types": sorted(f19b_types)})

    out = {
        "_meta": {
            "source": "NIST SP 1800-43C Appendix G, Figures 19 (PANOPTIC->LINDDUN) and 19b (LINDDUN->PANOPTIC)",
            "source_path": "references/nist-sp-1800-43c/appendix/media/Appendix-Figure19.png, "
                           "Appendix-Figure19b.png",
            "granularity": "category-level only (13 PANOPTIC Privacy Activities <-> 7 LINDDUN threat types) "
                           "-- NOT the finer PANOPTIC-sub-activity/LINDDUN-tree-node pairing also visible in "
                           "the figures, which wasn't cross-verified against two independent transcriptions "
                           "the way the rest of this repo's genomic data is, so it's excluded here to avoid "
                           "baking in an unverified fine-grained pairing.",
            "method": "vision-transcribed both figures independently, then cross-checked one direction "
                      "against the other for consistency.",
            "asymmetries": asymmetries,
            "raw_transcription": "scripts/data/panoptic_crosswalk_raw.json",
        },
        "panoptic_categories": {r["panoptic_category"]: r["panoptic_name"]
                                 for r in raw["fig19_panoptic_to_linddun"]},
        "linddun_types": {r["linddun_type"]: r["linddun_name"] for r in raw["fig19b_linddun_to_panoptic"]},
        "panoptic_to_linddun": {cat: sorted(types) for cat, types in sorted(panoptic_to_linddun.items())},
        "linddun_to_panoptic": {lt: sorted(cats) for lt, cats in sorted(linddun_to_panoptic.items())},
    }
    return out


def main():
    out = build()
    OUT_PATH.write_text(json.dumps(out, indent=2) + "\n")
    print(f"Wrote {OUT_PATH}")
    print(f"  {len(out['panoptic_to_linddun'])} PANOPTIC categories, {len(out['linddun_to_panoptic'])} LINDDUN types")
    if out["_meta"]["asymmetries"]:
        print(f"  asymmetries between the two transcription directions: {out['_meta']['asymmetries']}")


if __name__ == "__main__":
    main()
