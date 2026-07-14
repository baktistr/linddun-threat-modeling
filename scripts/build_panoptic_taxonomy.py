"""Builds knowledge_base/panoptic/taxonomy.json: the MITRE PANOPTIC taxonomy (5 Contextual
Domains + 13 Privacy Activities + their sub-activities), the knowledge base a "panoptic"
generation mode grounds its prompts in -- the PANOPTIC analogue of
knowledge_base/linddun/threat_trees.json.

Source: NIST SP 1800-43C Appendix C (category definitions, plain text --
references/nist-sp-1800-43c/appendix/appendixC.rst) and Appendix G Figure 19 (sub-activity
detail, vision-transcribed -- references/nist-sp-1800-43c/appendix/media/Appendix-Figure19.png).

Confidence: category names/definitions (PC01-05, PA01-13 top level) are copied verbatim from
appendixC.rst's plain-text tables -- high confidence, no OCR involved. Sub-activity id/name pairs
are vision-transcribed from Figure 19 and reasonably legible; sub-activity *descriptions* are the
part most exposed to transcription risk in a dense scanned table and should be treated the same
way this repo treats the genomic gold standard's own OCR'd figures: spot-check before relying on
an exact description string. One sub-activity id (PA02.06.02) wasn't printed in the figure and is
inferred from the surrounding pattern -- flagged with id_inferred: true in the raw data.

linddun_types per Privacy Activity are NOT duplicated here -- they're pulled from
knowledge_base/linddun/panoptic_crosswalk.json (the cross-checked, union version) so there's one
source of truth for the PANOPTIC<->LINDDUN pairing, not two files that can silently drift apart.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_PATH = ROOT / "scripts" / "data" / "panoptic_taxonomy_raw.json"
CROSSWALK_PATH = ROOT / "knowledge_base" / "linddun" / "panoptic_crosswalk.json"
OUT_DIR = ROOT / "knowledge_base" / "panoptic"
OUT_PATH = OUT_DIR / "taxonomy.json"


def build() -> dict:
    raw = json.loads(RAW_PATH.read_text())
    crosswalk = json.loads(CROSSWALK_PATH.read_text())
    panoptic_to_linddun = crosswalk["panoptic_to_linddun"]

    activities = []
    n_sub = 0
    for pa in raw["privacy_activities"]:
        activities.append({
            "id": pa["id"],
            "name": pa["name"],
            "linddun_types": panoptic_to_linddun.get(pa["id"], []),
            "sub_activities": pa["sub_activities"],
        })
        n_sub += len(pa["sub_activities"])

    out = {
        "_meta": {
            "source": "NIST SP 1800-43C Appendix C (category definitions) and Appendix G Figure 19 "
                       "(sub-activity detail)",
            "source_path": "references/nist-sp-1800-43c/appendix/appendixC.rst, "
                            "references/nist-sp-1800-43c/appendix/media/Appendix-Figure19.png",
            "confidence": "Category-level names/definitions (PC01-05, PA01-13): verbatim from "
                          "plain-text appendixC.rst, high confidence. Sub-activity id/name: "
                          "vision-transcribed from Figure 19, reasonably legible. Sub-activity "
                          "description text: the highest transcription-risk part of this file -- "
                          "treat as best-effort, spot-check against the bundled figure before "
                          "citing a specific description in a paper. PA02.06.02's id is inferred, "
                          "not printed in the source figure (see raw data's id_inferred flag). "
                          "Re-checked against a second independent read of Figure 19 (post-build "
                          "review): fixed one wording error (PA01.04), and PA03.02/PA03.03/PA03.04 "
                          "are flagged confidence=low in the raw data -- two independent "
                          "transcription passes parsed that specific densely-wrapped table region "
                          "differently and neither could be confirmed as definitively correct.",
            "raw_transcription": "scripts/data/panoptic_taxonomy_raw.json",
            "linddun_types_source": "knowledge_base/linddun/panoptic_crosswalk.json (single source "
                                     "of truth for the PANOPTIC<->LINDDUN pairing)",
        },
        "contextual_domains": raw["contextual_domains"],
        "privacy_activities": activities,
    }
    return out, n_sub


def main():
    out, n_sub = build()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=2) + "\n")
    print(f"Wrote {OUT_PATH}")
    print(f"  {len(out['contextual_domains'])} contextual domains, "
          f"{len(out['privacy_activities'])} privacy activities, {n_sub} sub-activities")


if __name__ == "__main__":
    main()
