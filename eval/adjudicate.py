"""Manual FP adjudication: the last stage of the eval pipeline, added because our gold standards
are curated catalogs, not exhaustive enumerations. Automated precision (tp / (tp + fp)) treats
every unmatched generated threat as wrong, but some of those "false positives" are threats the
model found that the gold standard simply never catalogued. There is no deterministic check for
this the way generation/verify.py checks a citation -- whether an uncatalogued threat is real is
a human judgment call, not a KB lookup.

This module builds a worklist of a scenario+mode's unmatched (FP) generated threats, lets a human
label each one (spurious / valid_uncatalogued / borderline) via a terminal review loop, and turns
those labels into a corrected precision estimate that can sit alongside the raw one. Unlike
verify.py, results here are only as good as the reviewer -- this is deliberately NOT LLM-automated,
since self-reported correctness is exactly what the rest of this project treats as untrustworthy.
"""
from __future__ import annotations
import json
import random
from dataclasses import dataclass
from pathlib import Path

import config
from generation.schema import GeneratedThreat
from generation.verify import verify_threat
from eval.match import MatchResult

ADJUDICATION_DIR = config.ROOT / "storage" / "adjudication"
LABELS = ("spurious", "valid_uncatalogued", "borderline")
LABEL_KEYS = {"s": "spurious", "v": "valid_uncatalogued", "b": "borderline"}


def fp_indices(generated: list[GeneratedThreat], match: MatchResult) -> list[int]:
    """Indices into `generated` of threats that matched no gold threat -- match.fp's members,
    made concrete so they can be sampled/reviewed individually."""
    return [gi for gi in range(len(generated)) if gi not in match.gen_to_gold]


def worklist_path(scenario: str, mode: str) -> Path:
    return ADJUDICATION_DIR / f"{scenario}_{mode}.json"


def build_worklist(scenario: str, mode: str, generated: list[GeneratedThreat], match: MatchResult,
                    dfd: dict, n: int | None = None, seed: int = 42) -> Path:
    """Create or extend the adjudication worklist file for this scenario+mode's FPs.

    Resumable and additive: existing records (including any labels already given) are preserved
    untouched. n=None puts every FP on the worklist; a smaller n adds a seeded-random sample of
    the *unlabeled* remainder, so re-running with a bigger n later tops up the same file rather
    than reshuffling it. The seed makes the sample reproducible across runs/machines.
    """
    path = worklist_path(scenario, mode)
    existing: dict[int, dict] = {}
    if path.exists():
        for rec in json.loads(path.read_text()):
            existing[rec["gen_index"]] = rec

    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    flows_by_id = {f["id"]: f for f in dfd["flows"]}
    all_fp = fp_indices(generated, match)
    already_on_list = [gi for gi in all_fp if gi in existing]
    remaining = [gi for gi in all_fp if gi not in existing]

    if n is None:
        to_add = remaining
    else:
        want = max(0, n - len(already_on_list))
        rng = random.Random(seed)
        to_add = rng.sample(remaining, min(want, len(remaining)))

    for gi in to_add:
        t = generated[gi]
        flow = flows_by_id.get(t.flow_id)
        src = elements_by_id.get(flow["source"]) if flow else None
        dst = elements_by_id.get(flow["destination"]) if flow else None
        v = verify_threat(t, dfd)
        existing[gi] = {
            "gen_index": gi,
            "flow_id": t.flow_id,
            "flow_description": flow.get("description", "") if flow else "",
            "source": src["name"] if src else t.flow_id,
            "destination": dst["name"] if dst else "",
            "threat_type": t.threat_type,
            "tree_node": t.tree_node,
            "title": t.title,
            "description": t.description,
            "assumptions": t.assumptions,
            "uncertainty_note": t.uncertainty_note,
            "citation_all_valid": v.all_valid,
            "citation_reasons": v.reasons,
            "label": None,
            "note": "",
        }

    ADJUDICATION_DIR.mkdir(parents=True, exist_ok=True)
    ordered = [existing[gi] for gi in sorted(existing)]
    path.write_text(json.dumps(ordered, indent=2))
    return path


def review_cli(path: Path) -> None:
    """Interactive terminal review of every unlabeled record in `path`. Saves after each answer
    so quitting (or crashing) mid-session loses at most the item in progress, not prior labels."""
    records = json.loads(path.read_text())
    unlabeled = [r for r in records if r["label"] is None]
    if not unlabeled:
        print(f"Nothing to review in {path} -- every item already labeled.")
        return
    print(f"{len(unlabeled)} unlabeled item(s) in {path}.\n"
          "Labels: [s]purious (not a real threat) / [v]alid but uncatalogued (real threat, gold "
          "just missed it) / [b]orderline (unclear) / [q]uit (saves progress so far)\n")
    for i, r in enumerate(unlabeled, 1):
        flag = "  [citation INVALID]" if not r["citation_all_valid"] else ""
        print(f"--- {i}/{len(unlabeled)}  (gen_index={r['gen_index']}){flag}")
        print(f"Flow: {r['source']} -> {r['destination']}  ({r['flow_id']}: {r['flow_description']})")
        print(f"Type: {r['threat_type']}  Node: {r['tree_node']}")
        print(f"Title: {r['title']}")
        print(f"Description: {r['description']}")
        if r["assumptions"]:
            print(f"Assumptions: {r['assumptions']}")
        if r["uncertainty_note"]:
            print(f"Model's own uncertainty note: {r['uncertainty_note']}")
        if not r["citation_all_valid"]:
            print(f"Citation check failed: {r['citation_reasons']}")
        while True:
            ans = input("Label [s/v/b/q]: ").strip().lower()
            if ans == "q":
                path.write_text(json.dumps(records, indent=2))
                labeled = sum(1 for x in records if x["label"])
                print(f"Saved progress ({labeled}/{len(records)} labeled).")
                return
            if ans in LABEL_KEYS:
                r["label"] = LABEL_KEYS[ans]
                r["note"] = input("Note (optional): ").strip()
                break
            print("Enter s, v, b, or q.")
        path.write_text(json.dumps(records, indent=2))
        print()
    labeled = sum(1 for x in records if x["label"])
    print(f"Done. {labeled}/{len(records)} labeled.")


@dataclass
class HumanCorrectedPrecision:
    n_fp_total: int
    n_labeled: int
    spurious: int
    valid_uncatalogued: int
    borderline: int
    precision_raw: float          # tp / (tp + fp_total) -- the conservative lower bound
    precision_corrected: float    # point estimate; borderline split 50/50 toward each side
    is_full_review: bool          # n_labeled == n_fp_total: exact, not an extrapolation


def human_corrected_precision(tp: int, fp_total: int,
                               path: Path) -> HumanCorrectedPrecision | None:
    """Turn adjudication labels into a corrected precision estimate. Returns None if the
    worklist doesn't exist yet or nothing on it has been labeled.

    If only a sample was labeled (n_labeled < fp_total), the sample's spurious/valid split is
    extrapolated across the full FP count -- valid only insofar as the sample is representative,
    which holds by construction for build_worklist()'s random sampling but not for a hand-picked
    subset. `borderline` items are split 50/50 toward spurious/valid for this single point
    estimate; the full label breakdown is returned alongside so a reader can recompute either
    bound (all-borderline-spurious vs. all-borderline-valid) themselves.
    """
    if not path.exists():
        return None
    records = json.loads(path.read_text())
    labeled = [r for r in records if r["label"] is not None]
    if not labeled:
        return None

    spurious = sum(1 for r in labeled if r["label"] == "spurious")
    valid = sum(1 for r in labeled if r["label"] == "valid_uncatalogued")
    borderline = sum(1 for r in labeled if r["label"] == "borderline")
    n = len(labeled)

    scale = fp_total / n
    spurious_est = spurious * scale + borderline * scale * 0.5
    valid_est = valid * scale + borderline * scale * 0.5
    tp_corrected = tp + valid_est

    precision_raw = tp / (tp + fp_total) if (tp + fp_total) else 0.0
    denom = tp_corrected + spurious_est
    precision_corrected = tp_corrected / denom if denom else 0.0

    return HumanCorrectedPrecision(
        n_fp_total=fp_total, n_labeled=n, spurious=spurious, valid_uncatalogued=valid,
        borderline=borderline, precision_raw=precision_raw, precision_corrected=precision_corrected,
        is_full_review=(n == fp_total),
    )
