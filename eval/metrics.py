"""Recall/precision/F1 per LINDDUN category, plus citation-correctness aggregation."""
from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass

from generation.schema import GeneratedThreat
from generation.verify import VerificationResult

LINDDUN_TYPES = ["L", "I", "Nr", "D", "Dd", "U", "Nc"]
CATEGORY_NAMES = {
    "L": "Linking", "I": "Identifying", "Nr": "Non-repudiation", "D": "Detecting",
    "Dd": "Data Disclosure", "U": "Unawareness", "Nc": "Non-compliance",
}

PANOPTIC_PARENT_RE = re.compile(r"^(PA\d{2})")


@dataclass
class CategoryScore:
    threat_type: str
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def per_category_scores(generated: list[GeneratedThreat], gold: list[dict],
                         gen_to_gold: dict[int, int], matched_gold_ids: set[int]
                         ) -> dict[str, CategoryScore]:
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)

    for idx, t in enumerate(generated):
        if idx in gen_to_gold:
            tp[t.threat_type] += 1
        else:
            fp[t.threat_type] += 1
    for g in gold:
        if g["id"] not in matched_gold_ids:
            fn[g["threat_type"]] += 1

    return {tt: CategoryScore(tt, tp[tt], fp[tt], fn[tt]) for tt in LINDDUN_TYPES}


def per_node_scores(generated: list[GeneratedThreat], gold: list[dict],
                     gen_to_gold: dict[int, int], matched_gold_ids: set[int]
                     ) -> dict[str, CategoryScore]:
    """Same as per_category_scores but grouped by tree_node instead of threat_type -- finds where
    misses concentrate below the top-level LINDDUN category. CategoryScore.threat_type holds a
    tree_node id here (e.g. "Dd.1.1"), not a type code; the field is reused rather than renamed
    to avoid an unrelated cross-cutting rename."""
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)

    for idx, t in enumerate(generated):
        if idx in gen_to_gold:
            tp[t.tree_node] += 1
        else:
            fp[t.tree_node] += 1
    for g in gold:
        if g["id"] not in matched_gold_ids:
            fn[g["tree_node"]] += 1

    nodes = set(tp) | set(fp) | set(fn)
    return {n: CategoryScore(n, tp[n], fp[n], fn[n]) for n in sorted(nodes)}


def _panoptic_parent(action: str) -> str:
    m = PANOPTIC_PARENT_RE.match(action or "")
    return m.group(1) if m else "?"


def per_panoptic_category_scores(generated: list[GeneratedThreat], gold: list[dict],
                                  gen_to_gold: dict[int, int], matched_gold_ids: set[int]
                                  ) -> dict[str, CategoryScore]:
    """Same shape as per_category_scores, grouped by PANOPTIC parent category (e.g. "PA03" from
    a "PA03.09" sub-activity id) instead of LINDDUN threat_type. Only scores generated threats
    that carry a panoptic_action (i.e. mode="panoptic" output); pair with match_threats_panoptic().

    A gold threat's panoptic_actions can span multiple parent categories (e.g. genomic gold #1
    touches PA03, PA08, PA10, PA11 all at once) -- unlike LINDDUN's one-threat-type-per-threat
    assumption. To keep totals additive (so summing every category's tp/fp/fn reproduces the
    overall counts, matching per_category_scores' invariant), an unmatched gold threat's FN is
    counted once, under the parent category of its *first* listed panoptic_action only -- a
    simplification, not a claim that the other categories weren't also missed."""
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)

    for idx, t in enumerate(generated):
        if not t.panoptic_action:
            continue
        cat = _panoptic_parent(t.panoptic_action)
        if idx in gen_to_gold:
            tp[cat] += 1
        else:
            fp[cat] += 1
    for g in gold:
        if g["id"] in matched_gold_ids:
            continue
        actions = g.get("panoptic_actions") or []
        if actions:
            fn[_panoptic_parent(actions[0])] += 1

    cats = set(tp) | set(fp) | set(fn)
    return {c: CategoryScore(c, tp[c], fp[c], fn[c]) for c in sorted(cats)}


def citation_correctness(verifications: list[VerificationResult]) -> dict:
    n = len(verifications) or 1
    return {
        "node_valid_rate": sum(v.node_valid for v in verifications) / n,
        "type_applicable_rate": sum(v.type_applicable for v in verifications) / n,
        "location_valid_rate": sum(v.location_valid for v in verifications) / n,
        "all_valid_rate": sum(v.all_valid for v in verifications) / n,
        "n": len(verifications),
    }
