"""Recall/precision/F1 per LINDDUN category, plus citation-correctness aggregation."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass

from generation.schema import GeneratedThreat
from generation.verify import VerificationResult

LINDDUN_TYPES = ["L", "I", "Nr", "D", "Dd", "U", "Nc"]
CATEGORY_NAMES = {
    "L": "Linking", "I": "Identifying", "Nr": "Non-repudiation", "D": "Detecting",
    "Dd": "Data Disclosure", "U": "Unawareness", "Nc": "Non-compliance",
}


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


def citation_correctness(verifications: list[VerificationResult]) -> dict:
    n = len(verifications) or 1
    return {
        "node_valid_rate": sum(v.node_valid for v in verifications) / n,
        "type_applicable_rate": sum(v.type_applicable for v in verifications) / n,
        "location_valid_rate": sum(v.location_valid for v in verifications) / n,
        "all_valid_rate": sum(v.all_valid for v in verifications) / n,
        "n": len(verifications),
    }
