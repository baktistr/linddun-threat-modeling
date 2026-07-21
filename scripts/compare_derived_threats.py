#!/usr/bin/env python3
"""M4: compare threat generation on the DERIVED DFD against the hand-authored DFD, over the SAME
anchorable subset of gold threats.

The derived DFD has no counterpart for some hand flows: the 2 planned-feature ceiling flows
(DF13/DF14, endpoints P4/EE3, present in no code) and whatever flows the adapter arm that built it
missed. kidstube_derived's re-anchored gold leaves the threats on those flows unanchored (no [DFn]
tag), so eval/reachability.py classifies them unresolved_location and they never count against the
derived DFD's recall. That is correct for the derived side -- but it means a straight
derived-vs-hand comparison is unfair in the OTHER direction: the hand DFD would get recall credit
for threats the derived DFD structurally cannot even be scored on.

So the hand baseline is restricted to the same anchorable subset. Restricting both sides isolates
the question that matters -- "does deriving the DFD from source cost recall?" -- from the confound
"the derived DFD simply has fewer flows". The two causes of a missing flow are kept apart (ceiling
vs. adapter miss) and reported separately, because conflating them would let a real adapter
limitation hide inside the structural ceiling.

RECALL-ONLY by design. Restricting the gold turns a generated threat that matched an excluded gold
into a false positive, so precision over a restricted gold is not meaningful; precision is reported
UNRESTRICTED (its curated-catalog lower-bound caveat, eval/adjudicate.py, is unchanged). Citation
correctness -- the metric this project argues actually moves with grounding -- is reported per side
and is independent of the subset.

The derived side needs `storage/generated/kidstube_derived_<mode>.json`, produced by
`python cli.py generate --scenario kidstube_derived [--rag|--ungrounded]`. Rows whose generated
file is absent are reported as such rather than invented, so this script is runnable before those
live runs exist (it will still print the hand baseline and the anchorable-subset accounting).

Usage:
  python scripts/compare_derived_threats.py
  python scripts/compare_derived_threats.py --hand kidstube --derived kidstube_derived
"""
from __future__ import annotations
import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from eval.match import gold_flow_id, match_threats
from eval.metrics import citation_correctness
from eval.reachability import reachability_breakdown
from generation.generate import load_generated
from generation.verify import verify_threat

GROUNDING_MODES = ("grounded", "rag", "ungrounded")


def _load(scenario: str, name: str) -> dict:
    return json.loads((config.KB_DIR / "scenarios" / scenario / name).read_text())


def anchorable_subset(hand_gold: list[dict], derived_meta: dict) -> set[int]:
    """The hand-gold threat ids that DO anchor to a flow the derived DFD has -- the complement of
    the derived gold's deliberately-unanchored ids. Read from the derived gold's own _meta so this
    can never drift from the re-anchoring that produced it (scripts/build_kidstube_derived_gold.py).
    """
    unanchored = set(derived_meta.get("unanchored_threat_ids", []))
    return {t["id"] for t in hand_gold} - unanchored


@dataclass
class RecallRow:
    n_generated: int
    matched: int
    reachable_but_missed: int
    structurally_unreachable: int
    unresolved_location: int
    raw_recall: float
    reachable_recall: float
    citation_all_valid: float

    @property
    def n_gold(self) -> int:
        return (self.matched + self.reachable_but_missed + self.structurally_unreachable
                + self.unresolved_location)


def score_recall(generated: list, gold: list[dict], scenario: str, dfd: dict) -> RecallRow:
    """Match, then compute both raw recall (vs all gold here) and reachability-adjusted recall
    (vs only the gold the per-flow pipeline could ever have produced). Reuses the exact match and
    reachability primitives eval/run_eval.py uses, so a number here means the same thing it means
    there -- the only difference is that `gold` may already be restricted to a subset."""
    match = match_threats(generated, gold, scenario=scenario, dfd=dfd)
    rc = reachability_breakdown(gold, scenario, dfd, match.matched_gold_ids)
    raw_recall = match.tp / len(gold) if gold else 0.0
    cc = citation_correctness([verify_threat(t, dfd) for t in generated])
    return RecallRow(n_generated=len(generated), matched=match.tp,
                     reachable_but_missed=rc.reachable_but_missed,
                     structurally_unreachable=rc.structurally_unreachable,
                     unresolved_location=rc.unresolved_location,
                     raw_recall=raw_recall, reachable_recall=rc.reachable_recall,
                     citation_all_valid=cc["all_valid_rate"])


def _generated_path(scenario: str, mode: str) -> Path:
    return config.ROOT / "storage" / "generated" / f"{scenario}_{mode}.json"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hand", default="kidstube", help="Hand-authored scenario (the baseline).")
    ap.add_argument("--derived", default="kidstube_derived", help="Derived scenario to compare.")
    args = ap.parse_args()

    hand_gold = _load(args.hand, "gold_standard_threats.json")["threats"]
    hand_dfd = _load(args.hand, "dfd.json")
    derived_gold_doc = _load(args.derived, "gold_standard_threats.json")
    derived_gold = derived_gold_doc["threats"]
    derived_dfd = _load(args.derived, "dfd.json")
    dmeta = derived_gold_doc["_meta"]

    anchorable = anchorable_subset(hand_gold, dmeta)
    hand_gold_restricted = [t for t in hand_gold if t["id"] in anchorable]
    ceiling = dmeta.get("unanchored_hand_flows_ceiling", [])
    adapter_miss = dmeta.get("unanchored_hand_flows_adapter_miss", [])

    print(f"M4 comparison: threats on the derived DFD ({args.derived}) vs. the hand DFD "
          f"({args.hand}),\nboth on the same anchorable gold subset.\n")
    print(f"Gold accounting (from {args.derived}/gold_standard_threats.json _meta):")
    print(f"  hand gold total                 {len(hand_gold)}")
    print(f"  anchorable (has a derived flow) {len(anchorable)}")
    print(f"  unanchored -> unresolved_location {len(hand_gold) - len(anchorable)}  "
          f"= ceiling {ceiling} (planned, no code) + adapter-miss {adapter_miss}")
    print(f"  adapter DFD that produced the derived flows: "
          f"{derived_dfd.get('_meta', {}).get('derived_from', {}).get('adapter_mode', '?')}\n")

    header = (f"{'mode':<11} {'side':<20} {'gen':>4} {'gold':>5} {'match':>6} {'RbM':>4} {'SU':>3} "
              f"{'UL':>3} {'raw_R':>6} {'reach_R':>8} {'cit_valid':>10}")
    print(header)
    print("-" * len(header))

    missing = []
    for mode in GROUNDING_MODES:
        hand_gen_path = _generated_path(args.hand, mode)
        derived_gen_path = _generated_path(args.derived, mode)

        if hand_gen_path.exists():
            hg = load_generated(str(hand_gen_path))
            full = score_recall(hg, hand_gold, args.hand, hand_dfd)
            sub = score_recall(hg, hand_gold_restricted, args.hand, hand_dfd)
            _print_row(mode, "hand (all gold)", full)
            _print_row(mode, "hand (anchorable)", sub)
        else:
            missing.append(hand_gen_path)
            print(f"{mode:<11} {'hand':<20} (not generated: cli.py generate --scenario "
                  f"{args.hand} ...)")

        if derived_gen_path.exists():
            dg = load_generated(str(derived_gen_path))
            der = score_recall(dg, derived_gold, args.derived, derived_dfd)
            _print_row(mode, "derived", der)
        else:
            missing.append(derived_gen_path)
            print(f"{mode:<11} {'derived':<20} (not generated: cli.py generate --scenario "
                  f"{args.derived}{_mode_flag(mode)})")
        print()

    print("Legend: RbM=reachable_but_missed  SU=structurally_unreachable  UL=unresolved_location")
    print("  raw_R = matched / gold-in-this-row;  reach_R = matched / (matched + RbM) -- the honest")
    print("  cross-DFD number, since it drops from the denominator what each DFD structurally can't")
    print("  produce. Compare 'hand (anchorable)' reach_R against 'derived' reach_R for each mode.")
    print("  Precision is UNRESTRICTED (see cli.py eval); citation validity is the metric grounding "
          "moves.")

    if missing:
        print(f"\n{len(missing)} generated file(s) absent -- rows above are the hand baseline and "
              "the subset accounting; the full comparison needs those live runs.")
    return 0


def _mode_flag(mode: str) -> str:
    return {"grounded": "", "rag": " --rag", "ungrounded": " --ungrounded"}[mode]


def _print_row(mode: str, side: str, r: RecallRow) -> None:
    print(f"{mode:<11} {side:<20} {r.n_generated:>4} {r.n_gold:>5} {r.matched:>6} "
          f"{r.reachable_but_missed:>4} {r.structurally_unreachable:>3} {r.unresolved_location:>3} "
          f"{r.raw_recall:>6.2f} {r.reachable_recall:>8.2f} {r.citation_all_valid:>10.2f}")


if __name__ == "__main__":
    sys.exit(main())
