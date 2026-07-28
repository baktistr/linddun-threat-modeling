#!/usr/bin/env python3
"""Score every experiment condition on ONE denominator, so the numbers can be compared.

Each condition anchors a different subset of the gold. The image arm reproduces the diagram's
printed flow ids, so all 41 KidsTube gold threats anchor; the source `llm` arm assigns its own
ids, so its gold is re-anchored per run and only the flows the alignment mapped survive. Reading
those two `ALL` recall rows side by side compares 12/17 against 31/41 and calls it a model
difference.

So: compute each condition's anchorable set, intersect across all of them, and re-score everyone
on that intersection. Recall-only, for the reason M4 already established -- restricting the gold
turns a generated threat that matched an excluded gold threat into a false positive, so precision
on a restricted gold is not meaningful.

Run: PYTHONPATH=. python3 scripts/compare_conditions.py [--scenario kidstube]
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import runs
from eval.match import gold_flow_id, match_threats
from eval.run_eval import load_generated

MODE = "grounded"


def anchorable(gold: list[dict], dfd: dict) -> set[int]:
    """Gold ids that carry a [DFn] tag naming a flow this DFD actually has."""
    have = {f["id"] for f in dfd["flows"]}
    return {g["id"] for g in gold if (fid := gold_flow_id(g)) and fid in have}


def collect(scenario: str) -> list[dict]:
    hand_gold_path = config.KB_DIR / "scenarios" / scenario / "gold_standard_threats.json"
    out = []
    for scen, cond, run, run_dir in runs.iter_runs(scenario):
        dfd_path = run_dir / "dfd.json"
        gen_path = runs.generated_dir(scen, cond, run) / f"{MODE}.json"
        if not (dfd_path.exists() and gen_path.exists()):
            continue
        gold_path = run_dir / "gold.json"
        if not gold_path.exists():
            gold_path = hand_gold_path
        raw = json.loads(gold_path.read_text())
        gold = raw if isinstance(raw, list) else raw["threats"]
        dfd = json.loads(dfd_path.read_text())
        generated = load_generated(gen_path)
        m = match_threats(generated, gold, scenario=scen, dfd=dfd)
        out.append({
            "condition": cond, "run": run, **runs.parse_condition(cond),
            "n_elements": len(dfd["elements"]), "n_flows": len(dfd["flows"]),
            "n_generated": len(generated),
            "anchorable": anchorable(gold, dfd),
            "matched": set(m.matched_gold_ids),
            "gold_total": len(gold),
        })
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scenario", default="kidstube")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    rows = collect(args.scenario)
    if not rows:
        raise SystemExit(f"no completed conditions under storage/derived/{args.scenario}/")

    # A condition whose re-anchoring mapped NOTHING scores 0.00 by construction, and intersecting
    # its empty set with everyone else's would silently empty the common subset and report nan for
    # the whole table. Hold it out of the intersection and name it, because "this run cannot be
    # scored" and "this model found nothing" are completely different claims and only one of them
    # is about the model.
    unscorable = [r for r in rows if not r["anchorable"]]
    scorable = [r for r in rows if r["anchorable"]]
    if not scorable:
        raise SystemExit("no condition anchors any gold threat -- nothing to compare.")
    common = set.intersection(*(r["anchorable"] for r in scorable))
    lines = [
        f"Cross-condition comparison -- {args.scenario}, {MODE}",
        f"  {len(rows)} conditions; each anchors a different gold subset, so all are re-scored",
        f"  on the INTERSECTION: {len(common)} of {rows[0]['gold_total']} gold threats.",
        "  Recall-only by design (a restricted gold makes precision meaningless).",
        "",
        f"  {'condition':42} {'el':>3} {'fl':>4} {'gen':>5} {'anchor':>7} {'R(own)':>7} {'R(common)':>10}",
    ]
    for r in sorted(scorable, key=lambda x: (x["input"], x["model"])):
        own = len(r["matched"]) / len(r["anchorable"])
        comm = (f"{len(r['matched'] & common) / len(common):.2f}" if common else "n/a")
        lines.append(f"  {r['condition']:42} {r['n_elements']:>3} {r['n_flows']:>4} "
                     f"{r['n_generated']:>5} {len(r['anchorable']):>7} {own:>7.2f} {comm:>10}")
    for r in sorted(unscorable, key=lambda x: (x["input"], x["model"])):
        lines.append(f"  {r['condition']:42} {r['n_elements']:>3} {r['n_flows']:>4} "
                     f"{r['n_generated']:>5} {0:>7} {'--':>7} {'--':>10}  UNSCORABLE")
    lines += ["",
              "  R(own)    = recall against the gold THAT condition can anchor -- not comparable",
              "              across conditions, because the denominators differ.",
              "  R(common) = recall on the shared intersection -- the comparable number.",
              ""]

    if unscorable:
        lines += [f"  UNSCORABLE ({len(unscorable)}): the re-anchoring mapped no gold threat at "
                  f"all, so eval reports 0.00 by construction. That is a property of the",
                  "  alignment, NOT a measurement of the model, and it is held out of the "
                  "intersection so it cannot empty everyone else's denominator.", ""]

    dropped = sorted(set.union(*(r["anchorable"] for r in scorable)) - common)
    if dropped:
        lines.append(f"  {len(dropped)} gold threats anchorable by SOME condition but not all, "
                     f"excluded from the common subset: {dropped}")
    report = "\n".join(lines)
    print(report)
    if args.out:
        Path(args.out).write_text(report + "\n")


if __name__ == "__main__":
    main()
