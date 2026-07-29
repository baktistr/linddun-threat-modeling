#!/usr/bin/env python3
"""Regenerate every committed threat set against the corrected LINDDUN trees.

WHY THIS EXISTS. Until 2026-07-28 the grounded prompt was built from a threat tree containing
three nodes this project INVENTED (D.1.1, U.1.3, Nc.1.3) and missing seventeen real ones. Every
generated set therefore contains citations to nodes that do not exist -- 20 of 118 in
kidstube_grounded alone -- and rescoring those old sets against the official tree drops citation
validity from 1.00 to 0.83 through no fault of the model. It cited what it was offered.

So the old numbers are not a measurement of the model, and neither are the rescored ones. The only
honest fix is to regenerate with a prompt built from the corrected tree. That is what this does.

Scope, in priority order:
  A  standing LINDDUN sets   3 scenarios x 3 grounding modes   (RESULTS_2026-07-14/21/28 SS1)
  B  derived-DFD sets        kidstube_derived x3, kidstube_image_derived x1
  C  Week 12 model sweep     9 conditions, grounded (DFDs are reused; only generation re-runs)

Every existing file is overwritten in place, so paths cited by committed reports stay valid.

Run: PYTHONPATH=. python3 scripts/regenerate_all.py [--only A B C] [--dry-run]
"""
from __future__ import annotations
import argparse
import json
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import runs

STANDING = [("kidstube", ("grounded", "rag", "ungrounded")),
            ("smart_home", ("grounded", "rag", "ungrounded")),
            ("family_location", ("grounded", "rag", "ungrounded"))]
DERIVED = [("kidstube_derived", ("grounded", "rag", "ungrounded")),
           ("kidstube_image_derived", ("grounded",))]

# runs.slug() is lossy on purpose (dots break globs), so the inverse has to be explicit. Only
# needed for dfd_hand, whose DFD records no model.
UNSLUG = {"gpt-5-4": "gpt-5.4", "gpt-4o-mini": "gpt-4o-mini", "grok-4-3": "grok-4.3"}


def _log(m):
    print(m, flush=True)


def regen(scenario, mode, dfd_path=None, out=None, gold_path=None, model=None):
    from generation.generate import generate_for_scenario, save_generated
    from eval.run_eval import run_eval
    th = generate_for_scenario(scenario, mode=mode, dfd_path=dfd_path, progress=False, model=model)
    p = save_generated(scenario, mode, th, out=out)
    rep = run_eval(scenario, str(p), dfd_path=dfd_path, gold_path=gold_path)
    ev = Path(str(p).replace(".json", "_eval.txt"))
    ev.write_text(rep + "\n")
    allrow = next(l for l in rep.splitlines() if l.startswith("ALL")).split()
    cit = next((l.split()[1] for l in rep.splitlines() if "all_valid_rate" in l), "?")
    _log(f"      {len(th):>4} threats  P/R/F1 {allrow[4]} {allrow[5]} {allrow[6]}   citation {cit}")
    return {"n": len(th), "p": allrow[4], "r": allrow[5], "f1": allrow[6], "citation": cit}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", nargs="+", default=["A", "B", "C"], choices=["A", "B", "C"])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    results = {}

    if "A" in args.only:
        _log("\n=== A. standing LINDDUN sets ===")
        for scen, modes in STANDING:
            for m in modes:
                _log(f"  {scen} / {m}")
                if args.dry_run:
                    continue
                try:
                    results[f"{scen}_{m}"] = regen(scen, m)
                except Exception as e:
                    _log(f"      FAILED {type(e).__name__}: {e}"); traceback.print_exc()

    if "B" in args.only:
        _log("\n=== B. derived-DFD sets ===")
        for scen, modes in DERIVED:
            for m in modes:
                _log(f"  {scen} / {m}")
                if args.dry_run:
                    continue
                try:
                    results[f"{scen}_{m}"] = regen(scen, m)
                except Exception as e:
                    _log(f"      FAILED {type(e).__name__}: {e}"); traceback.print_exc()

    if "C" in args.only:
        _log("\n=== C. Week 12 model sweep (grounded) ===")
        hand = config.KB_DIR / "scenarios" / "kidstube" / "gold_standard_threats.json"
        for scen, cond, run, rd in runs.iter_runs("kidstube"):
            # The condition key holds a PATH-SANITISED model ("gpt-5-4"); the Azure deployment is
            # "gpt-5.4". Sending the slug would 404 all nine conditions, so take the real name from
            # the DFD's own _meta where the adapter recorded it. dfd_hand records model="none" --
            # correctly, since no model produced that DFD -- so its threat model comes from the
            # condition key, unslugged.
            meta = json.loads((rd / "dfd.json").read_text()).get("_meta", {})
            model = meta.get("model")
            if not model or model == "none":
                model = UNSLUG.get(runs.parse_condition(cond)["model"])
            if not model:
                _log(f"  {cond}: cannot resolve a real model name -- SKIPPED")
                continue
            _log(f"  {cond} run{run}  (model {model})")
            if args.dry_run:
                continue
            gold = rd / "gold.json"
            try:
                results[cond] = regen("kidstube", "grounded", dfd_path=rd / "dfd.json",
                                      out=runs.generated_dir(scen, cond, run) / "grounded.json",
                                      gold_path=gold if gold.exists() else hand, model=model)
            except Exception as e:
                _log(f"      FAILED {type(e).__name__}: {e}"); traceback.print_exc()

    if not args.dry_run:
        (config.ROOT / "storage" / "regen_last.json").write_text(
            json.dumps(results, indent=2) + "\n")
    _log(f"\ndone: {len(results)} sets regenerated")


if __name__ == "__main__":
    main()
