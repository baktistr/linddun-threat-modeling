#!/usr/bin/env python3
"""Run the adapter's LLM arms N times and report scores with variance.

Why N>=3 and not 1: element precision on a ~13-element graph moves a lot per element, so a
single run is roughly one coin flip wide -- and the gap we care about (llm vs. the facts_only
baseline) is plausibly narrower than that spread. A single-run number would let us claim a
difference that resampling would erase. If the llm arm cannot beat facts_only outside the noise
band, that IS the finding, and it gets reported rather than tuned away.

Runs are written to storage/derived/<scenario>_<mode>_run<n>.json so every number below is
auditable back to the DFD that produced it.

Usage:
  python scripts/run_adapter_arms.py --mode llm --runs 3 --source-root ~/src/KidsTube-PE
"""
from __future__ import annotations
import argparse
import json
import statistics
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from adapters.align import align_elements, align_flows, derived_element_keys, load_hand_keys
from adapters.evaluate import score
from adapters.schema import CodeFact, validate_dfd
from adapters.verify_dfd import _rate, verify_dfd


def _load_facts(scenario: str):
    raw = json.loads((config.ROOT / "adapters" / "data" /
                       f"{scenario}_code_facts.json").read_text())
    return [CodeFact.from_dict(f) for f in raw["facts"]], raw["facts"]


def _summarise(values: list[float]) -> str:
    if not values:
        return "n/a"
    if len(values) == 1:
        return f"{values[0]:.2f}"
    return f"{statistics.mean(values):.2f} +/- {statistics.stdev(values):.2f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", choices=["llm", "llm_naive", "facts_only"], default="llm")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--scenario", default="kidstube")
    ap.add_argument("--source-root", default=None,
                    help="Re-parse the source so facts_present is actually checked rather than "
                         "reported not_checked.")
    ap.add_argument("--provider", default=None)
    args = ap.parse_args()

    facts, facts_raw = _load_facts(args.scenario)
    hand = json.loads((config.KB_DIR / "scenarios" / args.scenario / "dfd.json").read_text())
    hand_keys = load_hand_keys(args.scenario)
    source_root = Path(args.source_root).expanduser().resolve() if args.source_root else None
    out_dir = config.ROOT / "storage" / "derived"
    out_dir.mkdir(parents=True, exist_ok=True)

    from adapters.synthesize import synthesize_facts_only, synthesize_llm

    rows = []
    for i in range(1, args.runs + 1):
        print(f"\n########## {args.mode} run {i}/{args.runs} ##########", flush=True)
        try:
            if args.mode == "facts_only":
                dfd = synthesize_facts_only(facts)
            else:
                dfd = synthesize_llm(facts, provider=args.provider)
        except Exception as e:
            print(f"  FAILED: {type(e).__name__}: {e}", flush=True)
            traceback.print_exc()
            continue

        path = out_dir / f"{args.scenario}_{args.mode}_run{i}.json"
        path.write_text(json.dumps(dfd, indent=2) + "\n")

        errors = validate_dfd(dfd)
        ea = align_elements(derived_element_keys(dfd, facts_raw), hand_keys)
        fa = align_flows(dfd, hand, ea)
        s = score(dfd, hand, hand_keys, ea, fa)
        ev, fv = verify_dfd(dfd, facts, source_root=source_root)

        rows.append({
            "run": i, "n_elements": len(dfd["elements"]), "n_flows": len(dfd["flows"]),
            "schema_errors": len(errors),
            "el_matched": s.elements.matched, "el_missed": s.elements.derivable_but_missed,
            "el_ceiling": s.elements.structurally_underivable,
            "el_precision": s.element_precision_raw,
            "el_recall_derivable": s.elements.derivable_recall,
            "fl_matched": s.flows.matched, "fl_missed": s.flows.derivable_but_missed,
            "fl_precision": s.flow_precision_raw,
            "fl_recall_derivable": s.flows.derivable_recall,
            "cit_resolvable": _rate(ev, "citations_resolvable"),
            "cit_type_ok": _rate(ev, "evidence_type_consistent"),
            "cit_present": _rate(ev, "facts_present"),
            "cit_all_valid": _rate(ev, "all_valid"),
            "flow_evidence_connects": _rate(fv, "evidence_connects_endpoints"),
            "flow_all_valid": _rate(fv, "all_valid"),
            "direction_matches": _rate(fv, "direction_matches_evidence"),
            "names": [e["name"] for e in dfd["elements"]],
            "path": str(path.relative_to(config.ROOT)),
        })
        r = rows[-1]
        print(f"  schema_errors={r['schema_errors']}  elements={r['n_elements']} flows={r['n_flows']}")
        print(f"  el: matched={r['el_matched']} missed={r['el_missed']} ceiling={r['el_ceiling']} "
              f"P={r['el_precision']:.2f} Rd={r['el_recall_derivable']:.2f}")
        print(f"  fl: matched={r['fl_matched']} missed={r['fl_missed']} "
              f"P={r['fl_precision']:.2f} Rd={r['fl_recall_derivable']:.2f}")
        print(f"  citations: all_valid={r['cit_all_valid']:.2f} connects={r['flow_evidence_connects']:.2f}")
        print(f"  names: {', '.join(r['names'])}", flush=True)

    summary_path = out_dir / f"{args.scenario}_{args.mode}_runs.json"
    summary_path.write_text(json.dumps({
        "_meta": {"mode": args.mode, "runs": len(rows), "scenario": args.scenario,
                  "source_checked": source_root is not None,
                  "facts": f"adapters/data/{args.scenario}_code_facts.json"},
        "runs": rows,
    }, indent=2) + "\n")

    if not rows:
        print("\nNo runs completed.")
        return 1

    print(f"\n\n########## {args.mode}: {len(rows)} runs ##########")
    for k, label in [("el_precision", "element precision"),
                     ("el_recall_derivable", "element recall (derivable)"),
                     ("fl_precision", "flow precision"),
                     ("fl_recall_derivable", "flow recall (derivable)"),
                     ("cit_all_valid", "citation all_valid"),
                     ("flow_evidence_connects", "flow evidence_connects"),
                     ("flow_all_valid", "flow all_valid"),
                     ("direction_matches", "direction (NOT scored)")]:
        vals = [r[k] for r in rows if r[k] == r[k]]
        print(f"  {label:30} {_summarise(vals)}")
    ceilings = {r["el_ceiling"] for r in rows}
    print(f"  ceiling held at 2 every run     {ceilings == {2}}   (got {sorted(ceilings)})")
    print(f"\nWritten: {summary_path.relative_to(config.ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
