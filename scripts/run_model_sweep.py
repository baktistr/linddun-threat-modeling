#!/usr/bin/env python3
"""Run the full pipeline across several models and both DFD inputs, into the runs.py layout.

For each (model x input): adapt -> DFD, resolve that DFD's gold, generate threats, score.

    image  + vision_naive   reads knowledge_base/scenarios/<scenario>/dfd.png
    source + llm            reads the committed code facts (closed fact-id vocabulary)

Gold resolution is the part that has to be got right, and it differs by arm:

  - The IMAGE arm cites pixel boxes, so the code-facts alignment cannot re-anchor it. If the run
    reproduced the hand DFD's flow ids exactly, the hand gold applies verbatim and the denominator
    stays the full 41. If it did NOT, there is no sound way to score it on flow-anchored gold, and
    this script says so and skips scoring rather than emitting a confident 0.00.
  - The SOURCE arm cites fact_ids, so its gold is re-anchored per run through that run's own
    alignment map -- flow ids differ between runs of the same model, let alone between models.

n=1 per condition by default. That is a POINT ESTIMATE, not a comparison: the llm arm's flow
recall spans 0.33-0.87 across three runs of one model, so any cross-model gap inside that band is
sampling noise. Pass --runs 3 to make the numbers comparable.

Run: PYTHONPATH=. python3 scripts/run_model_sweep.py --models gpt-5.4 gpt-4o-mini grok-4.3
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import runs

SCENARIO = "kidstube"
MODE = "grounded"


def _log(msg: str):
    print(msg, flush=True)


def derive_image(scenario: str, model: str, out_dir: Path, provider: str) -> dict:
    from adapters.vision import synthesize_vision_naive
    image = config.KB_DIR / "scenarios" / scenario / "dfd.png"
    return synthesize_vision_naive(image, provider=provider, scenario_name=scenario,
                                   model=model)


def derive_source(scenario: str, model: str, out_dir: Path, provider: str) -> dict:
    from adapters.schema import CodeFact
    from adapters.synthesize import synthesize_llm
    raw = json.loads((config.ROOT / "adapters" / "data"
                      / f"{scenario}_code_facts.json").read_text())
    facts = [CodeFact.from_dict(f) for f in (raw["facts"] if isinstance(raw, dict) else raw)]
    return synthesize_llm(facts, provider=provider, scenario_name=scenario, model=model)


def load_facts(scenario: str) -> list:
    from adapters.schema import CodeFact
    raw = json.loads((config.ROOT / "adapters" / "data"
                      / f"{scenario}_code_facts.json").read_text())
    return [CodeFact.from_dict(f) for f in (raw["facts"] if isinstance(raw, dict) else raw)]


def resolve_gold(input_kind: str, dfd_path: Path, run_dir: Path) -> tuple[Path | None, str]:
    """(gold path, note). None means this run cannot be scored on flow-anchored gold."""
    sys.path.insert(0, str(config.ROOT / "scripts"))
    import build_kidstube_derived_gold as bg

    derived = json.loads(dfd_path.read_text())
    hand_dfd = json.loads((config.KB_DIR / "scenarios" / SCENARIO / "dfd.json").read_text())
    hand_gold = config.KB_DIR / "scenarios" / SCENARIO / "gold_standard_threats.json"

    if not bg.cites_code_facts(derived):
        if bg.flow_ids_identical(derived, hand_dfd):
            return hand_gold, "hand gold verbatim (flow ids reproduced exactly; denominator 41/41)"
        return None, ("flow ids NOT reproduced and no fact_ids to re-anchor through -- "
                      "cannot be scored on flow-anchored gold")

    gold = bg.build(identity=False, derived_dfd_path=dfd_path)
    out = run_dir / "gold.json"
    out.write_text(json.dumps(gold, indent=2) + "\n")
    n_un = len(gold["_meta"]["unanchored_threat_ids"])
    return out, f"re-anchored through this run's alignment map ({41 - n_un}/41 anchored)"


ARMS = {"image": "vision_naive", "source": "llm", "dfd": "hand"}
# The fusion inputs' arm is the ENRICHMENT arm (adapters/enrich.py), chosen per invocation:
# enrich_llm is the proposal (closed fact-id vocabulary), enrich_facts the deterministic bar.
FUSION_INPUTS = ("image-src", "dfd-src")


def arm_for(input_kind: str, enrich_arm: str) -> str:
    return enrich_arm if input_kind in FUSION_INPUTS else ARMS[input_kind]


def one_condition(model: str, input_kind: str, run: int, provider: str, dry: bool,
                  enrich_arm: str = "enrich_llm") -> dict:
    arm = arm_for(input_kind, enrich_arm)
    cond = runs.condition(input_kind, arm, model)
    run_dir = runs.derived_dir(SCENARIO, cond, run)
    gen_dir = runs.generated_dir(SCENARIO, cond, run)
    _log(f"\n=== {cond} run{run} ===")
    if dry:
        _log(f"  would write {run_dir} and {gen_dir}")
        return {"condition": cond, "status": "dry-run"}

    run_dir.mkdir(parents=True, exist_ok=True)
    gen_dir.mkdir(parents=True, exist_ok=True)

    # 1. adapter -- except for the control, which has none: it uses the hand DFD unchanged, so
    #    Stage A is held constant and any difference is Stage B (threat elicitation) alone.
    dfd_path = run_dir / "dfd.json"
    if input_kind in ("dfd", "dfd-src"):
        _log(f"  [1/4] no adapter -- hand-authored DFD"
             + (" (to be enriched)" if input_kind == "dfd-src" else
                f" ({model} varies Stage B only)"))
        dfd = json.loads((config.KB_DIR / "scenarios" / SCENARIO / "dfd.json").read_text())
        dfd["_meta"] = {**dfd.get("_meta", {}), "adapter_mode": "hand", "backend": "none",
                        "model": "none",
                        "note": "control condition: the hand DFD verbatim, no adapter. The model "
                                "named in the condition key generated the THREATS, not this DFD."}
    else:
        base_arm = "vision_naive" if input_kind == "image-src" else arm
        _log(f"  [1/4] adapt ({base_arm}, {model})")
        dfd = (derive_source if input_kind == "source" else derive_image)(
            SCENARIO, model, run_dir, provider)
    if input_kind in FUSION_INPUTS:
        from adapters.enrich import enrich_dfd, format_enrichment_report
        _log(f"  [1b ] enrich ({arm}, "
             f"{'no model' if arm == 'enrich_facts' else model})")
        facts = load_facts(SCENARIO)
        base = dfd
        dfd = enrich_dfd(base, facts, arm=arm, provider=provider, model=model, verbose=False)
        report = format_enrichment_report(base, dfd, facts)
        (run_dir / "enrichment.txt").write_text(report + "\n")
        _log("        " + "\n        ".join(report.splitlines()[:3]))
        if "VIOLATED" in report:
            raise RuntimeError(f"enrichment contract violated -- see {run_dir}/enrichment.txt")
    dfd["_meta"]["condition"] = cond
    dfd["_meta"]["run"] = run
    dfd["_meta"]["code"] = config.code_state()
    dfd_path.write_text(json.dumps(dfd, indent=2) + "\n")
    _log(f"        {len(dfd['elements'])} elements, {len(dfd['flows'])} flows -> {dfd_path}")

    # 2. gold
    _log("  [2/4] resolve gold")
    gold_path, note = resolve_gold(input_kind, dfd_path, run_dir)
    _log(f"        {note}")
    if gold_path is None:
        return {"condition": cond, "run": run, "status": "unscorable", "note": note,
                "n_elements": len(dfd["elements"]), "n_flows": len(dfd["flows"])}

    # 3. generate
    _log(f"  [3/4] generate ({MODE})")
    from generation.generate import generate_for_scenario, save_generated
    threats = generate_for_scenario(SCENARIO, mode=MODE, provider=provider,
                                    dfd_path=dfd_path, progress=False, model=model)
    gen_path = save_generated(SCENARIO, MODE, threats, out=gen_dir / f"{MODE}.json")
    _log(f"        {len(threats)} threats -> {gen_path}")

    # 4. eval
    _log("  [4/4] eval")
    from eval.run_eval import run_eval
    report = run_eval(SCENARIO, str(gen_path), dfd_path=dfd_path, gold_path=gold_path)
    (gen_dir / f"{MODE}_eval.txt").write_text(report + "\n")
    for line in report.splitlines():
        if line.startswith("ALL") or "all_valid_rate" in line:
            _log(f"        {line.strip()}")
    return {"condition": cond, "run": run, "status": "ok", "n_threats": len(threats),
            "n_elements": len(dfd["elements"]), "n_flows": len(dfd["flows"]), "gold_note": note}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--inputs", nargs="+", default=["image", "source"], choices=list(runs.INPUTS))
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--provider", default="azure")
    ap.add_argument("--enrich-arm", default="enrich_llm", choices=["enrich_llm", "enrich_facts"],
                    help="Which adapters/enrich.py arm the image-src/dfd-src inputs use.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.runs == 1:
        _log("NOTE: n=1 per condition. These are POINT ESTIMATES, not comparisons -- the llm "
             "arm's flow recall spans 0.33-0.87 across runs of one model.\n")

    results = []
    for model in args.models:
        for input_kind in args.inputs:
            for run in range(1, args.runs + 1):
                try:
                    results.append(one_condition(model, input_kind, run, args.provider,
                                                 args.dry_run, enrich_arm=args.enrich_arm))
                except Exception as e:
                    _log(f"  FAILED: {type(e).__name__}: {e}")
                    traceback.print_exc()
                    results.append({"condition": runs.condition(
                        input_kind, arm_for(input_kind, args.enrich_arm), model),
                        "run": run, "status": "failed", "error": f"{type(e).__name__}: {e}"})

    _log("\n" + "=" * 70)
    for r in results:
        _log(f"  {r['status']:11} {r['condition']}"
             + (f"  ({r.get('n_elements')} el, {r.get('n_flows')} fl, "
                f"{r.get('n_threats', '-')} threats)" if r["status"] == "ok" else ""))
    (config.ROOT / "storage" / "sweep_last.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
