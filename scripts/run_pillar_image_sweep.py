#!/usr/bin/env python3
"""PILLAR's own DFD exports, through our image adapter, across several models.

    knowledge_base/PILLAR/dfd_authentication.png ──> vision_naive ──> dfd.json ──> grounded threats
    knowledge_base/PILLAR/dfd_Enrollment.png     ──┘

Why these two images are worth the calls: every image result the project has is on
`kidstube/dfd.png`, a matplotlib render OF the very dfd.json it is scored against -- uniform
strokes, machine-consistent notation, a synthetic best case that WEEK12_REPORT.md flags as a
ceiling measurement rather than field validation. These are a different tool's export of a
different system: dark theme, trust-boundary rectangles the notation has no element type for,
`DF_0`-style ids, a duplicated element name, and a typo in a data store. That is the closest
thing to a field fixture the repo has ever had.

WHAT THIS SCRIPT DOES NOT DO, AND WHY. It does not score precision/recall/F1, because no gold
standard exists for either system -- nobody has enumerated the privacy threats of PILLAR's face
authentication example, and inventing one here would be grading the pipeline against an answer
key written by the thing being graded. `eval/run_eval.py` is therefore never called. What IS
measurable without gold is everything the project's actual thesis rests on:

    box citations   is the cited region inside the image, and is anything drawn there
    node citations  does the cited tree node exist, is the type applicable at that interaction,
                    does the originator resolve -- all re-derived against the KB, no gold needed
    structure       how many elements and flows each model reads off the same picture
    volume          how many threats each model emits from it

Run: PYTHONPATH=. python3 scripts/run_pillar_image_sweep.py --models gpt-5.4 gpt-4o-mini grok-4.3
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

MODE = "grounded"
ARM = "vision_naive"
INPUT = runs.INPUT_IMAGE
# See one_condition(). Measured on grok-4.3 over 6 identical calls: 1 failure, and the failure
# took 49s against 15-31s for the successes -- a gateway timeout dressed as a 500, and bursty
# (two runs of 3 consecutive failures, then 5 successes in 6). 5 attempts, not 3.
DERIVE_ATTEMPTS = 5

# scenario name -> the exported diagram. The scenario names a SYSTEM, so the two PILLAR diagrams
# are two scenarios rather than two runs of one: enrollment and authentication are different
# subsystems with different flows, and merging them would average unrelated things.
SCENARIOS = {
    "pillar_authentication": config.KB_DIR / "PILLAR" / "dfd_authentication.png",
    "pillar_enrollment": config.KB_DIR / "PILLAR" / "dfd_Enrollment.png",
}


def _log(msg: str):
    print(msg, flush=True)


def citation_rates(threats: list, dfd: dict) -> dict:
    """The gold-free half of eval/run_eval.py, which needs a gold standard and so cannot run here.

    Identical checks, same verifier, no scoring: whether a citation resolves is a property of the
    threat and the knowledge base, never of whether anyone wrote down the right answer.
    """
    from generation.verify import verify_threat
    if not threats:
        return {"n": 0, "node_valid": None, "type_applicable": None,
                "location_valid": None, "all_valid": None, "failures": []}
    vs = [verify_threat(t, dfd) for t in threats]
    n = len(vs)
    failures = [f"{t.threat_type}/{t.tree_node} @ {t.flow_id}: {v.reasons[0]}"
                for t, v in zip(threats, vs) if not v.all_valid]
    return {
        "n": n,
        "node_valid": sum(v.node_valid for v in vs) / n,
        "type_applicable": sum(v.type_applicable for v in vs) / n,
        "location_valid": sum(v.location_valid for v in vs) / n,
        "all_valid": sum(v.all_valid for v in vs) / n,
        "failures": failures,
    }


def one_condition(scenario: str, image: Path, model: str, run: int, provider: str,
                  dry: bool) -> dict:
    from adapters.vision import synthesize_vision_naive
    from adapters.verify_vision import (verify_vision_dfd, format_verification_report,
                                        ink_coverage, calibrate_scale, _load_grey)
    from generation.generate import generate_for_scenario, save_generated

    cond = runs.condition(INPUT, ARM, model)
    run_dir = runs.derived_dir(scenario, cond, run)
    gen_dir = runs.generated_dir(scenario, cond, run)
    _log(f"\n=== {scenario} / {cond} run{run} ===")
    if dry:
        _log(f"  would write {run_dir} and {gen_dir}")
        return {"scenario": scenario, "condition": cond, "status": "dry-run"}

    run_dir.mkdir(parents=True, exist_ok=True)
    gen_dir.mkdir(parents=True, exist_ok=True)

    # 1. image -> DFD. Retried, because the Azure gateway returns a bare 500 ("Failed to
    #    reconstruct non-streaming response") intermittently on image calls -- grok-4.3 hit it on
    #    4 consecutive attempts and then succeeded on the same prompt and budget. That is
    #    infrastructure noise, not a model result, and losing a condition to it would silently
    #    turn "the endpoint flaked" into "this model cannot read diagrams". The attempt count is
    #    recorded on the artifact so a retried run is never mistaken for a clean first pass.
    _log(f"  [1/4] derive ({ARM}, {model})")
    dfd, attempts = None, 0
    for attempt in range(1, DERIVE_ATTEMPTS + 1):
        attempts = attempt
        try:
            dfd = synthesize_vision_naive(image, provider=provider, scenario_name=scenario,
                                          model=model)
            break
        except Exception as e:
            if attempt == DERIVE_ATTEMPTS:
                raise
            _log(f"        attempt {attempt} failed ({type(e).__name__}), retrying: "
                 f"{str(e)[:110]}")
    dfd["_meta"]["condition"] = cond
    dfd["_meta"]["run"] = run
    dfd["_meta"]["derive_attempts"] = attempts
    dfd_path = run_dir / "dfd.json"
    dfd_path.write_text(json.dumps(dfd, indent=2) + "\n")
    n_el, n_fl = len(dfd["elements"]), len(dfd["flows"])
    _log(f"        {n_el} elements, {n_fl} flows -> {dfd_path}")

    # 2. verify the pixel citations -- no LLM, and scored AS EMITTED (scale 1.0). The calibrated
    #    rate is reported alongside it, never instead of it.
    _log("  [2/4] verify boxes (no LLM)")
    grey = _load_grey(image)
    vs, used, _ = verify_vision_dfd(dfd, image, scale=1.0)
    raw_cov = ink_coverage(dfd, grey, 1.0)
    best_scale, cal_cov = calibrate_scale(dfd, grey)
    (run_dir / "verification.txt").write_text(
        format_verification_report(vs, image, used, dfd, grey) + "\n")
    _log(f"        in-bounds/ink per box: {raw_cov:.2f} as emitted, "
         f"{cal_cov:.2f} at scale {best_scale}")

    # 3. threats, grounded
    #    Retried for the same reason as the derive step, and it matters more here: generation is
    #    one call per flow, so a single gateway 500 anywhere in the loop discards every flow
    #    already paid for.
    _log(f"  [3/4] generate ({MODE})")
    threats = None
    for attempt in range(1, DERIVE_ATTEMPTS + 1):
        try:
            threats = generate_for_scenario(scenario, mode=MODE, provider=provider,
                                            dfd_path=dfd_path, progress=False, model=model)
            break
        except Exception as e:
            if attempt == DERIVE_ATTEMPTS:
                raise
            _log(f"        attempt {attempt} failed ({type(e).__name__}), retrying: "
                 f"{str(e)[:110]}")
    gen_path = save_generated(scenario, MODE, threats, out=gen_dir / f"{MODE}.json")
    _log(f"        {len(threats)} threats -> {gen_path}")

    # 4. citation validity. Deliberately NOT written as `*_eval.txt`: scripts/summarize_runs.py
    #    parses those as scored evals, and a run with no gold must not enter the index as a
    #    confident 0.00 precision -- the same refusal the flow-anchor bug forced in Week 12.
    _log("  [4/4] verify citations (no LLM, no gold needed)")
    rates = citation_rates(threats, dfd)
    lines = [
        f"Citation validity -- {scenario} / {cond} run{run}",
        f"  {rates['n']} generated threats, grounded, over {n_fl} flows",
        "  NO GOLD STANDARD EXISTS for this system, so precision/recall/F1 are not computed.",
        "  These checks are gold-free: they re-derive each citation against the knowledge base.",
        "",
    ]
    if rates["n"] == 0:
        # A condition that produced nothing has no citation rate -- not a rate of 0.00, and not a
        # rate of 1.00 either (vacuously "no invalid citations" is the more tempting mistake here).
        # Same refusal as summarize_runs.py's UNSCORABLE flag: unmeasured is not a measurement.
        lines.append("  NOT MEASURABLE -- the adapter emitted no flows, so no threat was "
                     "generated and there is no citation to check.")
    else:
        lines += [
            f"  node_valid_rate        {rates['node_valid']:.2f}",
            f"  type_applicable_rate   {rates['type_applicable']:.2f}",
            f"  location_valid_rate    {rates['location_valid']:.2f}",
            f"  all_valid_rate         {rates['all_valid']:.2f}",
        ]
    if rates["failures"]:
        lines += ["", f"  {len(rates['failures'])} failing citation(s):"]
        lines += [f"    {f}" for f in rates["failures"][:20]]
    (gen_dir / f"{MODE}_citations.txt").write_text("\n".join(lines) + "\n")
    _log("        all_valid " + ("n/a (no threats)" if rates["n"] == 0
                                 else f"{rates['all_valid']:.2f}"))

    return {
        "scenario": scenario, "condition": cond, "run": run, "model": model,
        "status": "ok", "n_elements": n_el, "n_flows": n_fl,
        "element_names": [e.get("name") for e in dfd["elements"]],
        "flow_ids": [f.get("id") for f in dfd["flows"]],
        "n_threats": len(threats),
        "box_coverage_as_emitted": round(raw_cov, 3),
        "box_coverage_calibrated": round(cal_cov, 3),
        "box_scale": best_scale,
        "citations": {k: v for k, v in rates.items() if k != "failures"},
        "n_citation_failures": len(rates["failures"]),
    }


def scan_results() -> list[dict]:
    """Rebuild every condition's row from what is on disk, with no LLM call.

    The report is assembled from artifacts rather than from this invocation's return values, so
    re-running one model does not drop the others out of the table -- and so the published table
    can never disagree with the committed artifacts, which is the failure mode that matters.
    """
    from adapters.verify_vision import ink_coverage, calibrate_scale, _load_grey
    from generation.generate import load_generated

    out = []
    for scenario, image in sorted(SCENARIOS.items()):
        grey = None
        for scen, cond, run, run_dir in runs.iter_runs(scenario):
            dfd_path = run_dir / "dfd.json"
            if not dfd_path.exists():
                continue
            dfd = json.loads(dfd_path.read_text())
            grey = _load_grey(image) if grey is None else grey
            best_scale, cal_cov = calibrate_scale(dfd, grey)
            gen_path = runs.threats_path(scen, cond, run, MODE)
            threats = load_generated(gen_path) if gen_path.exists() else []
            rates = citation_rates(threats, dfd)
            out.append({
                "scenario": scen, "condition": cond, "run": run, "status": "ok",
                "model": dfd["_meta"].get("model", "?"),
                "derive_attempts": dfd["_meta"].get("derive_attempts"),
                "n_elements": len(dfd["elements"]), "n_flows": len(dfd["flows"]),
                "element_names": [e.get("name") for e in dfd["elements"]],
                "flow_ids": [f.get("id") for f in dfd["flows"]],
                "n_threats": len(threats),
                "box_coverage_as_emitted": round(ink_coverage(dfd, grey, 1.0), 3),
                "box_coverage_calibrated": round(cal_cov, 3),
                "box_scale": best_scale,
                "citations": {k: v for k, v in rates.items() if k != "failures"},
                "n_citation_failures": len(rates["failures"]),
            })
    return out


def render_comparison(results: list[dict]) -> str:
    ok = [r for r in results if r.get("status") == "ok"]
    lines = [
        "PILLAR DFD exports -- vision_naive + grounded, three models",
        "  images : knowledge_base/PILLAR/dfd_authentication.png, dfd_Enrollment.png",
        "  n=1 per condition -- POINT ESTIMATES. Measured resampling swings of ~0.05 recall on",
        "  kidstube mean any small gap here is noise (RESULTS_2026-07-28.md §7).",
        "  NO GOLD STANDARD exists for either system: no precision, recall or F1 is reported.",
        "",
        f"  {'scenario':22} {'model':14} {'el':>3} {'fl':>3} {'threats':>8} "
        f"{'box@emit':>9} {'box@cal':>8} {'scale':>6} {'cite':>6}",
    ]
    for r in ok:
        cite = r["citations"]["all_valid"]
        lines.append(
            f"  {r['scenario']:22} {r['model']:14} {r['n_elements']:3d} {r['n_flows']:3d} "
            f"{r['n_threats']:8d} {r['box_coverage_as_emitted']:9.2f} "
            f"{r['box_coverage_calibrated']:8.2f} {r['box_scale']:6.2f} "
            + (f"{cite:6.2f}" if cite is not None else f"{'n/a':>6}"))

    for scenario in sorted({r["scenario"] for r in ok}):
        rows = [r for r in ok if r["scenario"] == scenario]
        lines += ["", f"  {scenario} -- what each model read off the same picture:"]
        for r in rows:
            lines.append(f"    {r['model']:14} flows {r['flow_ids']}")
        for r in rows:
            lines.append(f"    {r['model']:14} elements {r['element_names']}")

    failed = [r for r in results if r.get("status") not in ("ok", "dry-run")]
    if failed:
        lines += ["", "  FAILED conditions:"]
        lines += [f"    {r['scenario']} / {r.get('condition')}: {r.get('error')}" for r in failed]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="+", default=["gpt-5.4", "gpt-4o-mini", "grok-4.3"])
    ap.add_argument("--scenarios", nargs="+", default=sorted(SCENARIOS),
                    choices=sorted(SCENARIOS))
    ap.add_argument("--runs", type=int, default=1, help="Runs per condition. n=1 is a point "
                                                        "estimate, not a comparison.")
    ap.add_argument("--provider", default=config.LLM_PROVIDER)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report-only", action="store_true",
                    help="Rebuild the comparison from committed artifacts. No LLM calls.")
    args = ap.parse_args()

    for scenario in args.scenarios:
        if not SCENARIOS[scenario].exists():
            raise SystemExit(f"image not found: {SCENARIOS[scenario]}")

    errors = []
    if not args.report_only:
        for scenario in args.scenarios:
            for model in args.models:
                for run in range(1, args.runs + 1):
                    try:
                        one_condition(scenario, SCENARIOS[scenario], model, run,
                                      args.provider, args.dry_run)
                    except Exception as e:  # one dead condition must not lose the other five
                        traceback.print_exc()
                        errors.append({"scenario": scenario,
                                       "condition": runs.condition(INPUT, ARM, model),
                                       "run": run, "model": model, "status": "error",
                                       "error": f"{type(e).__name__}: {e}"})
    if args.dry_run:
        return

    results = scan_results() + errors
    report = render_comparison(results)
    print("\n" + report)
    out = runs.GENERATED_ROOT / "PILLAR_IMAGE_SWEEP.txt"
    out.write_text(report + "\n")
    (config.ROOT / "storage" / "pillar_sweep_last.json").write_text(
        json.dumps(results, indent=2) + "\n")
    print(f"\n-> {out}")


if __name__ == "__main__":
    main()
