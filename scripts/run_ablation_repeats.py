#!/usr/bin/env python3
"""Repeat the scenario x grounding-mode ablation n times and report dispersion, not point estimates.

Every scenario-level number this project has published was n=1. That was defensible while the
effects were large (grounded 1.00 vs 0.79-0.91 ungrounded), and indefensible for anything smaller
-- and a reviewer said so. Two things had to happen in order, and this script is the second:

  1. PIN THE SAMPLER. Nothing set `temperature` until 2026-08-08, so every run went out at the
     provider default of 1.0. Most of the measured spread was sampling the experiment was paying
     for by default. config.GENERATION_TEMPERATURE now pins it (see config.py).
  2. REPEAT ANYWAY. temperature=0 is accepted by this project's gpt-5.4 deployment but is NOT
     deterministic -- three identical calls agreed on 8 of 10 cited nodes, not 10. Pinning
     shrinks the noise; only repetition measures what is left.

n=3 by default, deliberately: n=1 has no dispersion, n=2 gives a range but cannot separate a
spread from an outlier, n=3 is the smallest n with a standard deviation -- and n=5 only buys
SEM 0.45σ against n=3's 0.58σ, which is not worth 67% more spend unless a specific comparison
lands inside the noise band.

A NOTE ON WHAT THE REPEATS ARE FOR. They are not the unit of inference. The five scenarios are:
the headline claims are paired comparisons ACROSS scenarios (each scenario one block), which is
already significant at n=1 per cell. Repeats exist to keep measurement noise from inflating each
block's estimate, and to report the dispersion a reader needs to judge any difference. Recall on
a 20-threat gold is quantised at 0.05 -- one threat IS five recall points -- so no amount of
repetition resolves a difference finer than that. More scenarios, not more runs, is the fix there.

Run: PYTHONPATH=. python3 scripts/run_ablation_repeats.py --runs 3
     PYTHONPATH=. python3 scripts/run_ablation_repeats.py --report-only   # offline, no LLM calls
"""
from __future__ import annotations
import argparse
import json
import re
import statistics
from collections import Counter
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config

SCENARIOS = ["kidstube", "smart_home", "family_location", "school_grades", "wearable_fitness"]
MODES = ["grounded", "rag", "ungrounded"]
OUT_DIR = config.ROOT / "storage" / "generated" / "repeats"
STATE = config.ROOT / "storage" / "ablation_repeats.json"
REPORT = config.ROOT / "storage" / "generated" / "ABLATION_REPEATS.txt"

_ALL_RE = re.compile(r"^ALL\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", re.M)
_CITE_RE = re.compile(r"all_valid_rate\s+([\d.]+)")


def _log(msg: str):
    print(msg, flush=True)


def parse_report(text: str) -> dict:
    m, c = _ALL_RE.search(text), _CITE_RE.search(text)
    if not m:
        raise ValueError("eval report has no ALL row")
    tp, fp, fn, p, r, f1 = m.groups()
    return {"tp": int(tp), "fp": int(fp), "fn": int(fn),
            "precision": float(p), "recall": float(r), "f1": float(f1),
            "citation": float(c.group(1)) if c else None}


def one_run(scenario: str, mode: str, run: int, provider: str, model: str | None = None) -> dict:
    from generation.generate import generate_for_scenario, save_generated
    from generation.llm_backend import get_llm_backend
    from eval.run_eval import run_eval

    import runs as runs_mod

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # The model is in the filename now. Without it three deployments write the same path and the
    # last one silently wins -- the exact failure runs.py was created to prevent one tier up.
    stem = OUT_DIR / f"{runs_mod.slug(model or config.AZURE_AI_MODEL)}_{scenario}_{mode}_run{run}"
    gen_stats: dict = {}
    threats = generate_for_scenario(scenario, mode=mode, provider=provider, progress=False,
                                    model=model, stats=gen_stats)
    gen_path = save_generated(scenario, mode, threats, out=stem.with_suffix(".json"))
    report = run_eval(scenario, str(gen_path))
    stem.with_name(stem.name + "_eval.txt").write_text(report + "\n")

    llm = get_llm_backend(provider, model)
    metrics = parse_report(report)
    # The LINDDUN Pro position each threat was placed at. New with the `position` field, and the
    # first time this project can say where models actually locate threats rather than where the
    # schema forced them: the two-position schema silently coerced every flow threat onto an
    # endpoint, so an old run's location citations cannot be compared with these.
    positions = Counter(t.position or "unset" for t in threats)
    # Whether the DEPLOYMENT honoured the pinned temperature, not merely whether we asked. A run
    # that fell back is not greedy decoding and must not be reported as such.
    metrics.update(scenario=scenario, mode=mode, run=run, n_generated=len(threats),
                   model=llm.model,
                   n_position_S=positions.get("S", 0), n_position_fl=positions.get("fl", 0),
                   n_position_D=positions.get("D", 0), n_position_unset=positions.get("unset", 0),
                   n_malformed_dropped=gen_stats.get("malformed_dropped", 0),
                   concurrency=config.GENERATION_CONCURRENCY,
                   temperature=config.GENERATION_TEMPERATURE,
                   temperature_applied=llm.temperature_applied,
                   code=config.code_state())
    return metrics


def aggregate(rows: list[dict]) -> list[dict]:
    out = []
    for scenario in SCENARIOS:
        for mode in MODES:
            got = [r for r in rows if r["scenario"] == scenario and r["mode"] == mode
                   and r.get("status", "ok") == "ok"]
            if not got:
                continue
            agg = {"scenario": scenario, "mode": mode, "n_runs": len(got)}
            for metric in ("n_generated", "precision", "recall", "f1", "citation"):
                vals = [g[metric] for g in got if g.get(metric) is not None]
                if not vals:
                    continue
                agg[metric] = {
                    "mean": round(statistics.mean(vals), 4),
                    # Population SD is wrong here: these runs are a SAMPLE of the condition's
                    # behaviour, not its entirety. stdev needs n>=2; n=1 reports None rather than
                    # a fabricated 0.0, which would read as "perfectly reproducible".
                    "sd": round(statistics.stdev(vals), 4) if len(vals) > 1 else None,
                    "min": min(vals), "max": max(vals), "values": vals,
                }
            out.append(agg)
    return out


def format_report(aggs: list[dict], rows: list[dict]) -> str:
    applied = {r.get("temperature_applied") for r in rows if r.get("status", "ok") == "ok"}
    temps = {r.get("temperature") for r in rows if r.get("status", "ok") == "ok"}
    lines = [
        "Scenario x grounding-mode ablation, repeated -- mean (sd) over runs",
        f"  temperature {temps or '?'}; deployment honoured it: {applied or '?'}",
        f"  code {next((r.get('code') for r in rows if r.get('code')), '?')}",
        "",
        "  NOTE: temperature=0 is accepted but NOT deterministic on this deployment, so a zero sd",
        "  would be a finding, not an expectation. Recall is quantised at 1/|gold| (0.05 on the",
        "  20-threat scenarios): differences below that are unmeasurable however many runs are made.",
        "",
        f"  {'scenario':18} {'mode':11} {'runs':>4} {'n_gen':>12} {'P':>13} {'R':>13} {'F1':>13} {'citation':>13}",
    ]

    def cell(a, key, fmt="{:.2f}"):
        if key not in a:
            return f"{'-':>13}"
        m, sd = a[key]["mean"], a[key]["sd"]
        txt = fmt.format(m) + (f" ({fmt.format(sd)})" if sd is not None else " (--)")
        return f"{txt:>13}"

    for a in aggs:
        lines.append(
            f"  {a['scenario']:18} {a['mode']:11} {a['n_runs']:>4} "
            + cell(a, "n_generated", "{:.0f}") + cell(a, "precision") + cell(a, "recall")
            + cell(a, "f1") + cell(a, "citation"))

    # Paired-across-scenarios contrasts: the actual unit of inference (see module docstring).
    lines += ["", "  Paired across scenarios (each scenario one block), mean of per-scenario means:"]
    by = {(a["scenario"], a["mode"]): a for a in aggs}
    for left, right in (("grounded", "ungrounded"), ("grounded", "rag"), ("rag", "ungrounded")):
        for metric in ("citation", "recall"):
            diffs = [by[(s, left)][metric]["mean"] - by[(s, right)][metric]["mean"]
                     for s in SCENARIOS
                     if (s, left) in by and (s, right) in by
                     and metric in by[(s, left)] and metric in by[(s, right)]]
            if len(diffs) < 2:
                continue
            mean, sd = statistics.mean(diffs), statistics.stdev(diffs)
            wins = sum(d > 0 for d in diffs)
            lines.append(f"    {metric:9} {left:10} - {right:11} "
                         f"mean {mean:+.3f}  sd {sd:.3f}  n={len(diffs)}  "
                         f"favours {left} in {wins}/{len(diffs)}")
    failed = [r for r in rows if r.get("status") == "failed"]
    if failed:
        lines += ["", f"  FAILED RUNS: {len(failed)}"]
        lines += [f"    {r['scenario']} {r['mode']} run{r['run']}: {r['error']}" for r in failed]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scenarios", nargs="+", default=SCENARIOS)
    ap.add_argument("--modes", nargs="+", default=MODES)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--provider", default="azure")
    ap.add_argument("--model", default=None,
                    help="Deployment name; default = config.AZURE_AI_MODEL. Recorded on every "
                         "row and included in the artifact path.")
    ap.add_argument("--force", action="store_true",
                    help="Re-run cells already recorded in STATE.")
    ap.add_argument("--report-only", action="store_true",
                    help="Re-aggregate committed runs offline; makes no LLM calls.")
    args = ap.parse_args()

    if args.report_only:
        rows = json.loads(STATE.read_text())
    else:
        # Resumable, and keyed on the MODEL as well as the cell. Without the model in the key a
        # second deployment's run is skipped as already-done; without resumability at all a crash
        # 1500 calls into a three-model sweep discards every completed cell.
        model_id = args.model or config.AZURE_AI_MODEL
        rows = [] if args.force or not STATE.exists() else json.loads(STATE.read_text())
        done = {(r.get("model"), r["scenario"], r["mode"], r["run"]) for r in rows
                if r.get("status", "ok") == "ok"}
        todo = [(sc, mo, rn) for sc in args.scenarios for mo in args.modes
                for rn in range(1, args.runs + 1)
                if (model_id, sc, mo, rn) not in done]
        if done:
            _log(f"resuming: {len(done)} cell(s) recorded, {len(todo)} to run for {model_id}")
        total = len(todo)
        for i, (scenario, mode, run) in enumerate(todo, 1):
            tag = f"[{i}/{total}] {model_id} {scenario} {mode} run{run}"
            try:
                m = one_run(scenario, mode, run, args.provider, args.model)
                pos = (f" S/fl/D={m['n_position_S']}/{m['n_position_fl']}/{m['n_position_D']}"
                       if m.get("n_position_fl") is not None else "")
                _log(f"{tag}: n={m['n_generated']} P={m['precision']:.2f} "
                     f"R={m['recall']:.2f} F1={m['f1']:.2f} cite={m['citation']}{pos}")
                rows.append(m)
            except Exception as e:
                _log(f"{tag}: FAILED {type(e).__name__}: {e}")
                traceback.print_exc()
                rows.append({"model": model_id, "scenario": scenario, "mode": mode, "run": run,
                             "status": "failed", "error": f"{type(e).__name__}: {e}"})
            # Written every cell, not once at the end: a 1701-call sweep must not lose completed
            # work to a failure in a later cell.
            STATE.write_text(json.dumps(rows, indent=2) + "\n")

    report = format_report(aggregate(rows), rows)
    REPORT.write_text(report + "\n")
    print("\n" + report)
    print(f"\n(written to {REPORT})")


if __name__ == "__main__":
    main()
