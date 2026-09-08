#!/usr/bin/env python3
"""Does the grounding advantage hold as model capability drops? The open-weight ladder, n=3.

WHY THIS IS A SEPARATE SCRIPT. run_ablation_repeats.py varies the GROUNDING MECHANISM at one
frontier model and owns storage/ablation_repeats.json -- the 45 runs behind the report's Table 3
and Figure 2. run_rag_backend_sweep.py varies the RETRIEVER inside the rag arm. This sweep varies
MODEL CAPABILITY across the grounding mechanisms, which is a third experiment with a third unit
of comparison, and it must not be able to overwrite either of the others' artifacts. Hence its
own OUT_DIR, STATE and REPORT.

THE HYPOTHESIS, stated before the data so the result can disconfirm it. Grounded mode prints the
applicable node ids in the prompt, so citing one is a COPYING task; ungrounded mode asks for a
node id the model must recall from training, so citing one is a RECALL task. If that framing is
right, grounded citation validity should stay near 1.00 all the way down the ladder while
ungrounded validity falls with scale -- i.e. the grounded-minus-ungrounded margin WIDENS as models
get smaller. Recall and precision, which measure threat elicitation rather than citation, should
degrade with scale in every arm.

WHY IT MATTERS BEYOND ANOTHER TABLE ROW. Every model measured so far is a hosted frontier model,
which is an awkward recommendation for privacy threat modelling: the DFD being analysed is exactly
the artifact an organisation cannot casually hand to a third-party API. If a small local model
grounded is competitive on citation validity, the deployability claim stops being hypothetical.

WHAT IS PINNED. Same scenarios, same gold, same prompt builders, same temperature, same k, same
retrieval backend, same concurrency. Only the served model varies.

CONCURRENCY IS PART OF THE CONDITION, NOT A FREE SPEEDUP. Greedy decoding on a batching server is
not bitwise deterministic: batch composition changes the arithmetic, and two runs of one scenario
at concurrency 1 vs 16 gave 166 and 136 threats on identical settings. So concurrency is recorded
in every row and must be held constant across a comparison. It is not a knob to tune mid-sweep.

THE SERVED MODEL IS ASSERTED, NOT TRUSTED. The model is chosen by OPENAI_MODEL/--model, but what
actually answers is whatever the endpoint happens to be serving -- and a local server serves one
model at a time. Pointing this script at a server loaded with a different model would produce a
clean-looking row for an experiment that never ran, which is precisely the failure mode that made
every pre-Week-13 rag artifact ambiguous. Each cell verifies the endpoint's /v1/models against the
requested id and refuses to run on a mismatch.

Because the server holds one model, MODEL IS AN OUTER LOOP RUN OUTSIDE THIS SCRIPT: invoke once
per served model (see scripts/run_open_model_sweep.sh, which restarts the container between
models). STATE persists across invocations, so the grid resumes wherever it stopped.

Resumable: cells already recorded in STATE are skipped. --force re-runs everything.

Run: PYTHONPATH=. python3 scripts/run_open_model_sweep.py --model Qwen/Qwen3.5-2B --runs 3
     PYTHONPATH=. python3 scripts/run_open_model_sweep.py --report-only   # offline, no LLM calls
"""
from __future__ import annotations
import argparse
import json
import statistics
from collections import Counter
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import runs as runs_mod
from scripts.run_ablation_repeats import parse_report

SCENARIOS = ["kidstube", "smart_home", "family_location", "school_grades", "wearable_fitness"]
MODES = ["grounded", "rag", "ungrounded"]
OUT_DIR = config.ROOT / "storage" / "generated" / "open_models"
STATE = config.ROOT / "storage" / "open_model_sweep.json"
REPORT = config.ROOT / "storage" / "generated" / "OPEN_MODEL_SWEEP.txt"


def _log(msg: str):
    print(msg, flush=True)


def served_model(provider: str) -> tuple[str | None, str | None]:
    """(model id the endpoint is serving, server version) -- or (None, None) if it cannot say.

    Asked of the endpoint rather than inferred from config, because config records what was
    REQUESTED. For a self-hosted server those differ whenever the container was started with
    another model, and nothing else in the pipeline would notice.
    """
    try:
        from generation.llm_backend import get_llm_backend
        client = get_llm_backend(provider).client
        listed = client.models.list().data
        return (listed[0].id if listed else None, None)
    except Exception:
        return (None, None)


def one_run(scenario: str, mode: str, run: int, provider: str, model: str | None,
            concurrency: int, strict_served: bool = True) -> dict:
    from generation.generate import generate_for_scenario, save_generated
    from generation.llm_backend import get_llm_backend
    from eval.run_eval import run_eval

    llm = get_llm_backend(provider, model)
    actually_serving, _ = served_model(provider)
    if strict_served and actually_serving and actually_serving != llm.model:
        raise RuntimeError(
            f"asked for {llm.model!r} but the endpoint is serving {actually_serving!r}. "
            f"Restart the server on the requested model, or pass --no-strict-served if the "
            f"endpoint legitimately multiplexes models.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stem = OUT_DIR / f"{runs_mod.slug(llm.model)}_{scenario}_{mode}_run{run}"
    # Schema compliance is a property of the model, not an incident: the hosted deployments never
    # emit a threat missing a `required` field, and the smaller open models do it routinely. It
    # belongs in the row next to citation validity so the ladder can be read on that axis too.
    gen_stats: dict = {}
    threats = generate_for_scenario(scenario, mode=mode, provider=provider, progress=False,
                                    model=model, concurrency=concurrency, stats=gen_stats)
    gen_path = save_generated(scenario, mode, threats, out=stem.with_suffix(".json"))
    report = run_eval(scenario, str(gen_path))
    stem.with_name(stem.name + "_eval.txt").write_text(report + "\n")

    metrics = parse_report(report)
    # Where the model actually put each threat. Kept in the row as well as the artifact so the
    # ladder can be read on this axis without re-opening 180 threat sets, and so it matches the
    # shape run_ablation_repeats.py records for the hosted models.
    positions = Counter(t.position or "unset" for t in threats)
    metrics.update(scenario=scenario, mode=mode, run=run, model=llm.model,
                   n_generated=len(threats),
                   n_position_S=positions.get("S", 0), n_position_fl=positions.get("fl", 0),
                   n_position_D=positions.get("D", 0), n_position_unset=positions.get("unset", 0),
                   n_malformed_dropped=gen_stats.get("malformed_dropped", 0),
                   served_model=actually_serving,
                   provider=provider, base_url=config.OPENAI_BASE_URL,
                   concurrency=concurrency,
                   retrieval_backend=config.EMBEDDING_BACKEND if mode == "rag" else None,
                   top_k=config.TOP_K if mode == "rag" else None,
                   temperature=config.GENERATION_TEMPERATURE,
                   temperature_applied=llm.temperature_applied,
                   code=config.code_state())
    return metrics


def aggregate(rows: list[dict], models: list[str]) -> list[dict]:
    out = []
    for model in models:
        for scenario in SCENARIOS:
            for mode in MODES:
                got = [r for r in rows if r.get("model") == model
                       and r["scenario"] == scenario and r["mode"] == mode
                       and r.get("status", "ok") == "ok"]
                if not got:
                    continue
                agg = {"model": model, "scenario": scenario, "mode": mode, "n_runs": len(got)}
                for metric in ("n_generated", "precision", "recall", "f1", "citation"):
                    vals = [g[metric] for g in got if g.get(metric) is not None]
                    if not vals:
                        continue
                    agg[metric] = {
                        "mean": round(statistics.mean(vals), 4),
                        # Sample SD, and None (not 0.0) at n=1 -- a fabricated zero would read as
                        # "perfectly reproducible". Same convention as the other two sweeps.
                        "sd": round(statistics.stdev(vals), 4) if len(vals) > 1 else None,
                        "min": min(vals), "max": max(vals), "values": vals,
                    }
                out.append(agg)
    return out


def format_report(aggs: list[dict], rows: list[dict], models: list[str]) -> str:
    ok = [r for r in rows if r.get("status", "ok") == "ok"]
    conc = {r.get("concurrency") for r in ok}
    temps = {r.get("temperature") for r in ok}
    applied = {r.get("temperature_applied") for r in ok}
    lines = [
        "Open-weight model ladder x grounding mechanism -- mean (sd) over runs",
        f"  temperature {temps or '?'}; deployment honoured it: {applied or '?'}",
        f"  concurrency {conc or '?'} (part of the condition: greedy decoding on a batching "
        f"server is not bitwise deterministic)",
        f"  endpoint {next((r.get('base_url') for r in ok if r.get('base_url')), '?')}; "
        f"code {next((r.get('code') for r in ok if r.get('code')), '?')}",
        "",
        f"  {'model':22} {'scenario':18} {'mode':11} {'runs':>4} {'n_gen':>12} {'P':>13} "
        f"{'R':>13} {'F1':>13} {'citation':>13}",
    ]

    def cell(a, key, fmt="{:.2f}"):
        if key not in a:
            return f"{'-':>13}"
        m, sd = a[key]["mean"], a[key]["sd"]
        txt = fmt.format(m) + (f" ({fmt.format(sd)})" if sd is not None else " (--)")
        return f"{txt:>13}"

    for a in aggs:
        lines.append(
            f"  {a['model'][:22]:22} {a['scenario']:18} {a['mode']:11} {a['n_runs']:>4} "
            + cell(a, "n_generated", "{:.0f}") + cell(a, "precision") + cell(a, "recall")
            + cell(a, "f1") + cell(a, "citation"))

    # The contrast the sweep exists for: does the grounded margin widen as the model shrinks?
    # Paired across scenarios within each model, so every number below is a within-model block
    # mean -- never a comparison of one model's scenario against another's.
    lines += ["", "  Per model, paired across scenarios (each scenario one block):"]
    by = {(a["model"], a["scenario"], a["mode"]): a for a in aggs}
    lines.append(f"    {'model':22} {'contrast':22} {'citation':>10} {'recall':>10} "
                 f"{'f1':>10}  scenarios")
    for model in models:
        for lo in ("ungrounded", "rag"):
            cells = []
            for metric in ("citation", "recall", "f1"):
                diffs = [by[(model, s, "grounded")][metric]["mean"]
                         - by[(model, s, lo)][metric]["mean"]
                         for s in SCENARIOS
                         if (model, s, "grounded") in by and (model, s, lo) in by
                         and metric in by[(model, s, "grounded")] and metric in by[(model, s, lo)]]
                cells.append((metric, diffs))
            n = len(cells[0][1]) if cells else 0
            if n < 2:
                continue
            txt = "".join(f"{statistics.mean(d):>+10.3f}" for _m, d in cells)
            lines.append(f"    {model[:22]:22} {'grounded - ' + lo:22}{txt}  n={n}")

    failed = [r for r in rows if r.get("status") == "failed"]
    if failed:
        lines += ["", f"  FAILED RUNS: {len(failed)}"]
        lines += [f"    {r.get('model')} {r['scenario']} {r['mode']} run{r['run']}: {r['error']}"
                  for r in failed]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", default=None,
                    help="Model id to run, which must be the one the endpoint is serving. "
                         "Default = config.OPENAI_MODEL.")
    ap.add_argument("--scenarios", nargs="+", default=SCENARIOS)
    ap.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--provider", default="openai")
    ap.add_argument("--concurrency", type=int, default=None,
                    help="Flow calls in flight; default = config.GENERATION_CONCURRENCY. "
                         "Held constant across every cell of a comparison.")
    ap.add_argument("--no-strict-served", dest="strict_served", action="store_false",
                    help="Skip the served-model assertion (only for a multiplexing endpoint).")
    ap.add_argument("--force", action="store_true", help="re-run cells already present in STATE")
    ap.add_argument("--report-only", action="store_true",
                    help="Re-aggregate recorded runs offline; makes no LLM calls.")
    args = ap.parse_args()

    concurrency = (args.concurrency if args.concurrency is not None
                   else config.GENERATION_CONCURRENCY)

    if args.report_only:
        rows = json.loads(STATE.read_text()) if STATE.exists() else []
    else:
        rows = [] if args.force or not STATE.exists() else json.loads(STATE.read_text())
        model = args.model or config.OPENAI_MODEL
        done = {(r.get("model"), r["scenario"], r["mode"], r["run"]) for r in rows
                if r.get("status", "ok") == "ok"}
        # Scenario outer, mode inner: the three grounding arms of one scenario land close
        # together in time, so any server-side drift perturbs a block roughly equally instead of
        # biasing whichever arm ran last. Same reasoning as run_rag_backend_sweep.py.
        todo = [(s, m, run) for s in args.scenarios for m in args.modes
                for run in range(1, args.runs + 1) if (model, s, m, run) not in done]
        if done:
            _log(f"resuming: {len(done)} cell(s) recorded overall, {len(todo)} to run for {model}")
        for i, (scenario, mode, run) in enumerate(todo, 1):
            tag = f"[{i}/{len(todo)}] {model} {scenario} {mode} run{run}"
            try:
                m = one_run(scenario, mode, run, args.provider, model, concurrency,
                            strict_served=args.strict_served)
                bad = m.get("n_malformed_dropped") or 0
                _log(f"{tag}: n={m['n_generated']} P={m['precision']:.2f} "
                     f"R={m['recall']:.2f} F1={m['f1']:.2f} cite={m['citation']}"
                     f" S/fl/D={m['n_position_S']}/{m['n_position_fl']}/{m['n_position_D']}"
                     + (f" malformed={bad}" if bad else ""))
                rows.append(m)
            except Exception as e:
                _log(f"{tag}: FAILED {type(e).__name__}: {e}")
                traceback.print_exc()
                rows.append({"model": model, "scenario": scenario, "mode": mode, "run": run,
                             "status": "failed", "error": f"{type(e).__name__}: {e}"})
            # Written every cell, not once at the end: a sweep this long must not lose completed
            # work to a failure in a later cell.
            STATE.write_text(json.dumps(rows, indent=2) + "\n")

    models = []
    for r in rows:
        if r.get("model") and r["model"] not in models:
            models.append(r["model"])
    report = format_report(aggregate(rows, models), rows, models)
    REPORT.write_text(report + "\n")
    print("\n" + report)
    print(f"\n(written to {REPORT})")


if __name__ == "__main__":
    main()
