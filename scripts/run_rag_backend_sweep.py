#!/usr/bin/env python3
"""Does the RAG arm's retrieval backend change its results? tfidf vs bm25, n=3, rag mode only.

WHY THIS IS A SEPARATE SCRIPT. run_ablation_repeats.py varies the GROUNDING MECHANISM
(grounded / rag / ungrounded) and owns storage/ablation_repeats.json -- the 45 runs behind the
report's Table 3 and Figure 2. This sweep varies the RETRIEVER INSIDE one arm, which is a
different experiment with a different unit of comparison, and it must not be able to overwrite
those artifacts. Hence its own OUT_DIR, STATE, and REPORT.

WHAT IS CONTROLLED. Both indexes are built over the same 475-chunk corpus, so the only thing
that differs between the two conditions is the scoring function:

    tfidf   TF-IDF cosine, 1-2 grams, sublinear tf, L2-normalized
    bm25    Okapi BM25, unigrams, k1=1.5 b=0.75, Lucene IDF

Everything else is pinned: same scenarios, same gold, same prompt builder, same model
(gpt-5.4 by default), same temperature, same k, same source filter, same exclude_kinds. The
retriever is passed per call rather than through config, so one process can run both without the
first condition leaking into the second.

WHAT TO EXPECT, SO THE RESULT IS NOT OVERREAD. Measured before any generation: the two backends
return the same top-5 for 12 of 63 flows, mean Jaccard 0.88, and the share of retrieved context
that is a threat-tree node is 6.0% (tfidf) against 4.4% (bm25) -- both near zero. The retrieved
context is dominated by mapping-table rows under either backend. A large downstream difference
would therefore be surprising and would deserve investigation before being believed; the honest
prior is that this sweep measures a small effect, and n=3 at recall quantised to 1/|gold| may not
resolve it. That is a result worth having -- "the retrieval algorithm is not what is wrong with
the RAG arm" is exactly the claim the composition numbers imply.

Resumable: runs already recorded in STATE are skipped, so an interrupted sweep can be re-invoked
without paying for completed cells again. --force re-runs everything.

Run: PYTHONPATH=. python3 scripts/run_rag_backend_sweep.py --runs 3
     PYTHONPATH=. python3 scripts/run_rag_backend_sweep.py --report-only   # offline, no LLM calls
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
from scripts.run_ablation_repeats import parse_report

SCENARIOS = ["kidstube", "smart_home", "family_location", "school_grades", "wearable_fitness"]
BACKENDS = ["tfidf", "bm25"]
MODE = "rag"
OUT_DIR = config.ROOT / "storage" / "generated" / "rag_backend"
STATE = config.ROOT / "storage" / "rag_backend_sweep.json"
REPORT = config.ROOT / "storage" / "generated" / "RAG_BACKEND_SWEEP.txt"


def _log(msg: str):
    print(msg, flush=True)


def one_run(scenario: str, backend: str, run: int, provider: str, model: str | None) -> dict:
    from generation.generate import generate_for_scenario, save_generated
    from generation.llm_backend import get_llm_backend
    from retrieval.index import Retriever
    from eval.run_eval import run_eval

    # Assert the index actually serving this condition, rather than trusting the argument. A
    # backend that silently fell back (a missing index rebuilt under a different name, a stale
    # pickle) would produce a clean-looking row for an experiment that never ran.
    r = Retriever.load(backend)
    if r.backend.name != backend:
        raise RuntimeError(f"asked for '{backend}' but retriever resolved to '{r.backend.name}'")
    n_chunks = len(r.chunks)
    del r

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stem = OUT_DIR / f"{scenario}_{MODE}_{backend}_run{run}"
    threats = generate_for_scenario(scenario, mode=MODE, provider=provider, progress=False,
                                    model=model, retrieval_backend=backend)
    gen_path = save_generated(scenario, MODE, threats, out=stem.with_suffix(".json"))
    report = run_eval(scenario, str(gen_path))
    stem.with_name(stem.name + "_eval.txt").write_text(report + "\n")

    llm = get_llm_backend(provider, model)
    metrics = parse_report(report)
    metrics.update(scenario=scenario, mode=MODE, backend=backend, run=run,
                   n_generated=len(threats), n_index_chunks=n_chunks,
                   model=llm.model, top_k=config.TOP_K,
                   exclude_kinds=[k or "untyped" for k in config.RAG_EXCLUDE_KINDS],
                   temperature=config.GENERATION_TEMPERATURE,
                   temperature_applied=llm.temperature_applied,
                   code=config.code_state())
    return metrics


def aggregate(rows: list[dict]) -> list[dict]:
    out = []
    for scenario in SCENARIOS:
        for backend in BACKENDS:
            got = [r for r in rows if r["scenario"] == scenario and r["backend"] == backend
                   and r.get("status", "ok") == "ok"]
            if not got:
                continue
            agg = {"scenario": scenario, "backend": backend, "n_runs": len(got)}
            for metric in ("n_generated", "precision", "recall", "f1", "citation"):
                vals = [g[metric] for g in got if g.get(metric) is not None]
                if not vals:
                    continue
                agg[metric] = {
                    "mean": round(statistics.mean(vals), 4),
                    # Sample SD, and None (not 0.0) at n=1 -- a fabricated zero would read as
                    # "perfectly reproducible". Same convention as run_ablation_repeats.py.
                    "sd": round(statistics.stdev(vals), 4) if len(vals) > 1 else None,
                    "min": min(vals), "max": max(vals), "values": vals,
                }
            out.append(agg)
    return out


def format_report(aggs: list[dict], rows: list[dict]) -> str:
    ok = [r for r in rows if r.get("status", "ok") == "ok"]
    models = {r.get("model") for r in ok}
    applied = {r.get("temperature_applied") for r in ok}
    temps = {r.get("temperature") for r in ok}
    chunks = {r.get("n_index_chunks") for r in ok}
    lines = [
        "RAG arm: retrieval backend sweep -- tfidf vs bm25, mean (sd) over runs",
        f"  model {models or '?'}; temperature {temps or '?'}; deployment honoured it: {applied or '?'}",
        f"  mode '{MODE}' only; k={ {r.get('top_k') for r in ok} or '?'}; "
        f"index chunks {chunks or '?'} (both backends over the same corpus)",
        f"  code {next((r.get('code') for r in ok if r.get('code')), '?')}",
        "",
        "  Both conditions read the same corpus with the same filters. The only variable is the",
        "  scoring function. Recall is quantised at 1/|gold| (0.05 on the 20-threat scenarios),",
        "  so a difference below that is unmeasurable however many runs are made.",
        "",
        f"  {'scenario':18} {'backend':8} {'runs':>4} {'n_gen':>12} {'P':>13} {'R':>13} {'F1':>13} {'citation':>13}",
    ]

    def cell(a, key, fmt="{:.2f}"):
        if key not in a:
            return f"{'-':>13}"
        m, sd = a[key]["mean"], a[key]["sd"]
        txt = fmt.format(m) + (f" ({fmt.format(sd)})" if sd is not None else " (--)")
        return f"{txt:>13}"

    for a in aggs:
        lines.append(
            f"  {a['scenario']:18} {a['backend']:8} {a['n_runs']:>4} "
            + cell(a, "n_generated", "{:.0f}") + cell(a, "precision") + cell(a, "recall")
            + cell(a, "f1") + cell(a, "citation"))

    # Paired across scenarios: each scenario is one block, same as the grounding ablation. This
    # is the contrast to read; the per-scenario rows above are its inputs, not five findings.
    lines += ["", "  Paired across scenarios (each scenario one block), mean of per-scenario means:"]
    by = {(a["scenario"], a["backend"]): a for a in aggs}
    for metric in ("citation", "recall", "precision", "f1", "n_generated"):
        diffs = [by[(s, "bm25")][metric]["mean"] - by[(s, "tfidf")][metric]["mean"]
                 for s in SCENARIOS
                 if (s, "bm25") in by and (s, "tfidf") in by
                 and metric in by[(s, "bm25")] and metric in by[(s, "tfidf")]]
        if len(diffs) < 2:
            continue
        mean, sd = statistics.mean(diffs), statistics.stdev(diffs)
        wins = sum(d > 0 for d in diffs)
        fmt = "{:+.2f}" if metric == "n_generated" else "{:+.3f}"
        lines.append(f"    {metric:11} bm25 - tfidf  mean {fmt.format(mean):>7}  sd {sd:.3f}  "
                     f"n={len(diffs)}  favours bm25 in {wins}/{len(diffs)}")

    failed = [r for r in rows if r.get("status") == "failed"]
    if failed:
        lines += ["", f"  FAILED RUNS: {len(failed)}"]
        lines += [f"    {r['scenario']} {r['backend']} run{r['run']}: {r['error']}" for r in failed]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scenarios", nargs="+", default=SCENARIOS)
    ap.add_argument("--backends", nargs="+", default=BACKENDS)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--provider", default="azure")
    ap.add_argument("--model", default=None, help="deployment name; default = config.AZURE_AI_MODEL")
    ap.add_argument("--force", action="store_true", help="re-run cells already present in STATE")
    ap.add_argument("--report-only", action="store_true",
                    help="Re-aggregate recorded runs offline; makes no LLM calls.")
    args = ap.parse_args()

    if args.report_only:
        rows = json.loads(STATE.read_text())
    else:
        rows = [] if args.force or not STATE.exists() else json.loads(STATE.read_text())
        done = {(r["scenario"], r["backend"], r["run"]) for r in rows
                if r.get("status", "ok") == "ok"}
        # Scenario is the OUTER loop so both backends for one scenario land close together in
        # time. If the deployment drifts mid-sweep, it perturbs the two conditions of a block
        # roughly equally instead of biasing whichever backend ran last.
        todo = [(s, b, run) for s in args.scenarios for b in args.backends
                for run in range(1, args.runs + 1) if (s, b, run) not in done]
        if done:
            _log(f"resuming: {len(done)} cell(s) already recorded, {len(todo)} to run")
        for i, (scenario, backend, run) in enumerate(todo, 1):
            tag = f"[{i}/{len(todo)}] {scenario} {backend} run{run}"
            try:
                m = one_run(scenario, backend, run, args.provider, args.model)
                _log(f"{tag}: n={m['n_generated']} P={m['precision']:.2f} "
                     f"R={m['recall']:.2f} F1={m['f1']:.2f} cite={m['citation']}")
                rows.append(m)
            except Exception as e:
                _log(f"{tag}: FAILED {type(e).__name__}: {e}")
                traceback.print_exc()
                rows.append({"scenario": scenario, "backend": backend, "run": run,
                             "status": "failed", "error": f"{type(e).__name__}: {e}"})
            # Written every cell, not once at the end: a sweep this long must not lose completed
            # work to a failure in a later cell.
            STATE.write_text(json.dumps(rows, indent=2) + "\n")

    report = format_report(aggregate(rows), rows)
    REPORT.write_text(report + "\n")
    print("\n" + report)
    print(f"\n(written to {REPORT})")


if __name__ == "__main__":
    main()
