#!/usr/bin/env python3
"""LINDDUN knowledge-base CLI.

Usage:
  python cli.py build                         # (re)build the index
  python cli.py search "QUERY" [--source S] [-k N]
  python cli.py ask "QUESTION"                # retrieve + Claude answer (needs ANTHROPIC_API_KEY)
  python cli.py stats                         # corpus statistics
  python cli.py generate --scenario kidstube [--ungrounded|--rag] [--framework linddun|panoptic] [--provider anthropic|openai|azure]
  python cli.py eval --scenario kidstube --generated storage/generated/kidstube_grounded.json [--strict]
  python cli.py eval --scenario genomic --generated storage/generated/genomic_panoptic_grounded.json --framework panoptic
  python cli.py adjudicate --scenario kidstube --generated storage/generated/kidstube_grounded.json [--n N] [--report-only]
"""
from __future__ import annotations
import argparse
import sys

import config
from retrieval.index import Retriever

GENERATE_SCENARIOS = ["kidstube", "genomic", "smart_home", "family_location"]
EVAL_SCENARIOS = ["kidstube", "genomic", "smart_home", "family_location"]  # only scenarios with a gold_standard_threats.json


def cmd_build(_):
    r = Retriever.build()
    print(f"Built index: {len(r.chunks)} chunks, backend '{r.backend.name}', shape {r.matrix.shape}")


def cmd_search(args):
    r = Retriever.load()
    hits = r.search(args.query, k=args.k, source=args.source)
    print(f"\nQuery: {args.query!r}  (backend={r.backend.name}, source filter={args.source})\n")
    for i, h in enumerate(hits, 1):
        loc = f"{h.chunk.source}/{h.chunk.doc}"
        sect = f" §{h.chunk.section}" if h.chunk.section else ""
        print(f"[{i}] score={h.score:.3f}  {loc}{sect}")
        text = h.chunk.text.replace("\n", " ")
        print(f"    {text[:240]}{'…' if len(text) > 240 else ''}\n")


def cmd_stats(_):
    from collections import Counter
    r = Retriever.load()
    by_source = Counter(c.source for c in r.chunks)
    by_kind = Counter(c.meta.get("kind", "prose") for c in r.chunks)
    print(f"Total chunks: {len(r.chunks)}")
    print(f"Backend: {r.backend.name}")
    print(f"By source: {dict(by_source)}")
    print(f"By kind:   {dict(by_kind)}")


def cmd_generate(args):
    from generation.generate import generate_for_scenario, save_generated, resolve_mode
    try:
        mode = resolve_mode(rag=args.rag, ungrounded=args.ungrounded, framework=args.framework)
    except ValueError as e:
        raise SystemExit(str(e))
    threats = generate_for_scenario(args.scenario, mode=mode, provider=args.provider)
    path = save_generated(args.scenario, mode, threats)
    print(f"Generated {len(threats)} threats ({mode}) for scenario '{args.scenario}' -> {path}")


def cmd_eval(args):
    from eval.run_eval import run_eval
    report = run_eval(args.scenario, args.generated, strict=args.strict, by_node=args.by_node,
                      framework=args.framework)
    print(report)
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(report + "\n")
        print(f"\n(report also written to {args.out})")


def cmd_adjudicate(args):
    import json
    from generation.generate import load_generated
    from eval.match import match_threats
    from eval.adjudicate import build_worklist, review_cli, human_corrected_precision

    generated = load_generated(args.generated)
    gold = json.loads((config.KB_DIR / "scenarios" / args.scenario /
                       "gold_standard_threats.json").read_text())["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios" / args.scenario / "dfd.json").read_text())
    match = match_threats(generated, gold, scenario=args.scenario, dfd=dfd)
    mode = generated[0].mode if generated else "unknown"

    path = build_worklist(args.scenario, mode, generated, match, dfd, n=args.n, seed=args.seed)
    print(f"Worklist: {path}  ({match.fp} FP threat(s) total)")
    if not args.report_only:
        review_cli(path)

    hcp = human_corrected_precision(match.tp, match.fp, path)
    if hcp is None:
        print("\nNo labels yet.")
        return
    print(f"\nHuman-corrected precision: n_fp_total={hcp.n_fp_total} n_labeled={hcp.n_labeled} "
          f"(spurious={hcp.spurious} valid_uncatalogued={hcp.valid_uncatalogued} "
          f"borderline={hcp.borderline})")
    print(f"  precision_raw (lower bound):           {hcp.precision_raw:.2f}")
    review_note = "exact, full review" if hcp.is_full_review else "extrapolated from sample"
    print(f"  precision_corrected (point estimate):  {hcp.precision_corrected:.2f}   ({review_note})")


def cmd_ask(args):
    r = Retriever.load()
    hits = r.search(args.query, k=config.TOP_K)
    context = "\n\n".join(
        f"[{i+1}] ({h.chunk.source}/{h.chunk.doc} §{h.chunk.section})\n{h.chunk.text}"
        for i, h in enumerate(hits)
    )
    if not config.ANTHROPIC_API_KEY:
        print("No ANTHROPIC_API_KEY set. Retrieved context (no generation):\n")
        print(context)
        return
    try:
        import anthropic
    except ImportError:
        print("anthropic package not installed. `pip install anthropic`. Showing context only:\n")
        print(context)
        return
    client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    prompt = (
        "You are a LINDDUN Pro privacy threat-modeling assistant. Answer the question "
        "using ONLY the retrieved context below. Cite the bracketed source numbers you use. "
        "If the context is insufficient, say so.\n\n"
        f"Context:\n{context}\n\nQuestion: {args.query}"
    )
    resp = client.messages.create(
        model=config.CLAUDE_MODEL, max_tokens=800,
        messages=[{"role": "user", "content": prompt}],
    )
    print(resp.content[0].text)


def main():
    p = argparse.ArgumentParser(description="LINDDUN knowledge-base CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("build").set_defaults(func=cmd_build)
    sub.add_parser("stats").set_defaults(func=cmd_stats)

    sp = sub.add_parser("search")
    sp.add_argument("query")
    sp.add_argument("--source", choices=["linddun", "scenarios", "panoptic"], default=None)
    sp.add_argument("-k", type=int, default=config.TOP_K)
    sp.set_defaults(func=cmd_search)

    sa = sub.add_parser("ask")
    sa.add_argument("query")
    sa.set_defaults(func=cmd_ask)

    sg = sub.add_parser("generate")
    sg.add_argument("--scenario", required=True, choices=GENERATE_SCENARIOS)
    sg.add_argument("--framework", choices=["linddun", "panoptic"], default="linddun",
                     help="Which methodology to ground in: LINDDUN (default, mapping_table.json/"
                          "threat_trees.json) or MITRE PANOPTIC (knowledge_base/panoptic/"
                          "taxonomy.json, no Process-mediation gate -- every flow attempted).")
    sg.add_argument("--ungrounded", action="store_true",
                     help="Ablation baseline: no context from the chosen --framework's KB.")
    sg.add_argument("--rag", action="store_true",
                     help="RAG ablation: semantic-retrieval-grounded prompt (top-k over the "
                          "chosen --framework's KB), vs. the default deterministic/exhaustive "
                          "grounding or --ungrounded's no context at all. Mutually exclusive "
                          "with --ungrounded.")
    sg.add_argument("--provider", choices=["anthropic", "openai", "azure"], default=None,
                     help="Override LLM_PROVIDER from config/.env for this run.")
    sg.set_defaults(func=cmd_generate)

    se = sub.add_parser("eval")
    se.add_argument("--scenario", required=True, choices=EVAL_SCENARIOS)
    se.add_argument("--generated", required=True, help="Path to a generated threats JSON file.")
    se.add_argument("--strict", action="store_true", help="Also require exact tree_node match.")
    se.add_argument("--by-node", action="store_true",
                     help="Also report a per-tree-node breakdown, not just per LINDDUN category.")
    se.add_argument("--out", default=None, help="Also write the report to this path.")
    se.add_argument("--framework", choices=["linddun", "panoptic"], default="linddun",
                     help="Score against LINDDUN threat_type/tree_node (default), or PANOPTIC "
                          "panoptic_action membership (for mode=panoptic_* generated output).")
    se.set_defaults(func=cmd_eval)

    sj = sub.add_parser("adjudicate")
    sj.add_argument("--scenario", required=True, choices=EVAL_SCENARIOS)
    sj.add_argument("--generated", required=True, help="Path to a generated threats JSON file.")
    sj.add_argument("--n", type=int, default=None,
                     help="Review a random sample of N unmatched (FP) threats instead of all of "
                          "them. Omit to review every FP.")
    sj.add_argument("--seed", type=int, default=42, help="Sampling seed, for a reproducible sample.")
    sj.add_argument("--report-only", action="store_true",
                     help="Don't prompt interactively -- just (re)build the worklist file and "
                          "print human-corrected precision from whatever's already labeled.")
    sj.set_defaults(func=cmd_adjudicate)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
