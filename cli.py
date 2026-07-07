#!/usr/bin/env python3
"""LINDDUN knowledge-base CLI.

Usage:
  python cli.py build                         # (re)build the index
  python cli.py search "QUERY" [--source S] [-k N]
  python cli.py ask "QUESTION"                # retrieve + Claude answer (needs ANTHROPIC_API_KEY)
  python cli.py stats                         # corpus statistics
  python cli.py generate --scenario kidstube [--ungrounded] [--provider anthropic|openai]   # LLM threat generation
  python cli.py eval --scenario kidstube --generated storage/generated/kidstube_grounded.json [--strict]
"""
from __future__ import annotations
import argparse
import sys

import config
from retrieval.index import Retriever


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
    from generation.generate import generate_for_scenario, save_generated
    grounded = not args.ungrounded
    threats = generate_for_scenario(args.scenario, grounded=grounded, provider=args.provider)
    path = save_generated(args.scenario, grounded, threats)
    label = "grounded" if grounded else "ungrounded"
    print(f"Generated {len(threats)} threats ({label}) for scenario '{args.scenario}' -> {path}")


def cmd_eval(args):
    from eval.run_eval import run_eval
    print(run_eval(args.scenario, args.generated, strict=args.strict))


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
    sp.add_argument("--source", choices=["linddun", "regulations", "scenarios"], default=None)
    sp.add_argument("-k", type=int, default=config.TOP_K)
    sp.set_defaults(func=cmd_search)

    sa = sub.add_parser("ask")
    sa.add_argument("query")
    sa.set_defaults(func=cmd_ask)

    sg = sub.add_parser("generate")
    sg.add_argument("--scenario", required=True, choices=["kidstube", "genomic"])
    sg.add_argument("--ungrounded", action="store_true",
                     help="Ablation baseline: no interaction-context/regulatory retrieval.")
    sg.add_argument("--provider", choices=["anthropic", "openai"], default=None,
                     help="Override LLM_PROVIDER from config/.env for this run.")
    sg.set_defaults(func=cmd_generate)

    se = sub.add_parser("eval")
    se.add_argument("--scenario", required=True, choices=["kidstube", "genomic"])
    se.add_argument("--generated", required=True, help="Path to a generated threats JSON file.")
    se.add_argument("--strict", action="store_true", help="Also require exact tree_node match.")
    se.set_defaults(func=cmd_eval)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
