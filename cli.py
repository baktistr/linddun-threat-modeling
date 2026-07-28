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


def _scenarios(gold_required: bool = False) -> list[str]:
    """Scenario choices, read off the filesystem rather than hardcoded.

    These were two literal lists whose comment already said what they meant ("only scenarios with
    a gold_standard_threats.json"). Scanning makes that true instead of aspirational, so a
    scenario dropped into knowledge_base/scenarios/ -- notably the adapter's derived ones -- is
    runnable without editing this file and drifting out of sync with what's on disk.
    """
    directory = config.KB_DIR / "scenarios"
    if not directory.exists():
        return []
    return sorted(p.name for p in directory.iterdir()
                  if p.is_dir() and (p / "dfd.json").exists()
                  and (not gold_required or (p / "gold_standard_threats.json").exists()))


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


def _facts_path(scenario: str, override: str | None):
    from pathlib import Path
    if override:
        return Path(override)
    stem = scenario[:-len("_derived")] if scenario.endswith("_derived") else scenario
    return config.ROOT / "adapters" / "data" / f"{stem}_code_facts.json"


def _source_commit(source_root) -> str | None:
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or None
    except Exception:
        return None


def cmd_extract(args):
    import json
    from pathlib import Path
    from adapters.extract import extract_repo, source_files
    from adapters.resolve import resolve_facts

    root = Path(args.source_root).expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"source root not found: {root}")
    facts = resolve_facts(extract_repo(root))
    out = Path(args.out) if args.out else _facts_path(args.scenario, None)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_meta": {
            "source_repo": args.source_root,
            "commit": _source_commit(root),
            "n_source_files": len(source_files(root)),
            "extractor": "adapters/extract.py + adapters/resolve.py",
            "note": "Committed so the adapter runs from a clean clone with no tree-sitter and no "
                    "source checkout -- extraction is the only stage that needs either. Same "
                    "pattern as scripts/data/genomic_figure11_raw.json.",
        },
        "facts": [f.to_dict() for f in facts],
    }
    out.write_text(json.dumps(payload, indent=2) + "\n")
    literal = sum(1 for f in facts if not f.derived)
    print(f"Extracted {len(facts)} facts ({literal} literal, {len(facts) - literal} derived) "
          f"from {payload['_meta']['n_source_files']} files -> {out}")
    print(f"  commit: {payload['_meta']['commit']}")


def _load_facts(path):
    import json
    from adapters.schema import CodeFact
    raw = json.loads(path.read_text())
    facts = raw["facts"] if isinstance(raw, dict) else raw
    return [CodeFact.from_dict(f) for f in facts], (raw.get("_meta", {}) if isinstance(raw, dict) else {})


def cmd_derive(args):
    from pathlib import Path
    from adapters.emit import emit_scenario_dfd
    from adapters.synthesize import synthesize_facts_only

    path = _facts_path(args.scenario, args.facts)
    facts, meta = ([], {})
    if path.exists():
        facts, meta = _load_facts(path)

    if args.mode == "llm_naive":
        # The one arm whose input is the raw repository, not the resolved facts -- that IS the
        # ablation (adapters/synthesize.py). So it needs --source-root and can run with no
        # committed facts at all, exactly as the main pipeline's `ungrounded` arm still needs the
        # model but not the knowledge base.
        from adapters.synthesize import synthesize_llm_naive
        if not args.source_root:
            raise SystemExit("--mode llm_naive reads the raw source and needs --source-root PATH "
                             "(the one arm that cannot run from committed facts alone).")
        root = Path(args.source_root).expanduser().resolve()
        if not root.exists():
            raise SystemExit(f"source root not found: {root}")
        dfd = synthesize_llm_naive(root, provider=args.provider, scenario_name=args.scenario)
        derived_from = {"repo": args.source_root, "commit": meta.get("commit") or _source_commit(root),
                        "source_root": args.source_root, "adapter_mode": args.mode,
                        "adapter_version": 1}
    else:
        if not path.exists():
            raise SystemExit(f"no facts at {path} -- run `python cli.py extract "
                             f"--source-root PATH` first.")
        if args.mode == "facts_only":
            dfd = synthesize_facts_only(facts, scenario_name=args.scenario)
        else:
            from adapters.synthesize import synthesize_llm
            dfd = synthesize_llm(facts, provider=args.provider, scenario_name=args.scenario)
        derived_from = {"repo": meta.get("source_repo"), "commit": meta.get("commit"),
                        "facts": str(path.relative_to(config.ROOT)),
                        "adapter_mode": args.mode, "adapter_version": 1}

    out = emit_scenario_dfd(
        args.scenario, dfd, derived_from=derived_from,
        purpose="Derived from source code by adapters/. Every element and flow cites the code "
                "facts it was built from; adapters/verify_dfd.py re-derives those citations "
                "against the source rather than trusting them.")
    print(f"Derived {len(dfd['elements'])} elements, {len(dfd['flows'])} flows "
          f"({args.mode}) -> {out}")


def cmd_derive_image(args):
    """DFD image -> derived scenario. The third input adapter (adapters/vision.py)."""
    from pathlib import Path
    from adapters.emit import emit_scenario_dfd
    from adapters.vision import synthesize_vision_naive

    image = Path(args.image).expanduser().resolve()
    if not image.exists():
        raise SystemExit(f"image not found: {image}")

    dfd = synthesize_vision_naive(image, provider=args.provider, scenario_name=args.scenario)
    out = emit_scenario_dfd(
        args.scenario, dfd,
        derived_from={"image": str(image), "image_size": dfd["_meta"]["image_size"],
                      "adapter_mode": dfd["_meta"]["adapter_mode"],
                      "backend": dfd["_meta"]["backend"], "adapter_version": 1},
        purpose="Derived from a DFD image by adapters/vision.py. Every element and flow cites "
                "the pixel region it was read from; adapters/verify_vision.py re-derives those "
                "boxes against the image rather than trusting them.")
    print(f"Derived {len(dfd['elements'])} elements, {len(dfd['flows'])} flows "
          f"(vision_naive) -> {out}")


def cmd_verify_image(args):
    import json
    from adapters.verify_vision import format_verification_report, verify_vision_dfd

    dfd = json.loads((config.KB_DIR / "scenarios" / args.scenario / "dfd.json").read_text())
    image = args.image or dfd.get("_meta", {}).get("derived_from", {}).get("image")
    if not image:
        raise SystemExit(f"{args.scenario} has no _meta.derived_from.image -- pass --image PATH.")
    scale = None if args.calibrate else 1.0
    vs, used, _ = verify_vision_dfd(dfd, image, scale=scale)
    print(format_verification_report(vs, image, used, dfd))


def cmd_verify_dfd(args):
    import json
    from pathlib import Path
    from adapters.verify_dfd import format_verification_report, verify_dfd

    dfd = json.loads((config.KB_DIR / "scenarios" / args.scenario / "dfd.json").read_text())
    facts, _ = _load_facts(_facts_path(args.scenario, args.facts))
    root = Path(args.source_root).expanduser().resolve() if args.source_root else None
    ev, fv = verify_dfd(dfd, facts, source_root=root)
    print(format_verification_report(ev, fv, source_checked=root is not None))


def cmd_eval_dfd(args):
    import json
    from adapters.align import align_elements, align_flows, derived_element_keys, load_hand_keys
    from adapters.evaluate import format_report, score

    derived = json.loads((config.KB_DIR / "scenarios" / args.derived / "dfd.json").read_text())
    hand = json.loads((config.KB_DIR / "scenarios" / args.against / "dfd.json").read_text())
    facts_file = _facts_path(args.derived, args.facts)
    facts = json.loads(facts_file.read_text())
    facts = facts["facts"] if isinstance(facts, dict) else facts

    hand_keys = load_hand_keys(args.against)
    elements = align_elements(derived_element_keys(derived, facts), hand_keys)
    flows = align_flows(derived, hand, elements)
    report = format_report(args.against, args.derived, score(derived, hand, hand_keys, elements, flows),
                           elements, flows)
    print(report)
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(report + "\n")
        print(f"\n(report also written to {args.out})")


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
    sg.add_argument("--scenario", required=True, choices=_scenarios())
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
    se.add_argument("--scenario", required=True, choices=_scenarios(gold_required=True))
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
    sj.add_argument("--scenario", required=True, choices=_scenarios(gold_required=True))
    sj.add_argument("--generated", required=True, help="Path to a generated threats JSON file.")
    sj.add_argument("--n", type=int, default=None,
                     help="Review a random sample of N unmatched (FP) threats instead of all of "
                          "them. Omit to review every FP.")
    sj.add_argument("--seed", type=int, default=42, help="Sampling seed, for a reproducible sample.")
    sj.add_argument("--report-only", action="store_true",
                     help="Don't prompt interactively -- just (re)build the worklist file and "
                          "print human-corrected precision from whatever's already labeled.")
    sj.set_defaults(func=cmd_adjudicate)

    sx = sub.add_parser("extract", help="Source repo -> code facts (needs the optional adapter deps).")
    sx.add_argument("--source-root", required=True, help="Path to a checkout of the source repo.")
    sx.add_argument("--out", default=None,
                     help="Where to write the facts (default: adapters/data/<scenario>_code_facts.json).")
    sx.add_argument("--scenario", default="kidstube", help="Names the output file.")
    sx.set_defaults(func=cmd_extract)

    sd = sub.add_parser("derive", help="Code facts -> DFD, emitted as a *_derived scenario.")
    sd.add_argument("--facts", default=None,
                     help="Facts JSON (default: adapters/data/<scenario>_code_facts.json).")
    sd.add_argument("--scenario", default="kidstube_derived",
                     help="Derived scenario to write. Must end in _derived.")
    sd.add_argument("--mode", choices=["facts_only", "llm", "llm_naive"], default="facts_only",
                     help="facts_only: deterministic, no LLM (the baseline the LLM must beat). "
                          "llm: closed fact-id citation vocabulary. llm_naive: open file:line "
                          "vocabulary (the ablation baseline).")
    sd.add_argument("--provider", default=None, help="LLM provider for --mode llm/llm_naive.")
    sd.add_argument("--source-root", default=None,
                     help="Path to a checkout of the source repo. REQUIRED for --mode llm_naive, "
                          "whose input is the raw source rather than the committed facts.")
    sd.set_defaults(func=cmd_derive)

    si = sub.add_parser("derive-image", help="DFD image -> DFD, emitted as a *_derived scenario.")
    si.add_argument("--image", required=True, help="Path to the DFD diagram (PNG/JPEG/WebP).")
    si.add_argument("--scenario", default="kidstube_image_derived",
                     help="Derived scenario to write. Must end in _derived.")
    si.add_argument("--provider", default=None,
                     help="LLM provider. The backend must be able to see images.")
    si.set_defaults(func=cmd_derive_image)

    sq = sub.add_parser("verify-image",
                        help="Re-derive every cited pixel box against the image. No LLM.")
    sq.add_argument("--scenario", default="kidstube_image_derived")
    sq.add_argument("--image", default=None,
                     help="Defaults to _meta.derived_from.image in the scenario's dfd.json.")
    sq.add_argument("--calibrate", action="store_true",
                     help="Search for the global scale that best maps cited coordinates onto the "
                          "image. Off by default: the uncalibrated rate is what the citations are "
                          "worth as emitted. Both are printed either way.")
    sq.set_defaults(func=cmd_verify_image)

    sw = sub.add_parser("verify-dfd", help="Re-derive every citation in a derived DFD. No LLM.")
    sw.add_argument("--scenario", default="kidstube_derived")
    sw.add_argument("--facts", default=None)
    sw.add_argument("--source-root", default=None,
                     help="Re-parse the source to confirm each cited file:line really holds the "
                          "claimed construct. Omit and facts_present reports not_checked -- never "
                          "a pass.")
    sw.set_defaults(func=cmd_verify_dfd)

    sv = sub.add_parser("eval-dfd", help="Score a derived DFD against a hand-authored one.")
    sv.add_argument("--derived", required=True, help="Derived scenario to score.")
    sv.add_argument("--against", required=True,
                     help="Hand-authored scenario to score against. REQUIRED and never "
                          "defaulted: scoring one system's DFD against another system's "
                          "ground truth produces a confident, meaningless number. Most repos "
                          "have no hand-authored DFD at all -- for those, use `verify-dfd`, "
                          "which needs only the source.")
    sv.add_argument("--facts", default=None, help="Facts JSON the derived DFD cites.")
    sv.add_argument("--out", default=None, help="Also write the report here.")
    sv.set_defaults(func=cmd_eval_dfd)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
