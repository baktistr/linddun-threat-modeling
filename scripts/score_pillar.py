#!/usr/bin/env python3
"""Score a PILLAR export against this project's gold standard, using this project's matcher.

PILLAR (Mollaeefar et al., EuroS&PW 2025) is the closest prior system and the baseline
ABSTRACT.md argues against, so its output has to be scored by the SAME rule as ours or the
comparison means nothing. This does the translation and nothing else:

    PILLAR unit          one (edge x category) entry, carrying THREE node citations
                         (source_id / data_flow_id / destination_id)
    our unit             one threat per (flow, tree_node)

so the counts are not directly comparable and the report says so rather than hiding it.

THREE CONFOUNDS this script measures rather than papers over:

  1. PILLAR analyses ITS OWN DFD. Edges are matched to ours by endpoint NAME; anything with no
     counterpart is reported separately and can never match, whatever its quality. Our flows
     PILLAR never saw are reported too -- they inflate our recall relative to its.
  2. Node ids use a different case convention (PILLAR "DD.1.1", ours "Dd.1.1"). Case-folded
     matches are counted as valid and reported as a separate line, because a casing convention is
     not a fabrication.
  3. Our threat_trees.json is a CURATED SUBSET (51 nodes, max depth 4). PILLAR cites deeper.
     A node absent from our KB whose PARENT is present is a gap in our coverage, not a PILLAR
     error, and is counted separately. Reporting those as hallucinations would flatter us.

The export carries no model or DFD metadata, so --model and --note are recorded into the report;
otherwise a second run is indistinguishable from the first.

Run: PYTHONPATH=. python3 scripts/score_pillar.py --pillar knowledge_base/PILLAR/<file>.json \
         --model gpt-4o-mini --note "PILLAR's own DFD, built in its editor"
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from eval.match import gold_flow_id

# PILLAR's category names -> this KB's type codes.
CATEGORY = {
    "Linking": "L", "Identifying": "I", "Non-repudiation": "Nr", "Detecting": "D",
    "Data disclosure": "Dd", "Unawareness and unintervenability": "U", "Non-compliance": "Nc",
}
NON_IDS = {"not applicable", "threat not possible", ""}


def load_kb_nodes() -> set[str]:
    trees = json.loads((config.KB_DIR / "linddun" / "threat_trees.json").read_text())
    return {nid for tt in trees["threat_types"].values() for nid in tt.get("nodes", {})}


def classify_node(nid: str, valid: set[str], ci: dict[str, str]) -> str:
    if not nid or nid.strip().lower() in NON_IDS:
        return "not_an_id"
    if nid in valid:
        return "exact"
    if nid.lower() in ci:
        return "case_only"
    parent = ".".join(nid.split(".")[:-1])
    if parent and parent.lower() in ci:
        return "below_our_kb"       # our subset stops shallower -- OUR gap, not their error
    return "unresolvable"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pillar", required=True)
    ap.add_argument("--scenario", default="kidstube")
    ap.add_argument("--model", required=True, help="Which model PILLAR ran (the export omits it).")
    ap.add_argument("--note", default="", help="Anything else needed to reproduce this run.")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    dfd = json.loads((config.KB_DIR / "scenarios" / args.scenario / "dfd.json").read_text())
    names = {e["id"]: e["name"] for e in dfd["elements"]}
    by_endpoints = {(names[f["source"]], names[f["destination"]]): f["id"] for f in dfd["flows"]}
    gold = json.loads((config.KB_DIR / "scenarios" / args.scenario
                       / "gold_standard_threats.json").read_text())["threats"]

    entries = json.loads(Path(args.pillar).read_text())
    findings, unmapped = [], Counter()
    for e in entries:
        key = (e["edge"]["from"], e["edge"]["to"])
        fid = by_endpoints.get(key)
        if fid is None:
            unmapped[f"{key[0]} -> {key[1]}"] += 1
        findings.append({"flow_id": fid, "threat_type": CATEGORY.get(e["category"]),
                         "nodes": [e.get("source_id"), e.get("data_flow_id"),
                                   e.get("destination_id")]})

    matched, tp = set(), 0
    for f in findings:
        if not f["flow_id"]:
            continue
        for g in gold:
            if g["id"] in matched or g["threat_type"] != f["threat_type"]:
                continue
            if gold_flow_id(g) != f["flow_id"]:
                continue
            matched.add(g["id"]); tp += 1; break
    n = len(findings); fp = n - tp; fn = len(gold) - len(matched)
    prec = tp / n if n else 0.0
    rec = tp / len(gold) if gold else 0.0
    f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0

    valid = load_kb_nodes()
    ci = {v.lower(): v for v in valid}
    kinds = Counter(classify_node(nid, valid, ci)
                    for f in findings for nid in f["nodes"])
    total_nodes = sum(kinds.values())
    resolvable = kinds["exact"] + kinds["case_only"]

    seen_flows = {f["flow_id"] for f in findings if f["flow_id"]}
    never_seen = sorted({f["id"] for f in dfd["flows"]} - seen_flows,
                        key=lambda x: int("".join(c for c in x if c.isdigit()) or 0))

    L = [
        f"PILLAR scored against {args.scenario}'s gold, using eval/match.py's rule "
        f"(threat_type + same flow)",
        f"  export : {args.pillar}",
        f"  model  : {args.model}" + (f"   [{args.note}]" if args.note else ""),
        f"  unit   : {n} (edge x category) findings carrying {total_nodes} node citations.",
        f"           Our unit is one threat per (flow, node) -- counts are NOT directly comparable.",
        "",
        f"  TP {tp}   FP {fp}   FN {fn}",
        f"  precision {prec:.2f}   recall {rec:.2f}   F1 {f1:.2f}",
        "",
        "  DFD MISMATCH (the dominant confound -- PILLAR analysed its own DFD):",
        f"    findings on edges our DFD does not have : {sum(unmapped.values())} of {n} "
        f"(can never match, whatever their quality)",
    ]
    for edge, c in unmapped.most_common():
        L.append(f"      {edge}  x{c}")
    L.append(f"    our flows PILLAR never analysed        : {never_seen or 'none'}")
    L += [
        "",
        "  NODE CITATION VALIDITY (independently re-derived against threat_trees.json):",
        f"    exact match in our KB      {kinds['exact']:>4}  ({kinds['exact']/total_nodes:.2f})",
        f"    match after case-folding   {kinds['case_only']:>4}  ({kinds['case_only']/total_nodes:.2f})"
        f"   -- convention (DD.1.1 vs Dd.1.1), not a fabrication",
        f"    below our KB's depth       {kinds['below_our_kb']:>4}  ({kinds['below_our_kb']/total_nodes:.2f})"
        f"   -- parent exists; OUR subset stops shallower",
        f"    not an id at all           {kinds['not_an_id']:>4}  ({kinds['not_an_id']/total_nodes:.2f})"
        f"   -- empty, or prose in an id field",
        f"    unresolvable               {kinds['unresolvable']:>4}  ({kinds['unresolvable']/total_nodes:.2f})",
        f"    -> resolvable in our KB    {resolvable:>4}  ({resolvable/total_nodes:.2f})",
        "",
        f"  Our KB holds {len(valid)} nodes, max depth "
        f"{max(nid.count('.') for nid in valid) + 1}. A model cannot cite a node it was never "
        f"given, so 'below our KB's depth' is a limit on OUR coverage, not on PILLAR.",
    ]
    report = "\n".join(L)
    print(report)
    if args.out:
        Path(args.out).write_text(report + "\n")
        print(f"\n(written to {args.out})")


if __name__ == "__main__":
    main()
