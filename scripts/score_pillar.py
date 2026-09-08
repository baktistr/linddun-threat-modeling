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
  3. PARALLEL FLOWS. kidstube draws DF7 and DF10 both P3->DS2. An edge-level export cannot say
     which it meant, so an edge maps to the SET of flows over that pair and a gold threat on
     either counts. Keying on one id silently dropped whichever flow came second.
  4. Our threat_trees.json is a CURATED SUBSET (51 nodes, max depth 4). PILLAR cites deeper.
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


def resolve_endpoint(label: str, ids: set[str], by_name: dict[str, str]) -> str | None:
    """PILLAR's endpoint label -> one of OUR element ids, or None.

    Two conventions appear in the exports we have. The first run named elements freely
    ("Authentication Service"), so the only handle is the name. A later run was redrawn with our
    ids carried in the label ("P1 Authentication Services") -- there the leading token IS the
    element id and is authoritative, because the name after it drifts harmlessly ("Services" vs
    "Service", "MongoDB - users" vs "MongoDB users collection") and name matching would throw
    away an edge the analyst deliberately aligned. Id first, name second; a label that gives
    neither stays unmapped rather than being guessed onto the nearest element.
    """
    head = label.split()[0] if label.split() else ""
    if head in ids:
        return head
    return by_name.get(label)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pillar", required=True)
    ap.add_argument("--scenario", default="kidstube")
    ap.add_argument("--model", required=True, help="Which model PILLAR ran (the export omits it).")
    ap.add_argument("--note", default="", help="Anything else needed to reproduce this run.")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    dfd = json.loads((config.KB_DIR / "scenarios" / args.scenario / "dfd.json").read_text())
    ids = {e["id"] for e in dfd["elements"]}
    by_name = {e["name"]: e["id"] for e in dfd["elements"]}
    # A set per endpoint pair, not one id: kidstube draws DF7 and DF10 both P3->DS2, and an
    # edge-level export cannot say which of the two it meant.
    by_endpoints: dict[tuple[str, str], set[str]] = {}
    for f in dfd["flows"]:
        by_endpoints.setdefault((f["source"], f["destination"]), set()).add(f["id"])
    gold = json.loads((config.KB_DIR / "scenarios" / args.scenario
                       / "gold_standard_threats.json").read_text())["threats"]

    entries = json.loads(Path(args.pillar).read_text())
    findings, unmapped, resolution = [], Counter(), Counter()
    for e in entries:
        src = resolve_endpoint(e["edge"]["from"], ids, by_name)
        dst = resolve_endpoint(e["edge"]["to"], ids, by_name)
        for lbl, res in ((e["edge"]["from"], src), (e["edge"]["to"], dst)):
            how = ("by id" if lbl.split()[:1] and lbl.split()[0] in ids
                   else "by name" if res else "unresolved")
            resolution[how] += 1
        fids = by_endpoints.get((src, dst), set())
        if not fids:
            unmapped[f"{e['edge']['from']} -> {e['edge']['to']}"] += 1
        findings.append({"flow_ids": fids, "threat_type": CATEGORY.get(e["category"]),
                         "nodes": [e.get("source_id"), e.get("data_flow_id"),
                                   e.get("destination_id")]})
    # PILLAR emits one citation per position, in this order.
    POSITIONS = ("S (source)", "fl (data flow)", "D (destination)")

    matched, tp = set(), 0
    for f in findings:
        if not f["flow_ids"]:
            continue
        for g in gold:
            if g["id"] in matched or g["threat_type"] != f["threat_type"]:
                continue
            if gold_flow_id(g) not in f["flow_ids"]:
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

    by_position = [Counter(classify_node(f["nodes"][i], valid, ci) for f in findings)
                   for i in range(3)]

    seen_flows = {fid for f in findings for fid in f["flow_ids"]}
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
        "  EDGE-SET MISMATCH (the dominant confound -- PILLAR analyses the DFD drawn in its own",
        "  editor, so which edges exist is a modelling choice made before either tool ran):",
        f"    endpoint labels resolved {dict(resolution)} "
        f"(id = the label carries our element id, so the name after it may drift)",
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
        "  BY LINDDUN PRO POSITION (the export cites one node per position, so this is the one",
        "  place a per-position rate can be read off a third-party tool at all):",
    ]
    for label, k in zip(POSITIONS, by_position):
        r = k["exact"] + k["case_only"]
        L.append(f"    {label:16s} resolvable {r:>3}/{n}  ({r / n:.2f})"
                 f"   abstained (no id) {k['not_an_id']:>3}   fabricated {k['unresolvable']:>3}")
    L += [
        "    An abstention is PILLAR declining to place the threat at that position ('Not",
        "    applicable', 'Threat not possible', or empty), not a wrong answer. The flow position",
        "    is where it declines most -- the same position our own schema could not express",
        "    until the S/fl/D fix.",
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
