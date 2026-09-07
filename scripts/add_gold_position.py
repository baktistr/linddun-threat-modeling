#!/usr/bin/env python3
"""Record the LINDDUN Pro position each gold threat was already asserting.

WHAT THIS IS NOT. It does not decide where a threat belongs. Every position written here is
READ OFF the `originator_id` the human analyst already wrote, by comparing it against the flow's
own endpoints and id. Nothing is inferred from a title, a description, or a threat type, because
the gold is the ground truth this project scores against and a position invented here would be
evidence manufactured to fit the schema that wanted it.

WHY IT IS NEEDED. generation/schema.py gained a `position` field ("S" | "fl" | "D") after the
LINDDUN Pro tutorial's three elicitation positions. The gold predates it, so a generated threat
citing "fl" has nothing to be scored against. The mapping is nonetheless already present in the
data:

    originator_id == flow.source        -> S
    originator_id == flow.destination   -> D
    originator_id == flow.id            -> fl

THE FL CASES ARE REAL, AND THEY ARE THE POINT. KidsTube's gold carries three threats whose
originator_id is a FLOW id (DF1, DF4, DF8) -- "Interception of identified parent data during
registration transmission", "Child search queries and actions observable on the network". Human
LINDDUN analysts reached for the flow as a location unprompted, exactly as Qwen3.5-9B did when it
answered "fl" and was scored as fabricating a citation. verify.py's docstring has always promised
to accept "a real element or flow id"; this is the data that promise was written for.

WHAT IS LEFT UNSET, AND WHY THAT IS THE HONEST ANSWER. Anything that does not resolve to one of
the three gets no position and a note saying so, rather than a guess:

  * genomic -- originator_id is empty throughout; that catalog locates threats with
    dfd_source_id/dfd_destination_id in its own id scheme (S3-PH), not with element ids.
  * kidstube id=40 -- interaction says P3-EE2 while flow DF12 is P2->EE2, so originator_id 'P3'
    matches neither endpoint nor the flow. That is a pre-existing inconsistency in the catalog,
    surfaced here rather than papered over.
  * the derived kidstube variants -- their DFDs are re-derived, so element ids need not agree
    with the hand catalog's.

Every threat also gets `position_source`, so a reader can tell a recorded assertion from an
absence. Idempotent: re-running rewrites the same values.

Run: PYTHONPATH=. python3 scripts/add_gold_position.py            # report only
     PYTHONPATH=. python3 scripts/add_gold_position.py --write    # apply
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config

DERIVED = "derived_from_originator_id"
UNRESOLVED = "unresolved"


def _flow_for(threat: dict, dfd: dict) -> dict | None:
    """The flow a gold threat sits on, from whichever locator its catalog uses."""
    m = re.search(r"\[(\w+)\]", threat.get("interaction") or "")
    if m:
        return next((f for f in dfd["flows"] if f["id"] == m.group(1)), None)
    src, dst = threat.get("dfd_source_id"), threat.get("dfd_destination_id")
    if src and dst:
        return next((f for f in dfd["flows"]
                     if f["source"] == src and f["destination"] == dst), None)
    return None


def position_for(threat: dict, dfd: dict) -> tuple[str | None, str]:
    """(position, note). None means: this threat does not say, and we do not guess."""
    oid = threat.get("originator_id")
    if not oid:
        return None, "no originator_id in this catalog"
    flow = _flow_for(threat, dfd)
    if flow is None:
        return None, "no resolvable flow for this threat"
    if oid == flow["source"]:
        return "S", ""
    if oid == flow["destination"]:
        return "D", ""
    if oid == flow["id"]:
        return "fl", ""
    return None, (f"originator_id {oid!r} matches neither endpoint "
                  f"({flow['source']}/{flow['destination']}) nor the flow id {flow['id']!r}")


def process(scenario: str, write: bool) -> Counter:
    gold_path = config.KB_DIR / "scenarios" / scenario / "gold_standard_threats.json"
    dfd_path = config.KB_DIR / "scenarios" / scenario / "dfd.json"
    if not gold_path.exists() or not dfd_path.exists():
        return Counter()
    dfd = json.loads(dfd_path.read_text())
    doc = json.loads(gold_path.read_text())
    threats = doc["threats"] if isinstance(doc, dict) else doc

    counts: Counter = Counter()
    for t in threats:
        pos, note = position_for(t, dfd)
        if pos:
            t["position"] = pos
            t["position_source"] = DERIVED
            t.pop("position_note", None)
            counts[pos] += 1
        else:
            t["position"] = ""
            t["position_source"] = UNRESOLVED
            t["position_note"] = note
            counts["unset"] += 1
            print(f"    unset  id={t.get('id')}: {note}")
    if write:
        gold_path.write_text(json.dumps(doc, indent=2) + "\n")
    return counts


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write", action="store_true",
                    help="Apply the change. Without it, report only and touch nothing.")
    args = ap.parse_args()

    total: Counter = Counter()
    for d in sorted((config.KB_DIR / "scenarios").iterdir()):
        if not d.is_dir():
            continue
        print(f"  {d.name}")
        c = process(d.name, args.write)
        if c:
            print(f"    {dict(c)}")
        total.update(c)
    print()
    print(f"TOTAL {dict(total)}")
    print("fl = threats the human analysts already located at the data flow")
    if not args.write:
        print("\n(report only -- re-run with --write to apply)")


if __name__ == "__main__":
    main()
