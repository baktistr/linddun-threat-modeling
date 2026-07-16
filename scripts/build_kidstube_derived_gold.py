#!/usr/bin/env python3
"""Re-anchor KidsTube's 41 gold threats onto the DERIVED DFD, so the adapter's output can be
scored end to end on the same ground truth as the hand-authored DFD.

The gold standard anchors each threat to a hand-DFD flow id ("EE1-P1 [DF1]"). A derived DFD has
its own element and flow ids, so scoring generated-on-derived output against the hand gold
requires translating those anchors through the adapter's alignment map. That translation is the
only thing this script does; the threats themselves -- types, tree nodes, descriptions,
assumptions -- are copied verbatim. The gold's *content* is human-authored ground truth and is
never rewritten to fit a derived DFD; bending the answer key to fit the answer is not evaluation.

knowledge_base/scenarios/kidstube/gold_standard_threats.json is never modified.

Two threats have no derived counterpart. DF13 (DS2->P4) and DF14 (P4->EE3) hang off P4 (AI
Recommendation Engine) and EE3 (Third-Party Advertisers), which system_description.md marks
"(planned)" and which exist in no line of the KidsTube codebase. Their threats are emitted with
no [DFn] tag, so resolve_gold_flow() returns None and eval/reachability.py classifies them
unresolved_location rather than counting them as recall failures against a DFD that structurally
cannot contain them. This is why M4's honest comparison is against the hand baseline restricted
to the same 39 anchorable threats, not against all 41.

Usage:
  python scripts/build_kidstube_derived_gold.py --identity   # M0 plumbing gate (ids pass through)
  python scripts/build_kidstube_derived_gold.py              # M1+: maps come from the alignment
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from adapters.emit import emit_scenario_gold, scenario_dir
from eval.match import gold_flow_id

HAND_SCENARIO = "kidstube"
DERIVED_SCENARIO = "kidstube_derived"


def _load(scenario: str, name: str) -> dict:
    return json.loads((config.KB_DIR / "scenarios" / scenario / name).read_text())


def identity_maps(hand_dfd: dict) -> tuple[dict[str, str], dict[str, str]]:
    """M0 only: the derived DFD is a byte-identical copy, so every id maps to itself.

    This exists to gate the plumbing -- can the eval harness run at all on a scenario not named
    "kidstube"? -- before there is any real adapter output to translate. If the identity case
    doesn't reproduce the published numbers exactly, nothing measured later can be trusted.
    """
    return ({e["id"]: e["id"] for e in hand_dfd["elements"]},
            {f["id"]: f["id"] for f in hand_dfd["flows"]})


def alignment_maps(derived_dfd: dict, hand_dfd: dict) -> tuple[dict[str, str], dict[str, str]]:
    """Translate anchors through the adapter's alignment map.

    Where a hand element or flow aligns to several derived ones (the adapter models at a finer
    grain -- e.g. hand DS4 "File System (backend/uploads/)" covers both backend/uploads and
    backend/uploads/images), the first is chosen so the mapping stays a function. The alignment
    itself is deterministic, so the choice is reproducible.
    """
    from adapters.align import align_elements, align_flows, derived_element_keys, load_hand_keys

    facts_path = config.ROOT / "adapters" / "data" / "kidstube_code_facts.json"
    if not facts_path.exists():
        raise SystemExit(f"no code facts at {facts_path} -- run `python cli.py extract "
                         f"--source-root PATH` first, or use --identity for the M0 gate.")
    raw = json.loads(facts_path.read_text())
    facts = raw["facts"] if isinstance(raw, dict) else raw

    hand_keys = load_hand_keys(HAND_SCENARIO)
    ea = align_elements(derived_element_keys(derived_dfd, facts), hand_keys)
    fa = align_flows(derived_dfd, hand_dfd, ea)
    element_map = {h: d[0] for h, d in ea.hand_to_derived.items() if d}
    flow_map = {h: d[0] for h, d in fa.hand_to_derived.items() if d}
    return element_map, flow_map


def reanchor(threat: dict, element_map: dict[str, str], flow_map: dict[str, str],
             derived_flows_by_id: dict[str, dict]) -> dict:
    """Translate one gold threat's anchors. Everything else is copied verbatim."""
    t = dict(threat)
    hand_flow = gold_flow_id(threat)
    new_flow = flow_map.get(hand_flow) if hand_flow else None

    if new_flow is None:
        # No derived counterpart. Drop the [DFn] tag so resolve_gold_flow() returns None and the
        # threat lands in unresolved_location rather than being scored against a flow that means
        # something else. Two distinct causes, and the note must not conflate them: the flow's
        # endpoints are planned-and-unimplemented (the ceiling -- DF13/DF14), or the adapter
        # genuinely failed to derive an implemented flow (a real recall failure that M4's threat
        # numbers must not silently absorb).
        t["interaction"] = f"{threat['interaction'].split(' [')[0]} (no derived counterpart)"
        t["derived_anchor_note"] = (
            f"hand flow {hand_flow} has no counterpart in the derived DFD. Deliberately "
            f"unanchored -> unresolved_location. See this file's _meta.unanchored_reason for "
            f"which flows are the structural ceiling and which are adapter misses.")
    else:
        f = derived_flows_by_id[new_flow]
        # Endpoint prefix follows the derived dfd.json, which is the machine-readable source of
        # truth. Note the hand gold's own prefix disagrees with the hand dfd.json for DF12 (gold
        # says "P3-EE2", dfd.json and system_description.md both say P2->EE2). Harmless today --
        # eval/match.py reads only the [DFn] via FLOW_ID_RE and ignores the prefix -- but this
        # script has to emit something, so it emits what the DFD says rather than propagating the
        # discrepancy.
        t["interaction"] = f"{f['source']}-{f['destination']} [{new_flow}]"

    originator = threat["originator_id"]
    if originator in element_map:
        t["originator_id"] = element_map[originator]
    elif originator in flow_map:
        # 3 of the 41 (ids 3, 8, 22) cite a FLOW id as their originator, not an element id --
        # they must go through the flow map, not the element map.
        t["originator_id"] = flow_map[originator]
    else:
        t["derived_anchor_note"] = (
            t.get("derived_anchor_note", "")
            + f" originator_id {originator!r} has no derived counterpart; left as-authored.").strip()
    return t


def build(identity: bool) -> dict:
    hand_gold = _load(HAND_SCENARIO, "gold_standard_threats.json")
    hand_dfd = _load(HAND_SCENARIO, "dfd.json")
    derived_dfd = json.loads((scenario_dir(DERIVED_SCENARIO) / "dfd.json").read_text())

    element_map, flow_map = (identity_maps(hand_dfd) if identity
                             else alignment_maps(derived_dfd, hand_dfd))
    derived_flows_by_id = {f["id"]: f for f in derived_dfd["flows"]}

    threats = [reanchor(t, element_map, flow_map, derived_flows_by_id)
               for t in hand_gold["threats"]]
    unanchored = [t["id"] for t in threats if not gold_flow_id(t)]

    ceiling_flows = {"DF13", "DF14"}  # endpoints P4/EE3, marked "(planned)" in the description
    missing = sorted({gold_flow_id(t) for t in hand_gold["threats"]} - set(flow_map) - {None},
                     key=lambda f: int(f[2:]))
    ceiling_missing = [f for f in missing if f in ceiling_flows]
    adapter_missing = [f for f in missing if f not in ceiling_flows]

    return {
        "_meta": {
            **hand_gold["_meta"],
            "scenario": "KidsTube (derived DFD)",
            "derived_from": {
                "gold": f"knowledge_base/scenarios/{HAND_SCENARIO}/gold_standard_threats.json",
                "dfd": f"knowledge_base/scenarios/{DERIVED_SCENARIO}/dfd.json",
                "built_by": "scripts/build_kidstube_derived_gold.py",
                "mapping": "identity (M0 plumbing gate)" if identity else "adapter alignment map",
            },
            "role": "gold standard for the DERIVED DFD. Threat content is copied verbatim from "
                    "the hand-authored catalog; only the DFD anchors are translated.",
            "unanchored_threat_ids": unanchored,
            "unanchored_hand_flows_ceiling": ceiling_missing,
            "unanchored_hand_flows_adapter_miss": adapter_missing,
            "unanchored_reason": (
                f"{len(unanchored)} threats sit on hand flows the derived DFD has no counterpart "
                f"for, and are emitted without a [DFn] tag so they classify as "
                f"unresolved_location rather than being scored against a derived flow that means "
                f"something else. TWO DISTINCT CAUSES, not to be conflated: "
                f"ceiling {ceiling_missing} -- endpoints P4/EE3 are marked '(planned)' in "
                f"system_description.md and exist in no code, so no source-code adapter can ever "
                f"produce them; adapter misses {adapter_missing} -- flows the code DOES implement "
                f"that this adapter arm failed to derive. The second group is a real limitation "
                f"and must be reported as one, not hidden inside unresolved_location."
                if unanchored else "none -- every gold threat anchors to a derived flow."),
            "interaction_prefix_note": (
                "The `interaction` endpoint prefix is regenerated from the derived dfd.json. The "
                "hand gold's prefix for DF12 reads 'P3-EE2' while both kidstube/dfd.json and "
                "system_description.md say P2->EE2; this file follows the DFD. eval/match.py "
                "reads only the bracketed flow id, so no score depends on the prefix either way."),
        },
        "threats": threats,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--identity", action="store_true",
                    help="M0: derived DFD is a byte-identical copy, so ids pass through unchanged.")
    args = ap.parse_args()

    gold = build(identity=args.identity)
    path = emit_scenario_gold(DERIVED_SCENARIO, gold)
    n = len(gold["threats"])
    unanchored = gold["_meta"]["unanchored_threat_ids"]
    print(f"Wrote {n} re-anchored gold threats -> {path}")
    print(f"  anchored to a derived flow : {n - len(unanchored)}")
    print(f"  deliberately unanchored    : {len(unanchored)} {unanchored}")
