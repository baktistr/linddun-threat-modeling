"""Offline tests for the generation/eval pipeline: schema, citation verifier, matcher, metrics.

No ANTHROPIC_API_KEY or network access required -- every check here is a data-lookup or a
hand-crafted fixture, matching tests/test_kb.py's plain-assert convention.

Run: PYTHONPATH=. python3 tests/test_generation.py
"""
from __future__ import annotations
import json
import sys

import config
from generation.schema import GeneratedThreat
from generation.verify import verify_threat
from generation.llm_backend import get_llm_backend
from eval.match import match_threats
from eval.metrics import per_category_scores, per_node_scores
from eval.reachability import reachability_breakdown

PASS, FAIL = 0, 0


def check(cond: bool, msg: str):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {msg}")
    else:
        FAIL += 1
        print(f"  FAIL {msg}")


def test_dfd_files():
    print("\n[scenario dfd.json files]")
    for scenario, n_flows in [("kidstube", 17), ("genomic", 39)]:
        dfd = json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())
        check(len(dfd["flows"]) == n_flows, f"{scenario}: {n_flows} flows (got {len(dfd['flows'])})")
        elem_ids = {e["id"] for e in dfd["elements"]}
        check(all(f["source"] in elem_ids and f["destination"] in elem_ids for f in dfd["flows"]),
              f"{scenario}: every flow's source/destination resolves to a declared element")
        flow_ids = [f["id"] for f in dfd["flows"]]
        check(len(flow_ids) == len(set(flow_ids)), f"{scenario}: flow ids unique")


def test_genomic_gold_has_dfd_locations():
    print("\n[genomic gold: dfd_source_id/dfd_destination_id]")
    gold = json.loads((config.KB_DIR / "scenarios/genomic/gold_standard_threats.json").read_text())
    threats = gold["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    elem_ids = {e["id"] for e in dfd["elements"]}
    n_resolved = sum(1 for t in threats if t.get("dfd_location_confidence") != "unresolved")
    check(n_resolved == 97, f"97/99 genomic threats have a resolved DFD location (got {n_resolved})")
    for t in threats:
        if t.get("dfd_location_confidence") == "unresolved":
            check(t["dfd_source_id"] is None and t["dfd_destination_id"] is None,
                  f"threat {t['id']}: unresolved location has no source/destination asserted")
        else:
            check(t["dfd_source_id"] in elem_ids and t["dfd_destination_id"] in elem_ids,
                  f"threat {t['id']}: dfd_source_id/dfd_destination_id resolve to real elements")


def test_schema_roundtrip():
    print("\n[GeneratedThreat schema]")
    t = GeneratedThreat(flow_id="DF1", originator_id="P1", threat_type="Dd", tree_node="Dd.1.1",
                         title="Excessive collection", description="desc")
    d = t.to_dict()
    t2 = GeneratedThreat.from_dict(d)
    check(t == t2, "to_dict/from_dict round-trips to an equal object")
    t3 = GeneratedThreat.from_dict({**d, "unexpected_field": "ignored"})
    check(t3 == t, "from_dict ignores unknown keys instead of raising")


def test_verifier_valid_citation():
    print("\n[citation verifier: valid citations]")
    dfd = json.loads((config.KB_DIR / "scenarios/kidstube/dfd.json").read_text())
    # Dd.1.1 is a real node (used by KidsTube gold threat #2); EE1->P1 is DF1.
    t = GeneratedThreat(flow_id="DF1", originator_id="P1", threat_type="Dd", tree_node="Dd.1.1",
                         title="Excessive collection", description="desc")
    v = verify_threat(t, dfd)
    check(v.node_valid, "real tree_node verifies as valid")
    check(v.type_applicable, "Dd is applicable at ExternalEntity->Process")
    check(v.location_valid, "originator_id matching a flow endpoint verifies as valid")
    check(v.all_valid, "all_valid is true when every check passes")


def test_verifier_fabricated_citations():
    print("\n[citation verifier: fabricated / wrong citations]")
    dfd = json.loads((config.KB_DIR / "scenarios/kidstube/dfd.json").read_text())

    bad_node = GeneratedThreat(flow_id="DF1", originator_id="P1", threat_type="Dd",
                                tree_node="Zz.9.9", title="t", description="d")
    check(not verify_threat(bad_node, dfd).node_valid, "fabricated tree_node fails verification")

    bad_location = GeneratedThreat(flow_id="DF1", originator_id="XX99", threat_type="Dd",
                                    tree_node="Dd.1.1", title="t", description="d")
    check(not verify_threat(bad_location, dfd).location_valid,
          "originator_id not on the flow/elements fails verification")

    missing_flow = GeneratedThreat(flow_id="DF999", originator_id="P1", threat_type="Dd",
                                    tree_node="Dd.1.1", title="t", description="d")
    check(not verify_threat(missing_flow, dfd).type_applicable,
          "a flow_id absent from dfd.json fails the type-applicability check")


def _fixture_gold():
    return [
        {"id": 1, "interaction": "EE1-P1 [DF1]", "threat_type": "Dd", "tree_node": "Dd.1.1"},
        {"id": 2, "interaction": "EE1-P1 [DF1]", "threat_type": "L", "tree_node": "L.1.1"},
        {"id": 3, "interaction": "P1-DS1 [DF2]", "threat_type": "Dd", "tree_node": "Dd.3.4"},
    ]


def _fixture_generated():
    return [
        GeneratedThreat(flow_id="DF1", originator_id="P1", threat_type="Dd", tree_node="Dd.1.1",
                         title="t1", description="d1"),  # matches gold #1
        GeneratedThreat(flow_id="DF1", originator_id="EE1", threat_type="U", tree_node="U.1.1",
                         title="t2", description="d2"),  # no matching gold -> FP
        GeneratedThreat(flow_id="DF2", originator_id="DS1", threat_type="Dd", tree_node="Dd.9.9",
                         title="t3", description="d3"),  # same flow+type as gold #3, different node
    ]


def test_matcher_coarse_tier():
    print("\n[matcher: coarse tier (flow + type)]")
    gold, generated = _fixture_gold(), _fixture_generated()
    m = match_threats(generated, gold, scenario="kidstube", strict=False)
    check(m.tp == 2, f"tp==2 (got {m.tp})")
    check(m.fp == 1, f"fp==1 (got {m.fp})")
    check(m.fn == 1, f"fn==1 (gold #2 'L' never generated; got {m.fn})")
    check(m.matched_gold_ids == {1, 3}, f"matched gold ids {{1, 3}} (got {m.matched_gold_ids})")

    scores = per_category_scores(generated, gold, m.gen_to_gold, m.matched_gold_ids)
    check(scores["Dd"].tp == 2 and scores["Dd"].fp == 0 and scores["Dd"].fn == 0,
          "Dd category: tp=2 fp=0 fn=0")
    check(scores["Dd"].precision == 1.0 and scores["Dd"].recall == 1.0 and scores["Dd"].f1 == 1.0,
          "Dd category: precision=recall=f1=1.0")
    check(scores["L"].tp == 0 and scores["L"].fn == 1, "L category: tp=0 fn=1 (missed)")
    check(scores["U"].tp == 0 and scores["U"].fp == 1, "U category: tp=0 fp=1 (spurious)")


def test_matcher_strict_tier():
    print("\n[matcher: strict tier (+ exact tree_node)]")
    gold, generated = _fixture_gold(), _fixture_generated()
    m = match_threats(generated, gold, scenario="kidstube", strict=True)
    check(m.tp == 1, f"tp==1 -- gold #3/gen #3 node mismatch no longer counts (got {m.tp})")
    check(m.fp == 2, f"fp==2 (got {m.fp})")
    check(m.fn == 2, f"fn==2 (got {m.fn})")


def test_llm_backend_routing():
    print("\n[LLM backend routing (no network calls)]")
    try:
        get_llm_backend("not-a-real-provider")
        check(False, "unknown provider raises ValueError")
    except ValueError:
        check(True, "unknown provider raises ValueError")

    saved_key = config.ANTHROPIC_API_KEY
    config.ANTHROPIC_API_KEY = ""
    try:
        get_llm_backend("anthropic")
        check(False, "missing ANTHROPIC_API_KEY raises RuntimeError")
    except RuntimeError:
        check(True, "missing ANTHROPIC_API_KEY raises RuntimeError")
    finally:
        config.ANTHROPIC_API_KEY = saved_key

    saved_key = config.OPENAI_API_KEY
    config.OPENAI_API_KEY = ""
    try:
        get_llm_backend("openai")
        check(False, "missing OPENAI_API_KEY raises RuntimeError")
    except RuntimeError:
        check(True, "missing OPENAI_API_KEY raises RuntimeError")
    finally:
        config.OPENAI_API_KEY = saved_key

    saved_key, saved_endpoint = config.AZURE_AI_API_KEY, config.AZURE_AI_ENDPOINT
    config.AZURE_AI_API_KEY = ""
    try:
        get_llm_backend("azure")
        check(False, "missing AZURE_AI_API_KEY raises RuntimeError")
    except RuntimeError:
        check(True, "missing AZURE_AI_API_KEY raises RuntimeError")
    finally:
        config.AZURE_AI_API_KEY = saved_key

    config.AZURE_AI_ENDPOINT = ""
    try:
        get_llm_backend("azure")
        check(False, "missing AZURE_AI_ENDPOINT raises RuntimeError")
    except RuntimeError:
        check(True, "missing AZURE_AI_ENDPOINT raises RuntimeError")
    finally:
        config.AZURE_AI_ENDPOINT = saved_endpoint


def test_matcher_genomic_location_based():
    print("\n[matcher: genomic uses dfd_source_id/dfd_destination_id, not flow_id string]")
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    flow = next(f for f in dfd["flows"] if f["source"] == "S3-PH" and f["destination"] == "S11-PH")

    gold = [
        {"id": 1, "threat_type": "L", "tree_node": "L.2.1.2",
         "dfd_source_id": "S3-PH", "dfd_destination_id": "S11-PH", "dfd_location_confidence": "high"},
        {"id": 2, "threat_type": "I", "tree_node": "I.1.1",
         "dfd_source_id": None, "dfd_destination_id": None, "dfd_location_confidence": "unresolved"},
    ]
    generated = [
        # same (source, destination) as gold #1, but a *different* flow_id string -- must still
        # match, since genomic matching is location-based, not flow_id-string-based like KidsTube.
        GeneratedThreat(flow_id=flow["id"], originator_id="S3-PH", threat_type="L",
                         tree_node="L.2.1.2", title="t1", description="d1"),
        # correct threat_type but no gold threat has a resolved location matching this flow
        GeneratedThreat(flow_id="GF4", originator_id="S6-A", threat_type="I",
                         tree_node="I.1.1", title="t2", description="d2"),
    ]
    m = match_threats(generated, gold, scenario="genomic", dfd=dfd, strict=False)
    check(m.tp == 1, f"tp==1: matched via (source,destination), not flow_id string (got {m.tp})")
    check(1 in m.gen_to_gold.values(), "gold #1 (resolved location) was matched")
    check(2 not in m.matched_gold_ids, "gold #2 (unresolved location) can never be matched")
    check(m.fp == 1, f"fp==1: generated #2 has no matching resolved gold threat (got {m.fp})")


def test_per_node_scores():
    print("\n[per-node breakdown]")
    gold, generated = _fixture_gold(), _fixture_generated()
    m = match_threats(generated, gold, scenario="kidstube", strict=False)
    scores = per_node_scores(generated, gold, m.gen_to_gold, m.matched_gold_ids)
    check(scores["Dd.1.1"].tp == 1, "node Dd.1.1: tp=1 (gold #1 matched by gen #1)")
    check(scores["L.1.1"].fn == 1, "node L.1.1: fn=1 (gold #2 never generated)")
    check(scores["U.1.1"].fp == 1, "node U.1.1: fp=1 (gen #2 has no gold counterpart)")
    check(scores["Dd.9.9"].tp == 1,
          "node Dd.9.9: tp=1 -- gen #3 matched gold #3 at the coarse (flow+type) tier despite a different node")
    check("Dd.3.4" not in scores,
          "gold #3's own node (Dd.3.4) doesn't appear in the coarse-tier breakdown at all -- "
          "the node mismatch is invisible unless --strict is also used")


def test_reachability_genomic_reproduces_published_split():
    print("\n[reachability: genomic reproduces the WEEK3/4 hand-counted 70/27/2 split]")
    gold = json.loads((config.KB_DIR / "scenarios/genomic/gold_standard_threats.json").read_text())["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    # matched_gold_ids=set() -- as if nothing were generated yet, isolating the pure structural
    # ceiling (independent of any live LLM run) from actual recall failures.
    rc = reachability_breakdown(gold, "genomic", dfd, matched_gold_ids=set())
    check(rc.reachable_but_missed == 70, f"70 structurally reachable (got {rc.reachable_but_missed})")
    check(rc.structurally_unreachable == 27, f"27 structurally unreachable (got {rc.structurally_unreachable})")
    check(rc.unresolved_location == 2, f"2 unresolved-location (got {rc.unresolved_location})")


def test_reachability_kidstube_multiflow_threats_are_unresolved():
    print("\n[reachability: kidstube multi-flow gold threats can't anchor to one flow]")
    gold = json.loads((config.KB_DIR / "scenarios/kidstube/gold_standard_threats.json").read_text())["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios/kidstube/dfd.json").read_text())
    rc = reachability_breakdown(gold, "kidstube", dfd, matched_gold_ids=set())
    check(rc.structurally_unreachable == 0, "kidstube has no mapping-table gap (all flows Process-mediated)")
    check(rc.unresolved_location == 4,
          f"4 gold threats span multiple flows (e.g. '[DF7/DF10]') and can't anchor to one (got {rc.unresolved_location})")
    check(rc.reachable_but_missed == 32, f"32 remaining threats are on a single, valid flow (got {rc.reachable_but_missed})")


def test_reachability_recall_property():
    print("\n[reachability: reachable_recall excludes structural misses from the denominator]")
    from eval.reachability import ReachabilityCounts
    rc = ReachabilityCounts(matched=7, reachable_but_missed=3, structurally_unreachable=5, unresolved_location=2)
    check(rc.reachable_recall == 0.7, f"7/(7+3)=0.7 (got {rc.reachable_recall})")


def test_matcher_genomic_without_dfd_falls_back_to_coarse():
    print("\n[matcher: genomic without a dfd arg falls back to type-only matching]")
    gold = [{"id": 1, "threat_type": "L", "tree_node": "L.2.1.2",
             "dfd_source_id": "S3-PH", "dfd_destination_id": "S11-PH"}]
    generated = [GeneratedThreat(flow_id="GF999", originator_id="S6-A", threat_type="L",
                                  tree_node="L.2.1.2", title="t", description="d")]
    m = match_threats(generated, gold, scenario="genomic", dfd=None, strict=False)
    check(m.tp == 1, "without a dfd, genomic matching degrades to threat_type-only (coarser, not stricter)")


def main():
    test_dfd_files()
    test_genomic_gold_has_dfd_locations()
    test_schema_roundtrip()
    test_verifier_valid_citation()
    test_verifier_fabricated_citations()
    test_matcher_coarse_tier()
    test_matcher_strict_tier()
    test_per_node_scores()
    test_reachability_genomic_reproduces_published_split()
    test_reachability_kidstube_multiflow_threats_are_unresolved()
    test_reachability_recall_property()
    test_llm_backend_routing()
    test_matcher_genomic_location_based()
    test_matcher_genomic_without_dfd_falls_back_to_coarse()
    print(f"\n{'='*50}\nPASSED {PASS}  FAILED {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
