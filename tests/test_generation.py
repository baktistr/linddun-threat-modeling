"""Offline tests for the generation/eval pipeline: schema, citation verifier, matcher, metrics.

No ANTHROPIC_API_KEY or network access required -- every check here is a data-lookup or a
hand-crafted fixture, matching tests/test_kb.py's plain-assert convention.

Run: PYTHONPATH=. python3 tests/test_generation.py
"""
from __future__ import annotations
import os
import json
import sys

import config
from generation.schema import GeneratedThreat
from generation.verify import verify_threat
from generation.llm_backend import get_llm_backend
from generation.generate import resolve_mode
from generation.prompt import (build_flow_query, build_rag_prompt, build_panoptic_prompt,
                               build_panoptic_rag_prompt, build_panoptic_ungrounded_prompt)
from retrieval.index import Retriever, Hit
from ingestion.loader import Chunk
from eval.match import match_threats, match_threats_panoptic
from eval.metrics import per_category_scores, per_node_scores, per_panoptic_category_scores
from eval.reachability import reachability_breakdown, reachability_breakdown_panoptic
from eval.adjudicate import fp_indices, build_worklist, worklist_path, human_corrected_precision

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
    check(n_resolved == 99, f"99/99 genomic threats have a resolved DFD location (got {n_resolved})")
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


def _fixture_dfd():
    return {
        "elements": [
            {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
            {"id": "P1", "name": "Auth Service", "type": "Process"},
            {"id": "DS1", "name": "User Store", "type": "DataStore"},
        ],
        "flows": [
            {"id": "DF1", "source": "EE1", "destination": "P1", "description": "registration"},
            {"id": "DF2", "source": "P1", "destination": "DS1", "description": "store account"},
        ],
    }


def test_adjudicate_worklist_and_precision():
    print("\n[adjudicate: worklist build/resume + human-corrected precision]")
    gold, generated = _fixture_gold(), _fixture_generated()
    dfd = _fixture_dfd()
    m = match_threats(generated, gold, scenario="kidstube", dfd=dfd, strict=False)
    check(fp_indices(generated, m) == [1], f"fp_indices == [1] (got {fp_indices(generated, m)})")

    scenario, mode = "_test_fixture", "_test_mode"
    path = worklist_path(scenario, mode)
    if path.exists():
        path.unlink()
    try:
        wp = build_worklist(scenario, mode, generated, m, dfd, n=None)
        check(wp == path, "build_worklist returns the expected path")
        records = json.loads(path.read_text())
        check(len(records) == 1, f"worklist has 1 record (the single FP) (got {len(records)})")
        check(records[0]["gen_index"] == 1, "worklist record is generated index 1")
        check(records[0]["label"] is None, "new record starts unlabeled")
        check(records[0]["source"] == "Parent User" and records[0]["destination"] == "Auth Service",
              "worklist record resolves source/destination names from dfd.json")

        check(human_corrected_precision(m.tp, m.fp, path) is None,
              "human_corrected_precision is None before any label is given")

        records[0]["label"] = "valid_uncatalogued"
        path.write_text(json.dumps(records, indent=2))
        hcp = human_corrected_precision(m.tp, m.fp, path)
        check(hcp is not None, "human_corrected_precision available once labeled")
        check(hcp.is_full_review, "1 labeled / 1 fp_total -> full review")
        check(hcp.precision_raw == m.tp / (m.tp + m.fp), "precision_raw matches raw tp/(tp+fp)")
        check(hcp.precision_corrected == 1.0,
              f"precision_corrected == 1.0 (sole FP relabeled valid -> no FPs left) (got {hcp.precision_corrected})")

        build_worklist(scenario, mode, generated, m, dfd, n=None)
        records2 = json.loads(path.read_text())
        check(records2[0]["label"] == "valid_uncatalogued",
              "re-running build_worklist preserves an existing label (resumable, not clobbered)")
    finally:
        if path.exists():
            path.unlink()


def test_adjudicate_precision_extrapolation_from_sample():
    print("\n[adjudicate: precision extrapolated from a partial sample]")
    scenario, mode = "_test_fixture2", "_test_mode"
    path = worklist_path(scenario, mode)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # 10 FPs total, only 4 sampled/labeled: 2 spurious, 1 valid_uncatalogued, 1 borderline.
        records = [{"gen_index": i, "label": None} for i in range(10)]
        records[0]["label"] = "spurious"
        records[1]["label"] = "spurious"
        records[2]["label"] = "valid_uncatalogued"
        records[3]["label"] = "borderline"
        path.write_text(json.dumps(records, indent=2))

        tp = 5
        hcp = human_corrected_precision(tp, fp_total=10, path=path)
        check(hcp.n_labeled == 4, f"n_labeled == 4 (got {hcp.n_labeled})")
        check(not hcp.is_full_review, "4 labeled / 10 fp_total -> not a full review, extrapolated")
        check(hcp.precision_raw == 5 / 15, f"precision_raw == 5/15 (got {hcp.precision_raw})")
        # scale=10/4=2.5; spurious_est=2*2.5+1*2.5*0.5=6.25; valid_est=1*2.5+1*2.5*0.5=3.75
        # tp_corrected=5+3.75=8.75; precision_corrected=8.75/(8.75+6.25)=8.75/15
        expected = 8.75 / 15
        check(abs(hcp.precision_corrected - expected) < 1e-9,
              f"precision_corrected matches hand-computed extrapolation "
              f"(got {hcp.precision_corrected}, expected {expected})")
    finally:
        if path.exists():
            path.unlink()


def test_schema_mode_field():
    print("\n[GeneratedThreat.mode field]")
    t_grounded = GeneratedThreat(flow_id="DF1", originator_id="P1", threat_type="Dd", tree_node="Dd.1.1",
                                  title="t", description="d")
    check(t_grounded.mode == "grounded" and t_grounded.grounded is True,
          "default construction: mode='grounded', grounded=True")

    t_rag = GeneratedThreat(flow_id="DF1", originator_id="P1", threat_type="Dd", tree_node="Dd.1.1",
                             title="t", description="d", mode="rag")
    check(t_rag.mode == "rag" and t_rag.grounded is True,
          "explicit mode='rag' is preserved, grounded still True (rag has KB context)")

    t_ungrounded = GeneratedThreat(flow_id="DF1", originator_id="P1", threat_type="Dd", tree_node="Dd.1.1",
                                    title="t", description="d", grounded=False)
    check(t_ungrounded.mode == "ungrounded",
          "grounded=False with no explicit mode infers mode='ungrounded'")

    # Simulates loading a pre-RAG-ablation storage/generated/*.json file: has "grounded" but no "mode" key.
    legacy_ungrounded = GeneratedThreat.from_dict({
        "flow_id": "DF1", "originator_id": "P1", "threat_type": "Dd", "tree_node": "Dd.1.1",
        "title": "t", "description": "d", "grounded": False,
    })
    check(legacy_ungrounded.mode == "ungrounded",
          "legacy dict (grounded=False, no mode key) backfills mode='ungrounded'")
    legacy_grounded = GeneratedThreat.from_dict({
        "flow_id": "DF1", "originator_id": "P1", "threat_type": "Dd", "tree_node": "Dd.1.1",
        "title": "t", "description": "d", "grounded": True,
    })
    check(legacy_grounded.mode == "grounded",
          "legacy dict (grounded=True, no mode key) backfills mode='grounded'")

    for t in (t_grounded, t_rag, t_ungrounded):
        d = t.to_dict()
        t2 = GeneratedThreat.from_dict(d)
        check(t == t2, f"to_dict/from_dict round-trips mode={t.mode!r} to an equal object")


def test_resolve_mode():
    print("\n[resolve_mode: CLI flag -> mode name]")
    check(resolve_mode(rag=False, ungrounded=False) == "grounded", "no flags -> grounded (default)")
    check(resolve_mode(rag=True, ungrounded=False) == "rag", "--rag -> rag")
    check(resolve_mode(rag=False, ungrounded=True) == "ungrounded", "--ungrounded -> ungrounded")
    try:
        resolve_mode(rag=True, ungrounded=True)
        check(False, "--rag and --ungrounded together raises ValueError")
    except ValueError:
        check(True, "--rag and --ungrounded together raises ValueError")


def test_build_flow_query():
    print("\n[build_flow_query]")
    elements_by_id = {
        "EE1": {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
        "P1": {"id": "P1", "name": "Authentication Service", "type": "Process"},
    }
    flow = {"id": "DF1", "source": "EE1", "destination": "P1",
            "description": "parent registration (email, password, name, govt ID)"}
    q = build_flow_query(flow, elements_by_id)
    check("Parent User" in q and "Authentication Service" in q, "query includes both element names")
    check("ExternalEntity" in q and "Process" in q, "query includes both element types")
    check("parent registration" in q, "query includes the flow description")


def test_build_rag_prompt():
    print("\n[build_rag_prompt]")
    elements_by_id = {
        "EE1": {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
        "P1": {"id": "P1", "name": "Authentication Service", "type": "Process"},
    }
    flow = {"id": "DF1", "source": "EE1", "destination": "P1",
            "description": "parent registration (email, password, name, govt ID)"}
    chunk = Chunk(id="linddun:threat_trees.json:3", text="Threat tree node Dd.1.1 -- Excessive collection...",
                  source="linddun", doc="threat_trees.json", section="Dd.1.1 Excessive collection",
                  meta={"kind": "tree_node", "tree_node": "Dd.1.1"})
    hits = [Hit(chunk=chunk, score=0.42)]

    prompt = build_rag_prompt(flow, elements_by_id, hits)
    check("Dd.1.1" in prompt and "Excessive collection" in prompt, "retrieved chunk content is inlined")
    check("linddun/threat_trees.json" in prompt, "retrieved chunk's source/doc is cited")
    check("guidance" in prompt.lower(), "prompt frames retrieved context as guidance, not a hard constraint")
    check("emit_threats" in prompt, "prompt still directs the model to the shared tool schema")

    empty_prompt = build_rag_prompt(flow, elements_by_id, [])
    check("no relevant knowledge-base passages retrieved" in empty_prompt,
          "empty retrieval degrades gracefully instead of an empty/broken context block")


def test_rag_retrieval_no_gold_leakage():
    print("\n[RAG retrieval: no gold-standard leakage into generation-time context]")
    r = Retriever.load()
    elements_by_id = {
        "EE1": {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
        "P1": {"id": "P1", "name": "Authentication Service", "type": "Process"},
    }
    flow = {"id": "DF1", "source": "EE1", "destination": "P1",
            "description": "parent registration (email, password, name, govt ID, six-digit code)"}
    query = build_flow_query(flow, elements_by_id)
    hits = r.search(query, k=config.TOP_K, source="linddun", exclude_kinds=["gold_threat"])
    check(len(hits) > 0, "a real flow query returns at least one hit from the linddun corpus")
    check(all(h.chunk.source == "linddun" for h in hits),
          "source='linddun' filter excludes every scenarios-corpus chunk (gold standards live there)")
    check(all(h.chunk.meta.get("kind") != "gold_threat" for h in hits),
          "no retrieved chunk is a gold_threat chunk (defense in depth alongside the source filter)")


def test_resolve_mode_panoptic():
    print("\n[resolve_mode: --framework x --rag/--ungrounded composition]")
    check(resolve_mode(rag=False, ungrounded=False, framework="panoptic") == "panoptic_grounded",
          "framework=panoptic, no flags -> panoptic_grounded")
    check(resolve_mode(rag=True, ungrounded=False, framework="panoptic") == "panoptic_rag",
          "framework=panoptic, --rag -> panoptic_rag")
    check(resolve_mode(rag=False, ungrounded=True, framework="panoptic") == "panoptic_ungrounded",
          "framework=panoptic, --ungrounded -> panoptic_ungrounded")
    check(resolve_mode(rag=False, ungrounded=False, framework="linddun") == "grounded",
          "framework=linddun (default), no flags -> grounded (unchanged, bare name)")
    check(resolve_mode(rag=True, ungrounded=False, framework="linddun") == "rag",
          "framework=linddun, --rag -> rag (unchanged, bare name)")
    try:
        resolve_mode(rag=True, ungrounded=True, framework="panoptic")
        check(False, "--rag and --ungrounded together raises ValueError regardless of framework")
    except ValueError:
        check(True, "--rag and --ungrounded together raises ValueError regardless of framework")
    try:
        resolve_mode(rag=False, ungrounded=False, framework="not-a-framework")
        check(False, "unknown framework raises ValueError")
    except ValueError:
        check(True, "unknown framework raises ValueError")


def test_build_panoptic_prompt():
    print("\n[build_panoptic_prompt (panoptic_grounded)]")
    taxonomy = json.loads((config.KB_DIR / "panoptic/taxonomy.json").read_text())
    elements_by_id = {
        "EE1": {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
        "P1": {"id": "P1", "name": "Authentication Service", "type": "Process"},
    }
    flow = {"id": "DF1", "source": "EE1", "destination": "P1",
            "description": "parent registration (email, password, name, govt ID)"}
    prompt = build_panoptic_prompt(flow, elements_by_id, taxonomy)
    check("PANOPTIC" in prompt, "prompt references PANOPTIC")
    check("PA03.09" in prompt, "a real sub-activity id appears in the menu")
    check("panoptic_action" in prompt, "prompt asks for a panoptic_action citation")
    check("emit_threats" in prompt, "prompt still directs the model to the shared tool schema")


def test_build_panoptic_rag_prompt():
    print("\n[build_panoptic_rag_prompt]")
    elements_by_id = {
        "EE1": {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
        "P1": {"id": "P1", "name": "Authentication Service", "type": "Process"},
    }
    flow = {"id": "DF1", "source": "EE1", "destination": "P1",
            "description": "parent registration (email, password, name, govt ID)"}
    chunk = Chunk(id="panoptic:taxonomy.json:5", text="PANOPTIC sub-activity PA03.09 -- Recording: ...",
                  source="panoptic", doc="taxonomy.json", section="PA03.09 Recording",
                  meta={"kind": "panoptic_sub_activity", "panoptic_id": "PA03.09"})
    hits = [Hit(chunk=chunk, score=0.51)]

    prompt = build_panoptic_rag_prompt(flow, elements_by_id, hits)
    check("PA03.09" in prompt and "Recording" in prompt, "retrieved chunk content is inlined")
    check("panoptic/taxonomy.json" in prompt, "retrieved chunk's source/doc is cited")
    check("guidance" in prompt.lower(), "prompt frames retrieved context as guidance, not a hard constraint")
    check("emit_threats" in prompt, "prompt still directs the model to the shared tool schema")

    empty_prompt = build_panoptic_rag_prompt(flow, elements_by_id, [])
    check("no relevant knowledge-base passages retrieved" in empty_prompt,
          "empty retrieval degrades gracefully instead of an empty/broken context block")


def test_build_panoptic_ungrounded_prompt():
    print("\n[build_panoptic_ungrounded_prompt]")
    elements_by_id = {
        "EE1": {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
        "P1": {"id": "P1", "name": "Authentication Service", "type": "Process"},
    }
    flow = {"id": "DF1", "source": "EE1", "destination": "P1",
            "description": "parent registration (email, password, name, govt ID)"}
    prompt = build_panoptic_ungrounded_prompt(flow, elements_by_id)
    check("PANOPTIC" in prompt, "prompt references PANOPTIC")
    check("no reference material is provided" in prompt, "prompt states no KB context is given")
    check("panoptic_action" in prompt, "prompt still asks for a panoptic_action citation")
    check("PA0" not in prompt, "no PANOPTIC taxonomy content (e.g. a real sub-activity id) leaks into the ungrounded prompt")


def test_panoptic_rag_retrieval_no_gold_leakage():
    print("\n[PANOPTIC RAG retrieval: source='panoptic' excludes LINDDUN/scenarios/gold content]")
    r = Retriever.load()
    elements_by_id = {
        "EE1": {"id": "EE1", "name": "Parent User", "type": "ExternalEntity"},
        "P1": {"id": "P1", "name": "Authentication Service", "type": "Process"},
    }
    flow = {"id": "DF1", "source": "EE1", "destination": "P1",
            "description": "parent registration (email, password, name, govt ID, six-digit code)"}
    query = build_flow_query(flow, elements_by_id)
    hits = r.search(query, k=config.TOP_K, source="panoptic", exclude_kinds=["gold_threat"])
    check(len(hits) > 0, "a real flow query returns at least one hit from the panoptic corpus")
    check(all(h.chunk.source == "panoptic" for h in hits),
          "source='panoptic' filter excludes every linddun/scenarios-corpus chunk")
    check(all(h.chunk.meta.get("kind") != "gold_threat" for h in hits),
          "no retrieved chunk is a gold_threat chunk (defense in depth alongside the source filter)")


def test_matcher_panoptic():
    print("\n[matcher: PANOPTIC-native, panoptic_action + flow location]")
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    flow = next(f for f in dfd["flows"] if f["source"] == "S3-PH" and f["destination"] == "S11-PH")

    gold = [
        {"id": 1, "threat_type": "L", "tree_node": "L.2.1.2", "panoptic_actions": ["PA03.09", "PA08.01.01"],
         "dfd_source_id": "S3-PH", "dfd_destination_id": "S11-PH", "dfd_location_confidence": "high"},
        {"id": 2, "threat_type": "I", "tree_node": "I.1.1", "panoptic_actions": ["PA05.02.02"],
         "dfd_source_id": None, "dfd_destination_id": None, "dfd_location_confidence": "unresolved"},
    ]
    generated = [
        # matches gold #1 via panoptic_action membership + same flow, even though tree_node differs
        GeneratedThreat(flow_id=flow["id"], originator_id="S3-PH", threat_type="Dd", tree_node="Dd.9.9",
                         title="t1", description="d1", mode="panoptic_grounded", panoptic_action="PA03.09"),
        # right panoptic_action, wrong flow -> no match
        GeneratedThreat(flow_id="GF999", originator_id="S6-A", threat_type="L", tree_node="L.2.1.2",
                         title="t2", description="d2", mode="panoptic_grounded", panoptic_action="PA08.01.01"),
        # no panoptic_action at all (e.g. from a non-panoptic mode) -> excluded, not scored as FP
        GeneratedThreat(flow_id=flow["id"], originator_id="S3-PH", threat_type="L", tree_node="L.2.1.2",
                         title="t3", description="d3", mode="grounded"),
    ]
    m = match_threats_panoptic(generated, gold, scenario="genomic", dfd=dfd)
    check(m.tp == 1, f"tp==1: gen #1 matched gold #1 via panoptic_action+flow (got {m.tp})")
    check(1 in m.gen_to_gold.values(), "gold #1 matched")
    check(2 not in m.matched_gold_ids, "gold #2 (unresolved location) can never be matched")
    check(m.fp == 1, f"fp==1: gen #2's panoptic_action is real but on the wrong flow (got {m.fp})")
    check(2 not in m.gen_to_gold, "gen #3 (no panoptic_action) is excluded entirely, not scored as FP")


def test_panoptic_category_scores():
    print("\n[per-PANOPTIC-category scores]")
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    flow = next(f for f in dfd["flows"] if f["source"] == "S3-PH" and f["destination"] == "S11-PH")
    gold = [
        {"id": 1, "threat_type": "L", "tree_node": "L.2.1.2", "panoptic_actions": ["PA03.09", "PA08.01.01"],
         "dfd_source_id": "S3-PH", "dfd_destination_id": "S11-PH", "dfd_location_confidence": "high"},
        {"id": 2, "threat_type": "L", "tree_node": "L.1.1", "panoptic_actions": ["PA10.01"],
         "dfd_source_id": "S3-PH", "dfd_destination_id": "S11-PH", "dfd_location_confidence": "high"},
    ]
    generated = [
        GeneratedThreat(flow_id=flow["id"], originator_id="S3-PH", threat_type="L", tree_node="L.2.1.2",
                         title="t1", description="d1", mode="panoptic_grounded", panoptic_action="PA03.09"),
        GeneratedThreat(flow_id=flow["id"], originator_id="S3-PH", threat_type="U", tree_node="U.1.1",
                         title="t2", description="d2", mode="panoptic_grounded", panoptic_action="PA01.01"),
    ]
    m = match_threats_panoptic(generated, gold, scenario="genomic", dfd=dfd)
    scores = per_panoptic_category_scores(generated, gold, m.gen_to_gold, m.matched_gold_ids)
    check(scores["PA03"].tp == 1, "PA03: tp=1 (gen #1 matched gold #1 via PA03.09)")
    check(scores["PA01"].fp == 1, "PA01: fp=1 (gen #2's PA01.01 has no matching gold)")
    check(scores["PA10"].fn == 1, "PA10: fn=1 (gold #2's first panoptic_action PA10.01 never generated)")


def test_reachability_panoptic_no_structural_gate():
    print("\n[reachability: panoptic mode has no structurally_unreachable concept]")
    gold = json.loads((config.KB_DIR / "scenarios/genomic/gold_standard_threats.json").read_text())["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    rc = reachability_breakdown_panoptic(gold, "genomic", dfd, matched_gold_ids=set())
    check(rc.structurally_unreachable == 0, "structurally_unreachable is always 0 for panoptic mode")
    # All 99 gold threats now carry a resolved DFD location (ids 20 and 23 best-fit anchored), so
    # under PANOPTIC (no Process-mediation gate) every one is reachable_but_missed, none unresolved.
    check(rc.reachable_but_missed == 99, f"99 reachable (got {rc.reachable_but_missed})")
    check(rc.unresolved_location == 0, f"0 unresolved-location (got {rc.unresolved_location})")


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


def test_gateway_retry_is_narrow_and_never_rerolls_an_answer():
    """A 5xx is transport; a 4xx is our bug; a bad answer is a RESULT.

    Generation is one call per flow, so a single gateway 500 discards every flow already paid for
    -- at the ~17% per-call rate measured on grok-4.3 an 8-flow run fails ~78% of the time. Hence
    the retry. But retrying must never widen past transport: re-rolling a model that answered
    badly would quietly turn "what the model said" into "what it said once we stopped asking",
    which is the one thing this project cannot let a number mean.
    """
    print("\n[gateway retry: 5xx only, no network]")
    from generation.llm_backend import AzureFoundryBackend, GATEWAY_RETRIES

    class Boom(Exception):
        def __init__(self, status):
            super().__init__(f"status {status}")
            self.status_code = status

    backend = AzureFoundryBackend.__new__(AzureFoundryBackend)   # no __init__: no client, no key

    calls = {"n": 0}

    def flaky(**kwargs):
        calls["n"] += 1
        if calls["n"] < 3:
            raise Boom(500)
        return "recovered"

    backend.client = type("C", (), {"chat": type("Ch", (), {"completions": type(
        "Co", (), {"create": staticmethod(flaky)})()})()})()
    check(backend._create_with_retry() == "recovered",
          f"a 500 is retried and the call recovers (took {calls['n']} attempts)")

    calls["n"] = 0

    def always_400(**kwargs):
        calls["n"] += 1
        raise Boom(400)

    backend.client.chat.completions.create = staticmethod(always_400)
    try:
        backend._create_with_retry()
        check(False, "a 400 must surface immediately")
    except Boom:
        check(calls["n"] == 1, f"a 400 is NOT retried -- surfaced after {calls['n']} attempt")

    calls["n"] = 0

    def always_500(**kwargs):
        calls["n"] += 1
        raise Boom(503)

    backend.client.chat.completions.create = staticmethod(always_500)
    try:
        backend._create_with_retry()
        check(False, "an unrecoverable 5xx must still raise")
    except Boom:
        check(calls["n"] == GATEWAY_RETRIES,
              f"retries are bounded at {GATEWAY_RETRIES}, then the error surfaces")


def test_temperature_is_pinned_and_degrades_honestly():
    """The sampler must be pinned, and 'we asked for temperature=0' must not be reported as
    'the deployment ran at temperature=0'.

    Nothing set temperature until 2026-08-08, so every run went out at the provider default of
    1.0 and the measured spread between repeats was sampling noise the experiment was paying for
    by default. Reasoning-class deployments reject the parameter outright (as this project's
    gpt-5.4 rejects max_tokens), so the fallback has to exist -- and when it fires, the run is NOT
    greedy and the artifact has to say so rather than inherit the claim."""
    print("\n[temperature: pinned, with an honest fallback]")
    from generation.llm_backend import LLMBackend

    check(config.GENERATION_TEMPERATURE == 0,
          f"default generation temperature is pinned at 0 (got {config.GENERATION_TEMPERATURE})")

    def probe(model_name):
        class Probe(LLMBackend):
            name = "probe"
            @property
            def model(self): return model_name
            def call_tool(self, *a, **k): return {}
        return Probe()

    seen = []
    b = probe("accepts")
    b._sampled(lambda **kw: seen.append(kw), model="m")
    check(seen[0].get("temperature") == 0, "the pinned temperature is sent on a normal call")
    check(b.temperature_applied is True, "and the deployment records that it was accepted")

    def refuses(**kw):
        if "temperature" in kw:
            raise RuntimeError("400: 'temperature' is not supported with this model")
        return "ok"

    b2 = probe("refuses")
    check(b2._sampled(refuses, model="m") == "ok", "a deployment refusing temperature still runs")
    check(b2.temperature_applied is False,
          "and is recorded as NOT temperature-pinned -- the run is not greedy and must not claim to be")
    check(b.temperature_applied is True,
          "support is tracked per deployment, so one refusing model does not mislabel another")

    calls = {"n": 0}
    def count(**kw):
        calls["n"] += 1
        if "temperature" in kw:
            raise RuntimeError("400: temperature unsupported")
        return "ok"
    probe("refuses")._sampled(count, model="m")
    check(calls["n"] == 1,
          "a FRESH backend for a known-refusing deployment skips the doomed attempt (no wasted call)")

    def unrelated(**kw):
        raise RuntimeError("500: gateway exploded")
    try:
        probe("healthy")._sampled(unrelated, model="m")
        check(False, "an unrelated error must propagate")
    except RuntimeError as e:
        check("gateway" in str(e), "an unrelated error is NOT swallowed by the temperature fallback")


def test_sweep_artifacts_record_the_code_state():
    """Every sweep artifact must say WHICH CODE produced it, dirtiness included.

    RESULTS_2026-08-07.md: the model sweep's source-arm runs came from a working tree whose
    adapter threading was only committed afterwards -- the recording commit's own code would have
    raised a TypeError -- and the resulting 36-flow outlier could not be traced to any tree.
    `git describe --always --dirty` in _meta is the cheapest stamp that makes that class of
    archaeology unnecessary."""
    print("\n[code_state: sweep artifacts are traceable to a tree]")
    import subprocess
    state = config.code_state()
    check(bool(state) and state != "unknown",
          f"code_state() reads this repo's git state: {state!r}")
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=config.ROOT,
                          capture_output=True, text=True).stdout.strip()
    check(state.split("-dirty")[0] == head,
          f"the stamp names HEAD ({state!r} vs {head!r}), so an artifact can be checked out")
    for script in ("run_model_sweep.py", "run_pillar_image_sweep.py"):
        src = (config.ROOT / "scripts" / script).read_text()
        check("code_state()" in src, f"{script} stamps code_state into its artifacts")


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
    print("\n[reachability: genomic reproduces the hand-counted 72/27/0 split]")
    gold = json.loads((config.KB_DIR / "scenarios/genomic/gold_standard_threats.json").read_text())["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    # matched_gold_ids=set() -- as if nothing were generated yet, isolating the pure structural
    # ceiling (independent of any live LLM run) from actual recall failures.
    # History: Week 3 found only 17/99 reachable (NIST types every human actor as ExternalEntity,
    # which the mapping table can't route through). Week 4 patched around it at lookup time with
    # a `role` annotation + effective_type() reclassification (70/99), never signed off, reverted
    # Week 8 (back to 17/99). Week 9 fixed it at the source -- genomic's dfd.json types
    # data-transforming staff as Process directly (scripts/build_genomic_dfd.py) -- giving 70/27/2.
    # Then a Week 9 re-OCR of Appendix G Figure 20 found the "de-identification cluster" (ids 18-27)
    # had corrupted descriptions/nodes in genomic_complete_raw.json (a phantom "within the data
    # delivery DMZ" threat, shifted rows, and wrong nodes at 24/25). With the raw corrected, all 99
    # gold threats map to Figure 11 row=id and every location resolves (0 unresolved); ids 20 and 23
    # land on their true flows (Patient->Clinician, and Genetic Counselor->3rd Party Previous
    # Enrollment -- a Process->ExternalEntity flow that is reachable), giving the final 72/27/0 split.
    rc = reachability_breakdown(gold, "genomic", dfd, matched_gold_ids=set())
    check(rc.reachable_but_missed == 72, f"72 structurally reachable (got {rc.reachable_but_missed})")
    check(rc.structurally_unreachable == 27, f"27 structurally unreachable (got {rc.structurally_unreachable})")
    check(rc.unresolved_location == 0, f"0 unresolved-location (got {rc.unresolved_location})")


def test_reachability_kidstube_all_resolved_after_v4_split():
    print("\n[reachability: kidstube gold threats all anchor to exactly one flow (v4)]")
    gold = json.loads((config.KB_DIR / "scenarios/kidstube/gold_standard_threats.json").read_text())["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios/kidstube/dfd.json").read_text())
    rc = reachability_breakdown(gold, "kidstube", dfd, matched_gold_ids=set())
    check(rc.structurally_unreachable == 0, "kidstube has no mapping-table gap (all flows Process-mediated)")
    check(rc.unresolved_location == 0,
          f"v4 split the 4 originally multi-flow threats (10, 18, 21, 29) into duplicate/independent "
          f"per-flow entries, so every gold threat now anchors to exactly one flow (got {rc.unresolved_location})")
    check(rc.reachable_but_missed == 41, f"all 41 threats are on a single, valid flow (got {rc.reachable_but_missed})")


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


def test_gold_location_convention_is_read_from_the_catalog():
    """Until Week 10 the matcher decided how to anchor gold by testing `scenario == "kidstube"`.
    Any other scenario built on the same flow-anchored convention -- kidstube_derived, whose gold
    is KidsTube's re-anchored -- silently took the location-anchored branch, found no
    dfd_source_id, resolved every threat to None, and scored 0.00 with no error. Detection now
    reads the catalog. These assertions pin the discriminator against the real data.
    """
    print("\n[matcher: anchoring convention is detected from the gold catalog, not the name]")
    from eval.match import FLOW_ANCHORED, LOCATION_ANCHORED, gold_location_convention

    expected = {"kidstube": FLOW_ANCHORED, "genomic": LOCATION_ANCHORED,
                "family_location": LOCATION_ANCHORED, "smart_home": LOCATION_ANCHORED}
    for scenario, want in expected.items():
        gold = json.loads((config.KB_DIR / "scenarios" / scenario /
                            "gold_standard_threats.json").read_text())["threats"]
        got = gold_location_convention(gold)
        check(got == want, f"{scenario} gold detected as {want} (got {got})")

    # A flow-anchored catalog stays flow-anchored even when some threats carry no anchor -- the
    # unanchored ones are handled downstream as unresolved_location. If `any` were `all`, a
    # derived gold with 2 deliberately-unanchored threats would flip conventions and score 0.00.
    partial = [{"id": 1, "interaction": "EE1-P1 [DF1]"}, {"id": 2, "interaction": "DS2-P4 (none)"}]
    check(gold_location_convention(partial) == FLOW_ANCHORED,
          "a partially-anchored flow catalog is still flow-anchored (guards the derived gold)")
    check(gold_location_convention([{"id": 1, "interaction": "S1.1"}]) == LOCATION_ANCHORED,
          "a catalog with no embedded flow ids is location-anchored")


def test_gold_positions_are_read_off_the_catalog_never_inferred():
    """The gold's positions must be what the analysts already asserted, not what the schema wants.

    Every value comes from comparing the human-written originator_id against the flow's endpoints
    and id. The three KidsTube `fl` threats are the ones that matter: expert analysts located
    "Interception of identified parent data during registration transmission" at DF1 -- the FLOW --
    unprompted, which is the same answer Qwen3.5-9B gave and was scored as fabricating. Anything
    that does not resolve is left unset with a note, because a guessed position in the ground truth
    would be evidence manufactured to fit the schema that wanted it."""
    print("\n[gold: position recorded, never invented]")
    import sys as _sys
    _sys.path.insert(0, str(config.ROOT / "scripts"))
    from add_gold_position import position_for

    seen = {"S": 0, "fl": 0, "D": 0, "unset": 0}
    for scenario in ("kidstube", "smart_home", "family_location", "school_grades",
                     "wearable_fitness"):
        dfd = json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())
        doc = json.loads((config.KB_DIR / "scenarios" / scenario
                          / "gold_standard_threats.json").read_text())
        threats = doc["threats"] if isinstance(doc, dict) else doc
        flows = {f["id"]: f for f in dfd["flows"]}
        for t in threats:
            pos = t.get("position", "")
            seen[pos or "unset"] += 1
            check_silent = True
            if not pos:
                check(t.get("position_source") == "unresolved" and t.get("position_note"),
                      f"{scenario} id={t['id']}: an unset position says why")
                continue
            # The recorded position must still agree with the catalog's own originator_id --
            # this is what catches a hand edit that drifts from the data it claims to describe.
            derived, _ = position_for(t, dfd)
            check(derived == pos,
                  f"{scenario} id={t['id']}: position {pos!r} re-derives from originator_id")
            flow = flows.get((t.get("interaction") or "").split("[")[-1].rstrip("]")) \
                or next((f for f in dfd["flows"] if f["source"] == t.get("dfd_source_id")
                         and f["destination"] == t.get("dfd_destination_id")), None)
            if flow:
                expected = {"S": flow["source"], "D": flow["destination"], "fl": flow["id"]}[pos]
                check(t["originator_id"] == expected,
                      f"{scenario} id={t['id']}: originator_id names the {pos} of {flow['id']}")

    check(seen["fl"] >= 3,
          f"the gold carries flow-position threats ({seen['fl']} found) -- the position the "
          f"schema could not previously express")
    check(seen["S"] > 0 and seen["D"] > 0, "and both endpoint positions are represented")


def test_position_is_the_third_linddun_location():
    """LINDDUN Pro elicits at three positions; the schema only ever had room for two.

    The tutorial (knowledge_base/linddun/threat_types_and_methodology.md, from LINDDUN PRO
    Tutorial v0.1) defines Source, Data Flow and Destination, and Table 4.1 lists all three for
    every threat type on every valid interaction. `originator_id` alone can only name an ELEMENT,
    so a data-flow threat -- the tutorial's own example, "meta-data about source and destination
    used to link flows" -- had nowhere to go. Models either coerced it onto an endpoint or
    answered "fl", the token the prompt's own legend teaches, and were then scored as having
    fabricated a citation."""
    print("\n[position: the flow is a legal location, not a fabricated one]")
    dfd = json.loads((config.KB_DIR / "scenarios/kidstube/dfd.json").read_text())
    flow = next(f for f in dfd["flows"] if f["id"] == "DF3")
    src, dst = flow["source"], flow["destination"]

    def v(position, originator_id):
        return verify_threat(GeneratedThreat(
            flow_id="DF3", originator_id=originator_id, threat_type="L", tree_node="L.1.1",
            title="t", description="d", position=position), dfd)

    check(v("S", src).location_valid, "S with the source id verifies")
    check(v("D", dst).location_valid, "D with the destination id verifies")
    check(v("fl", flow["id"]).location_valid,
          "fl with the FLOW's own id verifies -- the case that previously could not be expressed")

    check(not v("S", dst).location_valid,
          "S naming the destination fails: the pair must agree, not merely both exist")
    check(not v("fl", src).location_valid, "fl naming an element fails")
    check(not v("D", "DS5").location_valid,
          "an off-flow element fails -- the old rule accepted any element in the whole DFD")
    check(not v("X", src).location_valid and v("X", src).position_applicable is False,
          "a position outside S/fl/D is neither valid nor applicable")

    # Applicability is a separate question, checked against the mapping table the way tree_node is
    # checked against the trees.
    check(v("fl", flow["id"]).position_applicable is True,
          "fl is applicable for L at Process->ExternalEntity per mapping_table.json")

    legacy = v("", src)
    check(legacy.location_valid and legacy.position_applicable is None,
          "an artifact with no position keeps the old lenient rule and reports position UNKNOWN")
    check(legacy.all_valid,
          "and an unrunnable position check cannot fail a threat that predates the field")


def test_position_rate_is_reported_over_threats_that_cited_one():
    """A pre-position artifact has an unknown position rate, never a perfect one."""
    print("\n[position: the rate never counts unknowns as passes]")
    from eval.metrics import citation_correctness
    from generation.verify import VerificationResult

    mixed = [VerificationResult(True, True, True, True),
             VerificationResult(True, True, True, False),
             VerificationResult(True, True, True, None)]     # predates the field
    stats = citation_correctness(mixed)
    check(stats["n_position_cited"] == 2,
          f"only the two threats that cited a position are counted (got {stats['n_position_cited']})")
    check(abs(stats["position_applicable_rate"] - 0.5) < 1e-9,
          f"rate is 1/2, not 2/3 (got {stats['position_applicable_rate']})")

    legacy_only = [VerificationResult(True, True, True, None) for _ in range(3)]
    check("position_applicable_rate" not in citation_correctness(legacy_only),
          "with nothing cited the key is absent, so an old eval report is byte-unchanged")


def test_prompt_stops_teaching_fl_as_an_originator_id():
    """The prompt's legend defines fl=flow and repeats it seven times as a position. Before
    `position` existed there was no field that accepted it, so the instruction has to say
    explicitly where it belongs -- 131 citations across four sweeps put it in the wrong one."""
    print("\n[prompt: fl is directed to the position field]")
    from generation.prompt import build_grounded_prompt
    from retrieval.interaction_context import get_interaction_context, effective_type
    dfd = json.loads((config.KB_DIR / "scenarios/kidstube/dfd.json").read_text())
    els = {e["id"]: e for e in dfd["elements"]}
    flow = next(f for f in dfd["flows"] if f["id"] == "DF3")
    ctx = get_interaction_context(effective_type(els[flow["source"]]),
                                  effective_type(els[flow["destination"]]))
    p = build_grounded_prompt(flow, els, ctx)

    check("fl=flow" in p, "the legend that caused this is still present (it is the methodology's)")
    check('"fl" is a position' in p, "and the instruction now says where fl belongs")
    check(f'"{flow["id"]}" (this flow) for fl' in p,
          "the prompt names the flow id as the answer for the fl position")
    for tok in ("S", "fl", "D"):
        check(f'"{tok}"' in p, f"position value {tok!r} is offered to the model")


def test_malformed_threat_is_dropped_and_counted_not_fatal():
    """A threat missing a field its own tool schema marks `required` must cost that threat, not
    the whole run -- and must be counted, because it is a property of the model under test.

    Forced tool calling was assumed to make this impossible, and it does hold for the hosted
    deployments: across every Azure run in this repo it never fired once. A locally served open
    model breaks it routinely -- Qwen3.5-9B omitted threat_type or tree_node in 6 of its first 21
    cells -- and a single malformed item used to raise TypeError out of the whole scenario,
    discarding every flow already paid for.

    Silence would be the wrong fix. An entry with no threat_type is not an answer and must not
    enter the threat set, but schema compliance is exactly the kind of thing this repo measures
    rather than absorbs, so the count is surfaced through `stats` for the run record."""
    print("\n[schema: malformed threats are dropped, counted, and never fatal]")
    import generation.generate as gen_mod

    class PartlyMalformedBackend:
        name, model = "stub", "stub-1"
        def generate_threats(self, prompt):
            return {"threats": [
                {"originator_id": "E1", "threat_type": "L", "tree_node": "L.1.1",
                 "title": "well-formed", "description": "d"},
                {"originator_id": "E1", "tree_node": "L.1.1",          # no threat_type
                 "title": "missing threat_type", "description": "d"},
                {"originator_id": "E1", "threat_type": "Dd",           # no tree_node
                 "title": "missing tree_node", "description": "d"},
            ]}

    real = gen_mod.get_llm_backend
    gen_mod.get_llm_backend = lambda *a, **k: PartlyMalformedBackend()
    try:
        stats = {}
        threats = gen_mod.generate_for_scenario("kidstube", mode="grounded", progress=False,
                                                stats=stats)
    finally:
        gen_mod.get_llm_backend = real

    n_flows = len({t.flow_id for t in threats})
    check(len(threats) == n_flows and n_flows > 0,
          f"the well-formed threat from every flow survives ({len(threats)} kept)")
    check(all(t.title == "well-formed" for t in threats),
          "only the schema-conforming entry is kept")
    check(stats["malformed_dropped"] == 2 * n_flows,
          f"both malformed entries per flow are counted "
          f"(got {stats['malformed_dropped']}, expected {2 * n_flows})")
    check(len(stats["malformed"]) == stats["malformed_dropped"]
          and all(":" in m for m in stats["malformed"]),
          "each drop is recorded against the flow it came from, for the run record")

    # The contract the old code broke: one bad item must never discard the flows already paid for.
    class AllMalformedBackend:
        name, model = "stub", "stub-1"
        def generate_threats(self, prompt):
            return {"threats": [{"title": "nothing else at all"}]}

    gen_mod.get_llm_backend = lambda *a, **k: AllMalformedBackend()
    try:
        stats2 = {}
        threats2 = gen_mod.generate_for_scenario("kidstube", mode="grounded", progress=False,
                                                 stats=stats2)
    except TypeError:
        check(False, "an entirely malformed response returns empty rather than raising")
        threats2, stats2 = None, {"malformed_dropped": -1}
    finally:
        gen_mod.get_llm_backend = real

    if threats2 is not None:
        check(threats2 == [] and stats2["malformed_dropped"] > 0,
              f"an entirely malformed response yields no threats and a nonzero drop count "
              f"(got {len(threats2)} threats, {stats2['malformed_dropped']} dropped)")

    empty = {}
    gen_mod.get_llm_backend = lambda *a, **k: type(
        "Clean", (), {"name": "s", "model": "s",
                      "generate_threats": lambda self, p: {"threats": []}})()
    try:
        gen_mod.generate_for_scenario("kidstube", mode="grounded", progress=False, stats=empty)
    finally:
        gen_mod.get_llm_backend = real
    check(empty.get("malformed_dropped") == 0,
          "a clean run records 0 explicitly, so 'no key' never has to mean 'none happened'")


def test_concurrency_changes_issue_order_and_nothing_else():
    """Raising GENERATION_CONCURRENCY must change only the order calls are ISSUED.

    Flows are independent, so the serial loop was never a correctness requirement -- but the
    artifact is a list whose order readers and the matcher both rely on, and a thread pool returns
    completions in whatever order they finish. If that order leaked into the output, every
    concurrent run would be silently incomparable to every serial one already committed, which is
    worse than the slowness it was meant to fix.

    The stub answers deterministically per flow but with jittered latency, so a parallel run WILL
    complete out of order: if ordering were not enforced the outputs would differ and this test
    would fail rather than pass by luck. Concurrency is set per call rather than through the
    environment, matching how a sweep varies it."""
    print("\n[concurrency: parallel issue order, serial output order]")
    import random
    import time
    import generation.generate as gen_mod

    class StubBackend:
        name, model = "stub", "stub-1"
        def __init__(self):
            self.calls = []
        def generate_threats(self, prompt):
            flow_id = prompt.split("Flow ")[1].split(":")[0]
            self.calls.append(flow_id)
            time.sleep(random.uniform(0.001, 0.02))
            return {"threats": [{"originator_id": "E1", "threat_type": "L",
                                 "tree_node": "L.1.1", "title": f"t-{flow_id}",
                                 "description": f"d-{flow_id}"}]}

    real_get_backend = gen_mod.get_llm_backend
    stubs = {}
    try:
        serialised = {}
        for c in (1, 4, 16):
            stub = StubBackend()
            stubs[c] = stub
            gen_mod.get_llm_backend = lambda *a, **k: stub
            random.seed(0)
            threats = gen_mod.generate_for_scenario("kidstube", mode="grounded", progress=False,
                                                    concurrency=c)
            serialised[c] = json.dumps([t.to_dict() for t in threats], sort_keys=True)
    finally:
        gen_mod.get_llm_backend = real_get_backend

    check(serialised[1] == serialised[4] == serialised[16],
          "output is byte-identical at concurrency 1, 4 and 16")
    check(len(stubs[16].calls) == len(stubs[1].calls) > 0,
          f"every flow is called exactly once regardless of concurrency "
          f"({len(stubs[1].calls)} calls)")
    flow_order = [t["flow_id"] for t in json.loads(serialised[16])]
    check(flow_order == sorted(flow_order, key=lambda f: int(f.replace("DF", ""))),
          "threats stay in DFD flow order, not completion order")


def test_pillar_endpoint_resolution_prefers_the_element_id():
    """PILLAR run 2 redrew the DFD with our element ids in the labels; run 1 did not.

    The two exports name the same twelve elements differently -- run 1 free-form
    ("Authentication Service"), run 2 id-prefixed ("P1 Authentication Services", where the name
    after the id drifts to a plural). Name-only matching maps every run-2 edge to nothing and the
    comparison silently reports a recall of zero for a DFD the analyst had deliberately aligned.
    The id, when present, is the authoritative handle."""
    print("\n[pillar: endpoint labels resolve by element id first, name second]")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "score_pillar", config.ROOT / "scripts" / "score_pillar.py")
    sp = importlib.util.module_from_spec(spec); spec.loader.exec_module(sp)

    ids = {"EE1", "P1", "DS1"}
    by_name = {"Parent User": "EE1", "Authentication Service": "P1"}

    check(sp.resolve_endpoint("P1 Authentication Services", ids, by_name) == "P1",
          "the id wins even though 'Services' != our 'Service'")
    check(sp.resolve_endpoint("Authentication Service", ids, by_name) == "P1",
          "a free-form label still resolves by exact name (run 1 must not regress)")
    check(sp.resolve_endpoint("Some Unmodelled Thing", ids, by_name) is None,
          "a label giving neither id nor known name stays unmapped, never guessed")
    check(sp.resolve_endpoint("DS1 MongoDB - users", ids, by_name) == "DS1",
          "id-prefixed data stores resolve despite a completely different name")


def test_pillar_edge_maps_to_every_parallel_flow():
    """kidstube draws DF7 and DF10 both P3->DS2, and an edge-level export cannot say which.

    Keying the endpoint map on a single flow id let the second flow overwrite the first, so gold
    threats on whichever lost were unreachable and PILLAR's recall was understated. The pair maps
    to a SET; a gold threat on either member counts."""
    print("\n[pillar: an endpoint pair maps to every flow drawn over it]")
    dfd = json.loads((config.KB_DIR / "scenarios/kidstube/dfd.json").read_text())
    pairs = {}
    for f in dfd["flows"]:
        pairs.setdefault((f["source"], f["destination"]), set()).add(f["id"])
    dupes = {k: v for k, v in pairs.items() if len(v) > 1}
    check(dupes == {("P3", "DS2"): {"DF7", "DF10"}},
          f"kidstube's one parallel pair is P3->DS2 = DF7+DF10 (found {dupes})")
    check(sum(len(v) for v in pairs.values()) == len(dfd["flows"]),
          "every flow survives the grouping -- none is overwritten by a later one")


def test_pillar_abstention_is_not_a_wrong_citation():
    """PILLAR's grid has a cell per S/fl/D position, and a declined cell is an abstention.

    We reported 0.82 "citation validity" for PILLAR against our own 1.00. That was wrong: the
    0.18 shortfall is entirely cells PILLAR declined, and a declined id cell always has a
    declined PROSE cell beside it -- it never wrote a threat it could not cite. The number was
    measuring coverage while being quoted as validity, against a tool that abstains where ours
    cannot. Validity on asserted cells is 1.00 in both exports."""
    print("\n[pillar: a declined cell is an abstention, not an invalid citation]")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "score_pillar", config.ROOT / "scripts" / "score_pillar.py")
    sp = importlib.util.module_from_spec(spec); spec.loader.exec_module(sp)
    valid = sp.load_kb_nodes(); ci = {v.lower(): v for v in valid}
    ID_KEYS = ("source_id", "data_flow_id", "destination_id")
    PROSE = {"source_id": "source", "data_flow_id": "data_flow", "destination_id": "destination"}
    ABSTAIN = {"", "not applicable", "threat not possible", "n/a"}

    for name in ("linddun_pro_full_analysis.json", "linddun_pro_full_analysis_run2.json"):
        path = config.KB_DIR / "PILLAR" / name
        if not path.exists():
            continue
        entries = json.loads(path.read_text())
        asserted = fabricated = orphan_prose = 0
        for e in entries:
            for k in ID_KEYS:
                kind = sp.classify_node(e.get(k), valid, ci)
                if kind == "not_an_id":
                    if (e.get(PROSE[k]) or "").strip().lower() not in ABSTAIN:
                        orphan_prose += 1
                    continue
                asserted += 1
                if kind == "unresolvable":
                    fabricated += 1
        check(orphan_prose == 0,
              f"{name}: no cell writes a threat description without an id ({orphan_prose} found)")
        check(fabricated == 0,
              f"{name}: every asserted id resolves -- validity on asserted is 1.00, "
              f"not the coverage figure ({fabricated} fabricated of {asserted})")


def test_dotenv_placeholder_lines_do_not_become_empty_env_vars():
    """`.env` documents optional settings with bare `KEY=` lines. Exporting those as "" broke
    OpenAI entirely.

    config.OPENAI_BASE_URL already spells `or None`, so our own code was fine -- but the OpenAI
    SDK reads OPENAI_BASE_URL from the environment itself and checks presence, not truthiness.
    An exported "" therefore became a literal base URL and every call died with "Request URL is
    missing an 'http://' or 'https://' protocol", which reads as a network fault rather than a
    config one. A blank value in .env means the setting is off, not set to empty."""
    print("\n[.env: a bare KEY= line means absent, not empty]")
    import tempfile
    from pathlib import Path as _Path
    with tempfile.TemporaryDirectory() as d:
        env = _Path(d) / ".env"
        env.write_text("# comment\nSET_ME=value\nBLANK_ONE=\nPADDED=  spaced  \n"
                       "BLANK_PADDED=   \n")
        saved = {k: os.environ.get(k) for k in
                 ("SET_ME", "BLANK_ONE", "PADDED", "BLANK_PADDED")}
        for k in saved:
            os.environ.pop(k, None)
        try:
            config._load_dotenv(env)
            check(os.environ.get("SET_ME") == "value", "a real value is exported")
            check("BLANK_ONE" not in os.environ,
                  "a bare KEY= line exports nothing, so an SDK reading it sees absence")
            check("BLANK_PADDED" not in os.environ,
                  "a whitespace-only value is absent too, not a string of spaces")
            check(os.environ.get("PADDED") == "spaced", "values are still stripped")
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v


def test_rate_limit_retry_honours_the_stated_interval():
    """A 429 is the provider declining to process the request, so waiting it out is correct.

    The objection that forbids retrying a bad response -- never re-roll until the model agrees --
    does not apply, because on a 429 no model ran. It is also not optional at small tiers: one
    17-flow KidsTube run sends ~42k tokens against a 30k-per-minute allowance, and the first
    attempt at this comparison lost runs 2 and 3 to a single 429 after run 1 was already paid for.
    The wait must come from the provider's own figure; guessing low burns the retry budget on
    calls that cannot succeed."""
    print("\n[429: wait the interval the provider states, and cap it]")
    from generation.llm_backend import (OpenAIBackend, RATE_LIMIT_MAX_SLEEP,
                                        GATEWAY_BACKOFF_SECONDS)
    ra = OpenAIBackend._retry_after

    class Err(Exception):
        def __init__(self, msg, headers=None):
            super().__init__(msg)
            self.response = type("R", (), {"headers": headers or {}})()

    real = Err("Error code: 429 - {'error': {'message': 'Rate limit reached for gpt-4o in "
               "organization org-X on tokens per min (TPM): Limit 30000, Used 28924, Requested "
               "2548. Please try again in 2.944s.'}}")
    check(abs(ra(real, 1) - 3.444) < 1e-6,
          f"parses the seconds figure out of a real 429 body (+0.5s edge clearance): {ra(real,1)}")
    check(abs(ra(Err("please try again in 200ms"), 1) - 0.7) < 1e-6,
          "parses the millisecond form as milliseconds, not seconds")
    check(abs(ra(Err("nope", {"retry-after-ms": "1500"}), 1) - 2.0) < 1e-6,
          "falls back to the retry-after-ms header when the body does not say")
    check(ra(Err("nope"), 3) == GATEWAY_BACKOFF_SECONDS * 3,
          "with no figure anywhere, backs off proportionally to the attempt")
    check(ra(Err("try again in 9999s"), 1) == RATE_LIMIT_MAX_SLEEP,
          "a absurd or misparsed figure is capped, never an unbounded park")


def main():
    test_dfd_files()
    test_genomic_gold_has_dfd_locations()
    test_gold_location_convention_is_read_from_the_catalog()
    test_schema_roundtrip()
    test_schema_mode_field()
    test_resolve_mode()
    test_build_flow_query()
    test_build_rag_prompt()
    test_rag_retrieval_no_gold_leakage()
    test_resolve_mode_panoptic()
    test_build_panoptic_prompt()
    test_build_panoptic_rag_prompt()
    test_build_panoptic_ungrounded_prompt()
    test_panoptic_rag_retrieval_no_gold_leakage()
    test_matcher_panoptic()
    test_panoptic_category_scores()
    test_reachability_panoptic_no_structural_gate()
    test_verifier_valid_citation()
    test_verifier_fabricated_citations()
    test_matcher_coarse_tier()
    test_matcher_strict_tier()
    test_adjudicate_worklist_and_precision()
    test_adjudicate_precision_extrapolation_from_sample()
    test_per_node_scores()
    test_reachability_genomic_reproduces_published_split()
    test_reachability_kidstube_all_resolved_after_v4_split()
    test_reachability_recall_property()
    test_llm_backend_routing()
    test_gateway_retry_is_narrow_and_never_rerolls_an_answer()
    test_temperature_is_pinned_and_degrades_honestly()
    test_sweep_artifacts_record_the_code_state()
    test_matcher_genomic_location_based()
    test_matcher_genomic_without_dfd_falls_back_to_coarse()
    test_gold_positions_are_read_off_the_catalog_never_inferred()
    test_position_is_the_third_linddun_location()
    test_position_rate_is_reported_over_threats_that_cited_one()
    test_prompt_stops_teaching_fl_as_an_originator_id()
    test_malformed_threat_is_dropped_and_counted_not_fatal()
    test_concurrency_changes_issue_order_and_nothing_else()
    test_pillar_endpoint_resolution_prefers_the_element_id()
    test_pillar_edge_maps_to_every_parallel_flow()
    test_pillar_abstention_is_not_a_wrong_citation()
    test_dotenv_placeholder_lines_do_not_become_empty_env_vars()
    test_rate_limit_retry_honours_the_stated_interval()
    print(f"\n{'='*50}\nPASSED {PASS}  FAILED {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
