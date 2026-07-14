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
    check(rc.reachable_but_missed == 97, f"97 reachable (got {rc.reachable_but_missed})")
    check(rc.unresolved_location == 2, f"2 unresolved-location (got {rc.unresolved_location})")


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
    print("\n[reachability: genomic reproduces the WEEK9 hand-counted 70/27/2 split]")
    gold = json.loads((config.KB_DIR / "scenarios/genomic/gold_standard_threats.json").read_text())["threats"]
    dfd = json.loads((config.KB_DIR / "scenarios/genomic/dfd.json").read_text())
    # matched_gold_ids=set() -- as if nothing were generated yet, isolating the pure structural
    # ceiling (independent of any live LLM run) from actual recall failures.
    # History: Week 3 found only 17/99 reachable (NIST types every human actor as ExternalEntity,
    # which the mapping table can't route through). Week 4 patched around it at lookup time with
    # a `role` annotation + effective_type() reclassification (70/99), never signed off, reverted
    # Week 8 (back to 17/99). Week 9 fixes it at the source instead -- genomic's dfd.json now
    # types data-transforming staff as Process directly (scripts/build_genomic_dfd.py), so 70/99
    # is reachable again, this time as a structural fact about the DFD rather than a lookup-time
    # hack. See retrieval/interaction_context.py:effective_type() for the full history.
    rc = reachability_breakdown(gold, "genomic", dfd, matched_gold_ids=set())
    check(rc.reachable_but_missed == 70, f"70 structurally reachable (got {rc.reachable_but_missed})")
    check(rc.structurally_unreachable == 27, f"27 structurally unreachable (got {rc.structurally_unreachable})")
    check(rc.unresolved_location == 2, f"2 unresolved-location (got {rc.unresolved_location})")


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


def main():
    test_dfd_files()
    test_genomic_gold_has_dfd_locations()
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
    test_matcher_genomic_location_based()
    test_matcher_genomic_without_dfd_falls_back_to_coarse()
    print(f"\n{'='*50}\nPASSED {PASS}  FAILED {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
