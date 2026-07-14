"""Smoke + quality tests for the LINDDUN knowledge base and retriever.

Run: PYTHONPATH=. python3 tests/test_kb.py
These are plain asserts (no pytest dependency) so they run anywhere.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import config
from ingestion.loader import load_corpus
from retrieval.index import Retriever

PASS, FAIL = 0, 0


def check(cond: bool, msg: str):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {msg}")
    else:
        FAIL += 1
        print(f"  FAIL {msg}")


def test_kb_files_exist():
    print("\n[knowledge base files]")
    kb = config.KB_DIR
    for rel in [
        "linddun/threat_trees.json",
        "linddun/mapping_table.json",
        "linddun/threat_types_and_methodology.md",
        "scenarios/kidstube/system_description.md",
        "scenarios/kidstube/gold_standard_threats.json",
        "scenarios/genomic/system_description.md",
        "scenarios/genomic/gold_standard_threats.json",
    ]:
        check((kb / rel).exists(), f"exists: {rel}")


def test_gold_standard_integrity():
    print("\n[gold standard integrity]")
    gs = json.loads((config.KB_DIR / "scenarios/kidstube/gold_standard_threats.json").read_text())
    threats = gs["threats"]
    check(len(threats) == 41, f"41 threats (got {len(threats)})")
    ids = [t["id"] for t in threats]
    check(ids == list(range(1, 42)), "ids contiguous 1..41")
    types = {t["threat_type"] for t in threats}
    check(types == {"L", "I", "Nr", "D", "Dd", "U", "Nc"}, f"all 7 LINDDUN types present (got {sorted(types)})")
    check(all(t["tree_node"] for t in threats), "every threat has a tree node")
    check(all(t["assumptions"] for t in threats), "every threat has assumptions documented")


def test_genomic_gold_standard_integrity():
    print("\n[genomic gold standard integrity]")
    gs = json.loads((config.KB_DIR / "scenarios/genomic/gold_standard_threats.json").read_text())
    threats = gs["threats"]
    check(len(threats) == 99, f"99 threats / complete example (got {len(threats)})")
    ids = [t["id"] for t in threats]
    check(ids == list(range(1, 100)), "ids contiguous 1..99")
    types = {t["threat_type"] for t in threats}
    # the complete example exercises all 7 LINDDUN types
    check(types == {"L", "I", "Nr", "D", "Dd", "U", "Nc"}, f"all 7 LINDDUN types present (got {sorted(types)})")
    check(sum(t.get("in_core_example") for t in threats) == 10, "10 threats tagged in_core_example")
    check(all(t.get("nist_node") for t in threats), "every threat keeps its verbatim NIST node")
    check(all(t.get("impacted_peos") for t in threats), "every threat records impacted PEOs")
    check(all(t.get("ranking_value") is not None for t in threats), "every threat has a NIST ranking value")
    # cross-check against the NIST source (Figure 24 + ranking formula Tables 18/19)
    from scripts.verify_genomic import audit, formula_failures
    corroborated, flagged = audit(threats)
    fails = formula_failures(flagged)
    check(not fails, f"all rows satisfy NIST's ranking formula (violations: {[t[0] for t in fails]})")
    check(corroborated >= 97, f">=97/99 rows corroborated by two independent figures (got {corroborated})")
    # tree nodes must resolve against the official trees (prefix fallback for re-maps)
    trees = json.loads((config.KB_DIR / "linddun/threat_trees.json").read_text())
    tree_nodes = set()
    for tt in trees["threat_types"].values():
        tree_nodes |= set(tt["nodes"].keys())

    def covered(n):
        p = n.split(".")
        return any(".".join(p[:i]) in tree_nodes for i in range(len(p), 0, -1))

    check(all(covered(t["tree_node"]) for t in threats), "every tree node resolves against the trees")


def _check_scenario_gold_integrity(scenario: str, expected_count: int):
    print(f"\n[{scenario} gold standard integrity]")
    gs = json.loads((config.KB_DIR / f"scenarios/{scenario}/gold_standard_threats.json").read_text())
    threats = gs["threats"]
    dfd = json.loads((config.KB_DIR / f"scenarios/{scenario}/dfd.json").read_text())
    trees = json.loads((config.KB_DIR / "linddun/threat_trees.json").read_text())["threat_types"]
    tree_nodes = {nid for tt in trees.values() for nid in tt["nodes"]}
    elem_ids = {e["id"] for e in dfd["elements"]}
    flow_pairs = {(f["source"], f["destination"]) for f in dfd["flows"]}

    check(len(threats) == expected_count, f"{expected_count} threats (got {len(threats)})")
    ids = [t["id"] for t in threats]
    check(ids == list(range(1, expected_count + 1)), f"ids contiguous 1..{expected_count}")
    types = {t["threat_type"] for t in threats}
    check(types == {"L", "I", "Nr", "D", "Dd", "U", "Nc"}, f"all 7 LINDDUN types present (got {sorted(types)})")
    check(all(t["tree_node"] in tree_nodes for t in threats), "every tree_node is a real threat-tree node")
    check(all((t["dfd_source_id"], t["dfd_destination_id"]) in flow_pairs for t in threats),
          "every threat's dfd_source_id/dfd_destination_id matches a real dfd.json flow")
    check(all(t["originator_id"] in (t["dfd_source_id"], t["dfd_destination_id"]) for t in threats),
          "every threat's originator_id is one of its own flow's endpoints")
    check(all(t["originator_id"] in elem_ids for t in threats), "every originator_id is a real element")
    check(all(t["assumptions"] for t in threats), "every threat has assumptions documented")
    # Every flow is Process-mediated by design (see each dfd.json's _meta) -- no genomic-style gap.
    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    non_process_mediated = [
        f for f in dfd["flows"]
        if elements_by_id[f["source"]]["type"] != "Process" and elements_by_id[f["destination"]]["type"] != "Process"
    ]
    check(not non_process_mediated,
          f"every flow is Process-mediated (0 structurally-unreachable-by-design flows expected, "
          f"got {len(non_process_mediated)}: {[f['id'] for f in non_process_mediated]})")


def test_family_location_gold_standard_integrity():
    _check_scenario_gold_integrity("family_location", 20)


def test_smart_home_gold_standard_integrity():
    _check_scenario_gold_integrity("smart_home", 18)


def test_panoptic_crosswalk():
    print("\n[PANOPTIC<->LINDDUN crosswalk]")
    cw = json.loads((config.KB_DIR / "linddun/panoptic_crosswalk.json").read_text())
    check(len(cw["panoptic_categories"]) == 13, f"13 PANOPTIC categories (got {len(cw['panoptic_categories'])})")
    check(len(cw["linddun_types"]) == 7, f"7 LINDDUN types (got {len(cw['linddun_types'])})")
    check(set(cw["linddun_types"]) == {"L", "I", "Nr", "D", "Dd", "U", "Nc"}, "all 7 LINDDUN type codes present")
    check(len(cw["_meta"]["asymmetries"]) == 1,
          f"exactly 1 known transcription asymmetry (PA12), not silently re-introduced or hidden "
          f"(got {len(cw['_meta']['asymmetries'])})")

    from scripts.audit_panoptic_mapping import audit
    report = audit()
    check(report["n_total"] == 99, f"audited all 99 genomic gold threats (got {report['n_total']})")
    check(report["n_inconsistent"] == 0,
          f"every gold threat's (threat_type, panoptic_actions) pairing is consistent with the "
          f"crosswalk (got {report['n_inconsistent']} inconsistent: {report['inconsistent']})")
    check(report["n_no_categories"] == 0, "every gold threat has at least one parseable panoptic_action")


def test_panoptic_taxonomy():
    print("\n[PANOPTIC taxonomy KB]")
    tax = json.loads((config.KB_DIR / "panoptic/taxonomy.json").read_text())
    check(len(tax["contextual_domains"]) == 5, f"5 contextual domains (got {len(tax['contextual_domains'])})")
    check(len(tax["privacy_activities"]) == 13, f"13 privacy activities (got {len(tax['privacy_activities'])})")
    ids = {pa["id"] for pa in tax["privacy_activities"]}
    check(ids == {f"PA{n:02d}" for n in range(1, 14)}, f"PA01..PA13 all present (got {sorted(ids)})")
    check(all(pa["sub_activities"] for pa in tax["privacy_activities"]),
          "every privacy activity has at least one sub-activity")
    n_sub = sum(len(pa["sub_activities"]) for pa in tax["privacy_activities"])
    check(n_sub == 100, f"100 sub-activities total (got {n_sub})")

    cw = json.loads((config.KB_DIR / "linddun/panoptic_crosswalk.json").read_text())
    for pa in tax["privacy_activities"]:
        check(pa["linddun_types"] == cw["panoptic_to_linddun"].get(pa["id"]),
              f"{pa['id']}'s linddun_types matches panoptic_crosswalk.json (single source of truth)")


def test_chunks():
    print("\n[ingestion]")
    chunks = load_corpus()
    check(len(chunks) > 100, f"loaded >100 chunks (got {len(chunks)})")
    kinds = {c.meta.get("kind") for c in chunks}
    check("tree_node" in kinds, "tree_node chunks present")
    check("mapping_row" in kinds, "mapping_row chunks present")
    check("gold_threat" in kinds, "gold_threat chunks present")
    check("panoptic_sub_activity" in kinds, "panoptic_sub_activity chunks present")
    check(sum(1 for c in chunks if c.source == "panoptic") == 118,
          f"118 panoptic-source chunks: 5 domains + 13 activities + 100 sub-activities "
          f"(got {sum(1 for c in chunks if c.source == 'panoptic')})")


def test_retrieval_quality():
    print("\n[retrieval quality]")
    r = Retriever.load()
    # (query, source_filter, substring expected in any top-k hit's section or text)
    cases = [
        ("government ID stored unencrypted", None, "government id"),
        ("excessive data volume retained", "linddun", "Dd.2"),
        ("children not informed about tracking", None, "unaware"),
        ("unable to deny an action they took", "linddun", "non-repudiation"),
        ("mapping table external entity to process", "linddun", "ExternalEntity"),
        ("profiling children behavioral data", "scenarios", "profil"),
    ]
    for query, source, expect in cases:
        hits = r.search(query, k=5, source=source)
        blob = " ".join((h.chunk.section + " " + h.chunk.text) for h in hits).lower()
        check(expect.lower() in blob, f"query {query!r} -> finds {expect!r}")


def main():
    test_kb_files_exist()
    test_gold_standard_integrity()
    test_genomic_gold_standard_integrity()
    test_family_location_gold_standard_integrity()
    test_smart_home_gold_standard_integrity()
    test_panoptic_crosswalk()
    test_panoptic_taxonomy()
    test_chunks()
    test_retrieval_quality()
    print(f"\n{'='*50}\nPASSED {PASS}  FAILED {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
