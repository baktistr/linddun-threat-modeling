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


def test_chunks():
    print("\n[ingestion]")
    chunks = load_corpus()
    check(len(chunks) > 100, f"loaded >100 chunks (got {len(chunks)})")
    kinds = {c.meta.get("kind") for c in chunks}
    check("tree_node" in kinds, "tree_node chunks present")
    check("mapping_row" in kinds, "mapping_row chunks present")
    check("gold_threat" in kinds, "gold_threat chunks present")


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
    test_chunks()
    test_retrieval_quality()
    print(f"\n{'='*50}\nPASSED {PASS}  FAILED {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
