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
        "regulations/regulations.md",
        "scenarios/kidstube/system_description.md",
        "scenarios/kidstube/gold_standard_threats.json",
    ]:
        check((kb / rel).exists(), f"exists: {rel}")


def test_gold_standard_integrity():
    print("\n[gold standard integrity]")
    gs = json.loads((config.KB_DIR / "scenarios/kidstube/gold_standard_threats.json").read_text())
    threats = gs["threats"]
    check(len(threats) == 36, f"36 threats (got {len(threats)})")
    ids = [t["id"] for t in threats]
    check(ids == list(range(1, 37)), "ids contiguous 1..36")
    types = {t["threat_type"] for t in threats}
    check(types == {"L", "I", "Nr", "D", "Dd", "U", "Nc"}, f"all 7 LINDDUN types present (got {sorted(types)})")
    check(all(t["tree_node"] for t in threats), "every threat has a tree node")
    check(all(t["assumptions"] for t in threats), "every threat has assumptions documented")


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
        ("verifiable parental consent", "regulations", "312.5"),
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
    test_chunks()
    test_retrieval_quality()
    print(f"\n{'='*50}\nPASSED {PASS}  FAILED {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
