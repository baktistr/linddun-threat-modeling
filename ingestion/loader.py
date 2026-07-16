"""Ingestion: load knowledge-base documents and split them into retrievable chunks.

Handles Markdown/text (split on headings then size) and JSON (structured items
become individual chunks so each threat-tree node / threat is independently
retrievable). Every chunk carries metadata for filtering and citation.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

import config


@dataclass
class Chunk:
    id: str
    text: str
    source: str          # corpus tag: linddun | scenarios
    doc: str             # filename
    section: str = ""    # heading or json key path
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _split_markdown(text: str, doc: str, source: str) -> list[Chunk]:
    """Split markdown on ## / ### headings, then enforce max chunk size."""
    chunks: list[Chunk] = []
    current_heading = ""
    buf: list[str] = []

    def flush():
        if not buf:
            return
        body = "\n".join(buf).strip()
        if body:
            _emit_sized(body, current_heading)

    def _emit_sized(body: str, heading: str):
        # size-based splitting with overlap, on paragraph boundaries where possible
        if len(body) <= config.CHUNK_SIZE:
            chunks.append(_mk(body, heading))
            return
        start = 0
        while start < len(body):
            end = start + config.CHUNK_SIZE
            piece = body[start:end]
            chunks.append(_mk(piece, heading))
            start = end - config.CHUNK_OVERLAP

    def _mk(body: str, heading: str) -> Chunk:
        cid = f"{source}:{doc}:{len(chunks)}"
        return Chunk(id=cid, text=body, source=source, doc=doc, section=heading)

    for line in text.splitlines():
        if line.startswith("## "):
            flush()
            buf = []
            current_heading = line.lstrip("# ").strip()
        elif line.startswith("# "):
            flush()
            buf = []
            current_heading = line.lstrip("# ").strip()
        else:
            buf.append(line)
    flush()
    return chunks


def _split_json(path: Path, doc: str, source: str) -> list[Chunk]:
    """Turn structured JSON into per-item chunks.

    threat_trees.json   -> one chunk per threat-tree node
    mapping_table.json  -> one chunk per interaction row
    gold_standard_*.json-> one chunk per threat
    Fallback: one chunk for the whole file.
    """
    data = json.loads(path.read_text())
    chunks: list[Chunk] = []

    def add(text: str, section: str, meta: dict):
        cid = f"{source}:{doc}:{len(chunks)}"
        chunks.append(Chunk(id=cid, text=text.strip(), source=source, doc=doc, section=section, meta=meta))

    if "threat_types" in data:  # threat_trees.json
        for ttype, tinfo in data["threat_types"].items():
            tname = tinfo.get("name", ttype)
            add(f"LINDDUN threat type {ttype} ({tname}): {tinfo.get('definition','')}",
                section=f"{ttype} {tname}", meta={"threat_type": ttype, "kind": "type_definition"})
            for node_id, node in tinfo.get("nodes", {}).items():
                add(f"Threat tree node {node_id} — {node.get('title','')}: {node.get('description','')} "
                    f"(LINDDUN type: {tname})",
                    section=f"{node_id} {node.get('title','')}",
                    meta={"threat_type": ttype, "tree_node": node_id, "kind": "tree_node"})
    elif "interactions" in data:  # mapping_table.json
        for row in data["interactions"]:
            applicable = ", ".join(
                f"{tt} at {'/'.join(pos)}" for tt, pos in row["applicable_threats"].items()
            )
            add(f"Mapping table: interaction {row['source']} -> flow -> {row['destination']}. "
                f"Applicable LINDDUN threat types and positions: {applicable}.",
                section=f"{row['source']}->{row['destination']}",
                meta={"kind": "mapping_row", "src": row["source"], "dst": row["destination"]})
        for inv in data.get("invalid_interactions", []):
            add(f"Invalid interaction {inv['source']} -> {inv['destination']}: {inv['reason']}",
                section=f"invalid {inv['source']}->{inv['destination']}",
                meta={"kind": "mapping_invalid"})
    elif "privacy_activities" in data:  # panoptic/taxonomy.json
        for pc in data.get("contextual_domains", []):
            add(f"PANOPTIC Contextual Domain {pc['id']} ({pc['name']}): {pc.get('description','')}",
                section=f"{pc['id']} {pc['name']}",
                meta={"kind": "panoptic_contextual_domain", "panoptic_id": pc["id"]})
        for pa in data["privacy_activities"]:
            lt = ", ".join(pa.get("linddun_types", []))
            add(f"PANOPTIC Privacy Activity {pa['id']} ({pa['name']}). LINDDUN types: {lt}.",
                section=f"{pa['id']} {pa['name']}",
                meta={"kind": "panoptic_activity", "panoptic_id": pa["id"], "linddun_types": pa.get("linddun_types", [])})
            for sub in pa.get("sub_activities", []):
                add(f"PANOPTIC sub-activity {sub['id']} — {sub['name']}: {sub.get('description','')} "
                    f"(under {pa['id']} {pa['name']}; LINDDUN types: {lt})",
                    section=f"{sub['id']} {sub['name']}",
                    meta={"kind": "panoptic_sub_activity", "panoptic_id": sub["id"],
                          "parent_activity": pa["id"], "linddun_types": pa.get("linddun_types", [])})
    elif "threats" in data:  # gold_standard_threats.json
        for t in data["threats"]:
            # "interaction" is KidsTube/genomic's own field (a [DFn] tag or NIST scenario_id);
            # scenarios using the location-based convention (family_location, smart_home) instead
            # carry dfd_source_id/dfd_destination_id -- fall back to composing an equivalent
            # string from those rather than assuming every gold standard has "interaction".
            interaction = t.get("interaction") or f"{t.get('dfd_source_id', '?')}->{t.get('dfd_destination_id', '?')}"
            add(f"[Gold threat #{t['id']}] {t['title']} ({t['threat_type']}, node {t['tree_node']}, "
                f"originator {t['originator_id']}, interaction {interaction}). "
                f"{t['description']} Assumptions: {t['assumptions']} "
                f"Severity {t['severity']}, Likelihood {t['likelihood']}.",
                section=f"threat #{t['id']} {t['title']}",
                meta={"kind": "gold_threat", "threat_id": t["id"], "threat_type": t["threat_type"],
                      "tree_node": t["tree_node"]})
    else:
        add(path.read_text(), section=doc, meta={"kind": "raw_json"})

    return chunks


DERIVED_SCENARIO_SUFFIX = "_derived"


def _is_derived_artifact(path: Path, directory: Path) -> bool:
    """True for anything under a scenario the adapter derived from source code.

    Derived scenarios are pipeline *output*, not curated knowledge-base content -- the same
    reasoning that already excludes dfd.json below, one level up. They live in
    knowledge_base/scenarios/ so they are committed and reviewable for reproducibility, but
    ingesting them would pollute the corpus the published numbers were measured on:
    kidstube_derived's gold is KidsTube's 41 threats re-anchored, so chunking it would add 41
    near-duplicate gold_threat chunks, shift TF-IDF idf across every term they contain, and
    double-weight KidsTube in `cli.py search --source scenarios`, `cli.py ask`, and
    tests/test_kb.py::test_retrieval_quality. (--rag generation already filters to
    source="linddun" with exclude_kinds=["gold_threat"], so the headline RAG ablation would have
    survived it -- but a silent corpus shift under everything else is not worth the risk.)
    """
    try:
        relative = path.relative_to(directory)
    except ValueError:
        return False
    return bool(relative.parts) and relative.parts[0].endswith(DERIVED_SCENARIO_SUFFIX)


def load_corpus() -> list[Chunk]:
    """Walk every configured corpus directory and chunk all supported files."""
    all_chunks: list[Chunk] = []
    for source, directory in config.CORPORA.items():
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_dir():
                continue
            if path.name == "dfd.json":
                continue  # generation-time structure only; not retrieval content (see generation/)
            if source == "scenarios" and _is_derived_artifact(path, directory):
                continue  # adapter output, not curated KB content -- see _is_derived_artifact()
            doc = str(path.relative_to(directory))
            if path.suffix.lower() in {".md", ".txt"}:
                all_chunks.extend(_split_markdown(path.read_text(), doc, source))
            elif path.suffix.lower() == ".json":
                all_chunks.extend(_split_json(path, doc, source))
            # other types (pdf, code) handled in later weeks
    return all_chunks


if __name__ == "__main__":
    chunks = load_corpus()
    print(f"Loaded {len(chunks)} chunks from {len(config.CORPORA)} corpora")
    from collections import Counter
    by_source = Counter(c.source for c in chunks)
    by_kind = Counter(c.meta.get("kind", "prose") for c in chunks)
    print("By source:", dict(by_source))
    print("By kind:", dict(by_kind))
