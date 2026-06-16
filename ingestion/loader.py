"""Ingestion: load knowledge-base documents and split them into retrievable chunks.

Handles Markdown/text (split on headings then size) and JSON (structured items
become individual chunks so each threat-tree node / threat / regulation is
independently retrievable). Every chunk carries metadata for filtering and citation.
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
    source: str          # corpus tag: linddun | regulations | scenarios
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
    elif "threats" in data:  # gold_standard_threats.json
        for t in data["threats"]:
            add(f"[Gold threat #{t['id']}] {t['title']} ({t['threat_type']}, node {t['tree_node']}, "
                f"originator {t['originator_id']}, interaction {t['interaction']}). "
                f"{t['description']} Assumptions: {t['assumptions']} "
                f"Severity {t['severity']}, Likelihood {t['likelihood']}.",
                section=f"threat #{t['id']} {t['title']}",
                meta={"kind": "gold_threat", "threat_id": t["id"], "threat_type": t["threat_type"],
                      "tree_node": t["tree_node"]})
    else:
        add(path.read_text(), section=doc, meta={"kind": "raw_json"})

    return chunks


def load_corpus() -> list[Chunk]:
    """Walk every configured corpus directory and chunk all supported files."""
    all_chunks: list[Chunk] = []
    for source, directory in config.CORPORA.items():
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_dir():
                continue
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
