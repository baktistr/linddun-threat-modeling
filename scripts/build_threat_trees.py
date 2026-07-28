#!/usr/bin/env python3
"""Transcribe the OFFICIAL LINDDUN threat trees (v241203) into threat_trees.json.

This closes a debt opened in Week 1. WEEK1_REPORT.md said the v0.1 PRO tutorial "prints full trees
only for Linking, Data Disclosure, and Detecting; the other four types are given as type
definitions", encoded I/Nr/U/Nc as *approximated* top-level nodes, and scheduled replacement with
"the official complete trees from the LINDDUN website" as "a one-session transcription task for
Week 2". It was never done, and by Week 12 every citation-validity number in the project was being
measured against a tree its own author had marked incomplete.

The official per-type trees are now bundled at references/linddun-trees/v241203/, and this script
parses them rather than anyone re-typing 60 nodes. Re-runnable: drop a newer version in, change
VERSION, re-run, diff.

PDF LAYOUT. One page per type, text in reading order:

    <Type name>
    <type description>
    <NODE ID>                     e.g. "Nr.1.3", "DD.4.1.1" -- on its own line
    <title>                       may be hyphen-wrapped across lines: "evi-" / "dence"
    <description>
    Examples | Criteria | Impact | Additional Info      (optional, any subset, in this order)
    <content>
    <NEXT NODE ID>
    ...

Within Examples/Impact/Additional Info the items are "Name: text" pairs; Criteria items are bare
questions. Hyphenation is undone by joining a line ending in "-" to the next.

ONE DELIBERATE DEVIATION. The official notation for Data Disclosure is `DD.*`; this project has
used `Dd.*` since Week 1, and it is baked into six gold standards and twelve generated threat
sets. The ids are rewritten to `Dd.*` on the way in and the deviation is recorded in _meta, so a
later migration is a single decision rather than an archaeology exercise. Nothing else is altered.

Run: PYTHONPATH=. python3 scripts/build_threat_trees.py [--dry-run]
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config

VERSION = "v241203"
PDF_DIR = config.ROOT / "references" / "linddun-trees" / VERSION
OUT = config.KB_DIR / "linddun" / "threat_trees.json"

# file stem -> (official prefix, our prefix, full type name)
TYPES = [
    ("Linking",                         "L",  "L",  "Linking"),
    ("Identifying",                     "I",  "I",  "Identifying"),
    ("Nonrepudiation",                  "Nr", "Nr", "Non-repudiation"),
    ("Detecting",                       "D",  "D",  "Detecting"),
    ("DataDisclosure",                  "DD", "Dd", "Data Disclosure"),
    ("UnawarenessandUnintervenability", "U",  "U",  "Unawareness and Unintervenability"),
    ("Noncompliance",                   "Nc", "Nc", "Non-compliance"),
]

SECTIONS = ("Examples", "Criteria", "Impact", "Additional Info")
SECTION_KEY = {"Examples": "examples", "Criteria": "criteria",
               "Impact": "impact", "Additional Info": "additional_info"}


def dehyphenate(lines: list[str]) -> list[str]:
    """Join "evi-" + "dence" -> "evidence". The PDFs wrap inside words in narrow columns."""
    out: list[str] = []
    for ln in lines:
        if out and out[-1].endswith("-") and ln and ln[0].islower():
            out[-1] = out[-1][:-1] + ln
        else:
            out.append(ln)
    return out


def flow(lines: list[str]) -> str:
    return " ".join(dehyphenate(lines)).strip()


def split_items(lines: list[str]) -> list[dict]:
    """"Name: text" pairs, each possibly spanning several lines. A line whose text before the
    first ':' looks like a label starts a new item; everything else continues the current one."""
    text = flow(lines)
    if not text:
        return []
    parts = re.split(r"(?<=[.?!])\s+(?=[A-Z][^:]{0,60}:)", text)
    items = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        m = re.match(r"^([^:]{1,80}):\s*(.+)$", p, re.S)
        items.append({"name": m.group(1).strip(), "text": m.group(2).strip()} if m
                     else {"name": "", "text": p})
    return items


def parse_type(pdf: Path, official: str, ours: str, name: str) -> tuple[dict, str]:
    import fitz
    with fitz.open(pdf) as doc:
        raw = "\n".join(pg.get_text() for pg in doc)
    lines = [l.rstrip() for l in raw.splitlines()]
    node_re = re.compile(rf"^{re.escape(official)}(\.\d+)+$")

    starts = [i for i, l in enumerate(lines) if node_re.match(l.strip())]
    if not starts:
        raise SystemExit(f"{pdf.name}: no node ids matched prefix {official!r}")
    type_desc = flow([l for l in lines[1:starts[0]] if l.strip()])

    nodes: dict[str, dict] = {}
    for k, s in enumerate(starts):
        end = starts[k + 1] if k + 1 < len(starts) else len(lines)
        block = [l.strip() for l in lines[s + 1:end]]
        nid = ours + lines[s].strip()[len(official):]

        # split the block into the head (title + description) and the labelled sections
        idx = {}
        for sec in SECTIONS:
            if sec in block:
                idx[sec] = block.index(sec)
        first = min(idx.values()) if idx else len(block)
        head = [l for l in block[:first] if l]

        # The title is the first sentence-ish run; the description is the rest. The PDFs put the
        # title on its own (possibly hyphen-wrapped) line group, then the description.
        joined = dehyphenate(head)
        title = joined[0] if joined else ""
        # a wrapped title continues while the next line starts lowercase AND the current does not
        # already end a sentence
        di = 1
        while di < len(joined) and not title.endswith(".") and joined[di][:1].islower():
            title += " " + joined[di]
            di += 1
        node = {"title": title.strip(), "description": flow(joined[di:])}

        ordered = sorted(idx.items(), key=lambda kv: kv[1])
        for j, (sec, at) in enumerate(ordered):
            stop = ordered[j + 1][1] if j + 1 < len(ordered) else len(block)
            body = [l for l in block[at + 1:stop] if l]
            if sec == "Criteria":
                node["criteria"] = [c["text"] if not c["name"] else f"{c['name']}: {c['text']}"
                                    for c in split_items(body)]
            else:
                node[SECTION_KEY[sec]] = split_items(body)
        nodes[nid] = node
    return {"name": name, "description": type_desc, "nodes": nodes}, type_desc


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    old = json.loads(OUT.read_text())["threat_types"] if OUT.exists() else {}
    types = {}
    for stem, official, ours, name in TYPES:
        pdf = PDF_DIR / f"{stem}.pdf"
        if not pdf.exists():
            raise SystemExit(f"missing {pdf} -- download the official trees first")
        types[ours], _ = parse_type(pdf, official, ours, name)
        n_ex = sum(len(v.get("examples", [])) for v in types[ours]["nodes"].values())
        was = set(old.get(ours, {}).get("nodes", {}))
        now = set(types[ours]["nodes"])
        print(f"  {ours:3} {len(now):>3} nodes  {n_ex:>3} examples"
              f"   +{len(now - was)} new  -{len(was - now)} dropped")
        if now - was:
            print(f"      added   : {sorted(now - was)}")
        if was - now:
            print(f"      REMOVED : {sorted(was - now)}  (in our reconstruction, not official)")

    doc = {
        "_meta": {
            "source": f"Official LINDDUN threat trees, full version {VERSION}",
            "source_url": "https://downloads.linddun.org/linddun-trees/tree-full/"
                          f"{VERSION}/<Type>.pdf",
            "source_files": f"references/linddun-trees/{VERSION}/ (bundled)",
            "citation": "DistriNet, KU Leuven. LINDDUN threat trees (full), version "
                        f"{VERSION}. https://linddun.org",
            "built_by": "scripts/build_threat_trees.py",
            "note": "Transcribed mechanically from the official per-type tree PDFs -- every node, "
                    "with its title, description, examples, criteria, impact and additional info. "
                    "This REPLACES the Week 1 encoding, in which only L/Dd/D came from printed "
                    "trees and I/Nr/U/Nc were approximated from type definitions (WEEK1_REPORT.md "
                    "flagged that as a Week 2 task; it was still open in Week 12). Citation-"
                    "validity numbers from before this rebuild were measured against the "
                    "incomplete tree and are not comparable to numbers measured after it.",
            "id_convention": "Official notation, with ONE deviation: Data Disclosure nodes are "
                             "written Dd.* here, not the official DD.*. That spelling has been in "
                             "use since Week 1 and is baked into six gold standards and twelve "
                             "generated threat sets; it is preserved to avoid a migration this "
                             "rebuild does not need. Every other id is verbatim.",
        },
        "threat_types": types,
    }
    total = sum(len(t["nodes"]) for t in types.values())
    ex = sum(len(v.get("examples", [])) for t in types.values() for v in t["nodes"].values())
    print(f"\n  TOTAL {total} nodes, {ex} examples "
          f"(was {sum(len(t.get('nodes', {})) for t in old.values())} nodes)")
    if args.dry_run:
        print("  (dry run -- nothing written)")
        return
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    print(f"  wrote {OUT}")


if __name__ == "__main__":
    main()
