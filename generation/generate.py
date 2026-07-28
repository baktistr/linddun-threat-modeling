"""Threat generation driver.

For each DFD flow in a scenario's dfd.json, builds a prompt for one (framework, grounding)
combination and calls the LLM with a forced tool-use schema so the response parses directly into
GeneratedThreat objects -- no free-text parsing. See generation/prompt.py's module docstring for
the two frameworks (LINDDUN, PANOPTIC) and three grounding mechanisms (grounded/rag/ungrounded)
each supports.

`mode` composes framework x grounding: LINDDUN keeps its original bare names for backward
compatibility with every already-saved storage/generated/*.json -- "grounded"/"rag"/"ungrounded"
-- while PANOPTIC's three variants are prefixed: "panoptic_grounded"/"panoptic_rag"/
"panoptic_ungrounded". See resolve_mode().
"""
from __future__ import annotations
import json
from pathlib import Path

import config
from retrieval.interaction_context import get_interaction_context, effective_type
from retrieval.index import Retriever
from generation.schema import GeneratedThreat
from generation.prompt import (build_grounded_prompt, build_rag_prompt, build_ungrounded_prompt,
                               build_panoptic_prompt, build_panoptic_rag_prompt,
                               build_panoptic_ungrounded_prompt, build_flow_query)
from generation.llm_backend import get_llm_backend

GENERATED_DIR = config.ROOT / "storage" / "generated"
MODES = ("grounded", "rag", "ungrounded", "panoptic_grounded", "panoptic_rag", "panoptic_ungrounded")
UNGROUNDED_MODES = ("ungrounded", "panoptic_ungrounded")


def resolve_mode(rag: bool, ungrounded: bool, framework: str = "linddun") -> str:
    """CLI-flags -> mode name, shared by cli.py so the mutual-exclusivity rule lives in one place.

    --rag/--ungrounded select the grounding mechanism; --framework selects LINDDUN (default) or
    PANOPTIC -- orthogonal choices, unlike the three LINDDUN-only flags this replaced."""
    if rag and ungrounded:
        raise ValueError("--rag and --ungrounded are mutually exclusive.")
    if framework not in ("linddun", "panoptic"):
        raise ValueError(f"--framework must be 'linddun' or 'panoptic', got {framework!r}")
    grounding = "rag" if rag else ("ungrounded" if ungrounded else "grounded")
    return f"panoptic_{grounding}" if framework == "panoptic" else grounding


def _load_panoptic_taxonomy() -> dict:
    return json.loads((config.KB_DIR / "panoptic" / "taxonomy.json").read_text())


def _load_dfd(scenario: str) -> dict:
    return json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())


def generate_for_scenario(scenario: str, mode: str = "grounded", provider: str | None = None,
                          progress: bool = True,
                          dfd_path: Path | str | None = None) -> list[GeneratedThreat]:
    """`dfd_path` overrides the scenario's own dfd.json.

    A multi-model experiment produces one DFD per (input, arm, model, run) and they cannot all
    live in one scenario directory. Without this override, comparing N models would mean minting
    N scenario directories -- turning knowledge_base/scenarios/ into an experiment log and
    duplicating each gold standard N times. The scenario is still named because it identifies the
    SYSTEM (and, for eval, its gold); only the DFD moves. See runs.py.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")

    backend = get_llm_backend(provider)
    dfd = json.loads(Path(dfd_path).read_text()) if dfd_path else _load_dfd(scenario)
    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    # Only the two RAG modes need the vector index; the rest never touch it.
    retriever = Retriever.load() if mode in ("rag", "panoptic_rag") else None
    # Only panoptic_grounded needs the full taxonomy; load once, not per flow.
    taxonomy = _load_panoptic_taxonomy() if mode == "panoptic_grounded" else None

    all_threats: list[GeneratedThreat] = []
    n_flows = len(dfd["flows"])
    for i, flow in enumerate(dfd["flows"], 1):
        src = elements_by_id[flow["source"]]
        dst = elements_by_id[flow["destination"]]
        tag = f"[{i}/{n_flows}] {flow['id']}"

        if mode == "grounded":
            ctx = get_interaction_context(effective_type(src), effective_type(dst))
            if not ctx.valid:
                if progress:
                    print(f"{tag}: skipped (invalid interaction, no Process mediates)", flush=True)
                continue
            prompt = build_grounded_prompt(flow, elements_by_id, ctx)
        elif mode == "rag":
            # No mapping-table gate here on purpose: RAG doesn't consult the deterministic table
            # at all, so (unlike grounded mode) it attempts every flow, same as ungrounded --
            # isolating "retrieved context vs. no context" as the only variable vs. ungrounded,
            # and "retrieved vs. deterministic context" as the only variable vs. grounded.
            query = build_flow_query(flow, elements_by_id)
            hits = retriever.search(query, k=config.TOP_K, source="linddun",
                                    exclude_kinds=["gold_threat"])
            prompt = build_rag_prompt(flow, elements_by_id, hits)
        elif mode == "panoptic_grounded":
            # No gate here either, and for a different reason than rag's: PANOPTIC has no
            # Process-mediation restriction at all (see build_panoptic_prompt()'s docstring), so
            # there's no mapping-table-shaped concept of an "invalid" interaction to skip.
            prompt = build_panoptic_prompt(flow, elements_by_id, taxonomy)
        elif mode == "panoptic_rag":
            query = build_flow_query(flow, elements_by_id)
            hits = retriever.search(query, k=config.TOP_K, source="panoptic",
                                    exclude_kinds=["gold_threat"])
            prompt = build_panoptic_rag_prompt(flow, elements_by_id, hits)
        elif mode == "panoptic_ungrounded":
            prompt = build_panoptic_ungrounded_prompt(flow, elements_by_id)
        else:
            prompt = build_ungrounded_prompt(flow, elements_by_id)

        payload = backend.generate_threats(prompt)
        n_before = len(all_threats)
        for t in payload.get("threats", []):
            t = dict(t)
            t["flow_id"] = flow["id"]
            t["grounded"] = mode not in UNGROUNDED_MODES
            t["mode"] = mode
            all_threats.append(GeneratedThreat.from_dict(t))
        if progress:
            print(f"{tag}: {len(all_threats) - n_before} threat(s)", flush=True)

    return all_threats


def save_generated(scenario: str, mode: str, threats: list[GeneratedThreat],
                   out: Path | str | None = None) -> Path:
    """`out` overrides the flat `<scenario>_<mode>.json` name, for per-condition run output."""
    path = Path(out) if out else GENERATED_DIR / f"{scenario}_{mode}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([t.to_dict() for t in threats], indent=2))
    return path


def load_generated(path: Path | str) -> list[GeneratedThreat]:
    data = json.loads(Path(path).read_text())
    return [GeneratedThreat.from_dict(d) for d in data]
