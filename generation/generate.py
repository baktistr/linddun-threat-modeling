"""Threat generation driver.

For each DFD flow in a scenario's dfd.json, builds a grounded (interaction-context) or ungrounded
(ablation baseline) prompt and calls Claude with a forced tool-use schema so the response parses
directly into GeneratedThreat objects -- no free-text parsing.
"""
from __future__ import annotations
import json
from pathlib import Path

import config
from retrieval.interaction_context import get_interaction_context, effective_type
from generation.schema import GeneratedThreat
from generation.prompt import build_grounded_prompt, build_ungrounded_prompt
from generation.llm_backend import get_llm_backend

GENERATED_DIR = config.ROOT / "storage" / "generated"


def _load_dfd(scenario: str) -> dict:
    return json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())


def generate_for_scenario(scenario: str, grounded: bool = True, provider: str | None = None,
                          progress: bool = True) -> list[GeneratedThreat]:
    backend = get_llm_backend(provider)
    dfd = _load_dfd(scenario)
    elements_by_id = {e["id"]: e for e in dfd["elements"]}

    all_threats: list[GeneratedThreat] = []
    n_flows = len(dfd["flows"])
    for i, flow in enumerate(dfd["flows"], 1):
        src = elements_by_id[flow["source"]]
        dst = elements_by_id[flow["destination"]]
        tag = f"[{i}/{n_flows}] {flow['id']}"

        if grounded:
            ctx = get_interaction_context(effective_type(src), effective_type(dst))
            if not ctx.valid:
                if progress:
                    print(f"{tag}: skipped (invalid interaction, no Process mediates)", flush=True)
                continue
            prompt = build_grounded_prompt(flow, elements_by_id, ctx)
        else:
            prompt = build_ungrounded_prompt(flow, elements_by_id)

        payload = backend.generate_threats(prompt)
        n_before = len(all_threats)
        for t in payload.get("threats", []):
            t = dict(t)
            t["flow_id"] = flow["id"]
            t["grounded"] = grounded
            all_threats.append(GeneratedThreat.from_dict(t))
        if progress:
            print(f"{tag}: {len(all_threats) - n_before} threat(s)", flush=True)

    return all_threats


def save_generated(scenario: str, grounded: bool, threats: list[GeneratedThreat]) -> Path:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    suffix = "grounded" if grounded else "ungrounded"
    path = GENERATED_DIR / f"{scenario}_{suffix}.json"
    path.write_text(json.dumps([t.to_dict() for t in threats], indent=2))
    return path


def load_generated(path: Path | str) -> list[GeneratedThreat]:
    data = json.loads(Path(path).read_text())
    return [GeneratedThreat.from_dict(d) for d in data]
