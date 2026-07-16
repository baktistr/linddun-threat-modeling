"""Write a derived DFD out as a scenario directory the existing pipeline can consume unchanged.

Derived scenarios live in knowledge_base/scenarios/<name>_derived/ next to the hand-authored
ones, so `cli.py generate --scenario kidstube_derived` and `cli.py eval --scenario
kidstube_derived` work with no special-casing anywhere -- every command is already
--scenario-parameterised, and cli.py reads its choices off the filesystem.

They are committed rather than gitignored, because an adapter run is a claim about a codebase and
the artifact behind a published number should be reviewable in a diff. They are excluded from the
retrieval corpus (ingestion/loader.py::_is_derived_artifact) because they are pipeline output,
not curated knowledge-base content.

The `_derived` suffix is load-bearing in three places -- the loader's corpus skip, the emit guard
below, and a reader's expectations -- so it is enforced here rather than left to convention.
"""
from __future__ import annotations
import json
from pathlib import Path

import config
from adapters.schema import SCHEMA_VERSION, validate_dfd

DERIVED_SUFFIX = "_derived"


def scenario_dir(scenario: str) -> Path:
    return config.KB_DIR / "scenarios" / scenario


def emit_scenario_dfd(scenario: str, dfd: dict, derived_from: dict,
                      purpose: str = "") -> Path:
    """Validate and write knowledge_base/scenarios/<scenario>/dfd.json.

    Refuses to write anywhere but a *_derived scenario. The four hand-authored DFDs are the
    evaluation's ground truth and the thing the adapter is scored against; a tool that can
    overwrite its own answer key is one typo away from silently scoring itself against its own
    output. The guard is cheap and the failure it prevents is unrecoverable.

    Validates before writing, not after: an invalid DFD should never reach disk, because the next
    reader has no way to tell a half-written experiment from a real scenario.
    """
    if not scenario.endswith(DERIVED_SUFFIX):
        raise ValueError(
            f"refusing to emit to scenario {scenario!r}: adapters may only write to *{DERIVED_SUFFIX} "
            f"scenarios. The hand-authored DFDs are ground truth and are never overwritten.")

    errors = validate_dfd(dfd)
    if errors:
        raise ValueError("derived DFD violates the canonical schema; refusing to write:\n  "
                         + "\n  ".join(errors))

    dfd = dict(dfd)
    dfd["_meta"] = {**dfd.get("_meta", {}),
                    "schema_version": SCHEMA_VERSION,
                    "derived_from": derived_from}
    if purpose:
        dfd["_meta"]["purpose"] = purpose

    ordered = {"_meta": dfd["_meta"], "elements": dfd["elements"], "flows": dfd["flows"]}
    if dfd.get("trust_boundaries"):
        ordered["trust_boundaries"] = dfd["trust_boundaries"]

    path = scenario_dir(scenario) / "dfd.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ordered, indent=2) + "\n")
    return path


def emit_scenario_gold(scenario: str, gold: dict) -> Path:
    """Write a derived scenario's re-anchored gold standard. Same *_derived guard, same reason."""
    if not scenario.endswith(DERIVED_SUFFIX):
        raise ValueError(f"refusing to emit gold to scenario {scenario!r}: adapters may only "
                         f"write to *{DERIVED_SUFFIX} scenarios.")
    path = scenario_dir(scenario) / "gold_standard_threats.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(gold, indent=2) + "\n")
    return path
