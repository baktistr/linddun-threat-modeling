"""Where a multi-model experiment's artifacts live, and what identifies one.

The repo already separates *run artifacts* (many, cheap, kept for variance) from *promoted
scenarios* (few, committed, what published numbers cite). Until Week 12 the run tier had no place
for a re-anchored gold or for generated threats, and nothing anywhere carried the MODEL -- so a
second model silently overwrote the first, in both `storage/derived/` and `storage/generated/`.

This module fixes the identity, not the pipeline. A run is keyed by:

    scenario   the system being modelled          kidstube
    input      where the DFD came from            image | source
    arm        which adapter arm produced it      vision_naive | llm | llm_naive | facts_only
    model      the model that produced it         gpt-5-4 | claude-sonnet-5 | none
    run        which sample                       1, 2, 3, ...

    storage/derived/<scenario>/<condition>/run<n>/dfd.json
                                                 /gold.json     (only if flow ids moved)
    storage/generated/<scenario>/<condition>/run<n>/<mode>.json
                                                   /<mode>_eval.txt
                                          /summary.json         (aggregated across runs)

`run<n>` is part of the key from the START, never optional, and that is deliberate. The `llm`
arm's flow recall spans 0.33-0.87 across three runs of the SAME model, so a one-run-per-model
comparison would report sampling noise as a model difference. Anything that compares conditions
must aggregate over runs first; the layout makes doing it right the path of least resistance.

Nothing here migrates the Week 10-12 artifacts (`storage/derived/kidstube_llm_run1.json`,
`knowledge_base/scenarios/kidstube_derived/`). Those are grandfathered: their paths are cited by
committed eval reports, and rewriting them would make settled numbers look re-run.
"""
from __future__ import annotations
import re
from pathlib import Path

import config

DERIVED_ROOT = config.ROOT / "storage" / "derived"
GENERATED_ROOT = config.ROOT / "storage" / "generated"

NO_MODEL = "none"          # facts_only and any other arm with no model in the loop

INPUT_IMAGE = "image"
INPUT_SOURCE = "source"
INPUTS = (INPUT_IMAGE, INPUT_SOURCE)


def slug(value: str | None) -> str:
    """Path-safe form of a model or arm id.

    Model ids carry dots and slashes ("gpt-5.4", "anthropic/claude-sonnet-5"). Both are legal in
    filenames and both bite later -- dots in globs, slashes as directory separators. Normalise
    once, here, so a condition key is the same string everywhere it is written or parsed.
    """
    if not value:
        return NO_MODEL
    s = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return s or NO_MODEL


def condition(input_kind: str, arm: str, model: str | None) -> str:
    """The experimental condition, as one path segment: <input>_<arm>_<model>."""
    if input_kind not in INPUTS:
        raise ValueError(f"input must be one of {INPUTS}, got {input_kind!r}")
    return f"{input_kind}_{slug(arm)}_{slug(model)}"


def parse_condition(cond: str) -> dict:
    """Inverse of condition(). Used by the run index so it reads keys rather than re-deriving
    them from metadata that may be missing on older artifacts."""
    parts = cond.split("_")
    if len(parts) < 3:
        raise ValueError(f"not a condition key: {cond!r}")
    return {"input": parts[0], "arm": "_".join(parts[1:-1]), "model": parts[-1]}


def derived_dir(scenario: str, cond: str, run: int) -> Path:
    return DERIVED_ROOT / scenario / cond / f"run{run}"


def generated_dir(scenario: str, cond: str, run: int) -> Path:
    return GENERATED_ROOT / scenario / cond / f"run{run}"


def dfd_path(scenario: str, cond: str, run: int) -> Path:
    return derived_dir(scenario, cond, run) / "dfd.json"


def gold_path(scenario: str, cond: str, run: int) -> Path:
    return derived_dir(scenario, cond, run) / "gold.json"


def threats_path(scenario: str, cond: str, run: int, mode: str) -> Path:
    return generated_dir(scenario, cond, run) / f"{mode}.json"


def eval_path(scenario: str, cond: str, run: int, mode: str) -> Path:
    return generated_dir(scenario, cond, run) / f"{mode}_eval.txt"


def summary_path(scenario: str, cond: str) -> Path:
    return GENERATED_ROOT / scenario / cond / "summary.json"


def iter_runs(scenario: str | None = None):
    """Every (scenario, condition, run, dir) under the derived tree, sorted.

    Skips the grandfathered flat files (`storage/derived/kidstube_llm_run1.json`) -- they predate
    the layout and carry no condition key, so the index reports them separately rather than
    guessing which model produced them.
    """
    if not DERIVED_ROOT.exists():
        return
    for scen_dir in sorted(p for p in DERIVED_ROOT.iterdir() if p.is_dir()):
        if scenario and scen_dir.name != scenario:
            continue
        for cond_dir in sorted(p for p in scen_dir.iterdir() if p.is_dir()):
            for run_dir in sorted(p for p in cond_dir.iterdir()
                                  if p.is_dir() and p.name.startswith("run")):
                try:
                    n = int(run_dir.name[3:])
                except ValueError:
                    continue
                yield scen_dir.name, cond_dir.name, n, run_dir


def next_run(scenario: str, cond: str) -> int:
    """First unused run number for a condition, so a re-run never clobbers a sample."""
    existing = [n for s, c, n, _ in iter_runs(scenario) if c == cond]
    return max(existing, default=0) + 1
