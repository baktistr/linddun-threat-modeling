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
                          dfd_path: Path | str | None = None,
                          model: str | None = None,
                          retrieval_backend: str | None = None,
                          concurrency: int | None = None,
                          stats: dict | None = None) -> list[GeneratedThreat]:
    """`dfd_path` overrides the scenario's own dfd.json.

    `concurrency` is how many flow calls to keep in flight (None = config.GENERATION_CONCURRENCY,
    which defaults to 1 = the historical serial behaviour). It changes only the order calls are
    ISSUED: threats are assembled in flow order either way, so the artifact is identical. Raising
    it matters against a self-hosted server, which bills wall-clock rather than tokens and
    otherwise idles between sequential calls.

    `stats`, when given, is filled in with run-level counts the returned list cannot carry --
    currently `malformed_dropped`/`malformed`, the threats the model emitted without a field its
    own tool schema marks required. That is a property of the MODEL, so it belongs in the run
    record next to citation validity, not in a log line that scrolls away.

    `retrieval_backend` overrides config.EMBEDDING_BACKEND for the two RAG modes only, so a sweep
    can vary the retriever per run the way `model` varies the deployment -- on the call rather
    than in the environment. Mutating config mid-process would leak into whatever ran next, which
    for a retrieval backend means a later run silently scoring against the wrong index. None
    (the default) keeps the configured backend, so every existing caller is unaffected.

    A multi-model experiment produces one DFD per (input, arm, model, run) and they cannot all
    live in one scenario directory. Without this override, comparing N models would mean minting
    N scenario directories -- turning knowledge_base/scenarios/ into an experiment log and
    duplicating each gold standard N times. The scenario is still named because it identifies the
    SYSTEM (and, for eval, its gold); only the DFD moves. See runs.py.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    dfd = json.loads(Path(dfd_path).read_text()) if dfd_path else _load_dfd(scenario)
    return generate_for_dfd(dfd, mode=mode, backend=get_llm_backend(provider, model),
                            progress=progress, retrieval_backend=retrieval_backend,
                            concurrency=concurrency, stats=stats)


def generate_for_dfd(dfd: dict, *, backend, mode: str = "grounded", progress: bool = False,
                     retrieval_backend: str | None = None, concurrency: int | None = None,
                     stats: dict | None = None, flow_ids: list[str] | None = None) -> list[GeneratedThreat]:
    """Shared CLI/service pipeline over a DFD object with an explicitly supplied model client.

    `flow_ids` limits calls for checkpointed workers while retaining the entire diagram as
    context. It never changes the order of flows. No scenario files or global credentials are
    changed. CLI defaults, prompt construction, and malformed-item accounting stay shared.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    selected = set(flow_ids) if flow_ids is not None else {f["id"] for f in dfd["flows"]}
    if selected - {f["id"] for f in dfd["flows"]}:
        raise ValueError("flow_ids contains an unknown flow")
    flow_stats: dict[str, dict] = {}
    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    # Only the two RAG modes need the retrieval index; the rest never touch it.
    retriever = None
    if mode in ("rag", "panoptic_rag"):
        from retrieval.index import Retriever
        retriever = Retriever.load(retrieval_backend)
    if retriever is not None and progress:
        # Which retriever produced a rag threat set is not recoverable from the saved
        # JSON (it is a bare list of threats, with no _meta), and the backend is
        # env-switchable. Naming it here puts it in the run log, so a rag artifact can
        # always be traced to the retriever that generated it.
        print(f"[rag] retrieving with '{retriever.backend.name}' over "
              f"{len(retriever.chunks)} chunks, k={config.TOP_K}", flush=True)
    # Only panoptic_grounded needs the full taxonomy; load once, not per flow.
    taxonomy = _load_panoptic_taxonomy() if mode == "panoptic_grounded" else None

    # Phase 1 -- build every flow's prompt, in flow order. Deliberately sequential: prompt
    # construction is local work (a mapping-table lookup or a BM25 search over 475 chunks), and
    # keeping it here means the retriever is only ever touched by one thread. `skip` carries the
    # reason a grounded flow was gated out, so phase 2 can print it at the point the serial loop
    # used to -- the run log stays in flow order whatever the concurrency.
    planned: list[tuple[dict, str | None, str | None]] = []   # (flow, prompt, skip_reason)
    for flow in dfd["flows"]:
        if flow["id"] not in selected:
            continue
        flow_stats[flow["id"]] = {"mode": mode}
        src = elements_by_id[flow["source"]]
        dst = elements_by_id[flow["destination"]]

        if mode == "grounded":
            ctx = get_interaction_context(effective_type(src), effective_type(dst))
            flow_stats[flow["id"]].update({"source_type": ctx.source_type, "destination_type": ctx.dest_type,
                                          "applicable_threats": ctx.applicable,
                                          "context_nodes": {tt: list(nodes) for tt, nodes in ctx.tree_nodes.items()}})
            if not ctx.valid:
                flow_stats[flow["id"]]["skipped"] = ctx.note
                planned.append((flow, None, "invalid interaction, no Process mediates"))
                continue
            prompt = build_grounded_prompt(flow, elements_by_id, ctx)
        elif mode == "rag":
            # No mapping-table gate here on purpose: RAG doesn't consult the deterministic table
            # at all, so (unlike grounded mode) it attempts every flow, same as ungrounded --
            # isolating "retrieved context vs. no context" as the only variable vs. ungrounded,
            # and "retrieved vs. deterministic context" as the only variable vs. grounded.
            query = build_flow_query(flow, elements_by_id)
            hits = retriever.search(query, k=config.TOP_K, source="linddun",
                                    exclude_kinds=config.RAG_EXCLUDE_KINDS)
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

        import hashlib
        flow_stats[flow["id"]].update({"prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
                                      "prompt_chars": len(prompt)})
        planned.append((flow, prompt, None))

    # Phase 2 -- issue the model calls. Flows are independent, so `workers` of them can be in
    # flight at once; results are still consumed in flow order below, which is what keeps the
    # saved artifact identical to the serial path's. workers=1 calls lazily inside that loop, so
    # the historical path is not merely equivalent but the same code doing the same thing in the
    # same order.
    workers = concurrency if concurrency is not None else config.GENERATION_CONCURRENCY
    workers = max(1, int(workers))
    payloads: dict[int, dict] = {}
    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor
        pending = [(i, p) for i, (_f, p, _s) in enumerate(planned) if p is not None]
        if progress and pending:
            print(f"[concurrency] {len(pending)} flow call(s), {workers} in flight", flush=True)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {i: pool.submit(backend.generate_threats, p) for i, p in pending}
        # .result() re-raises inside the with-block's join, so a failed flow still fails the run
        # rather than silently yielding an empty threat set -- same contract as the serial path.
        payloads = {i: f.result() for i, f in futures.items()}

    all_threats: list[GeneratedThreat] = []
    malformed: list[str] = []
    n_flows = len(dfd["flows"])
    for i, (flow, prompt, skip_reason) in enumerate(planned):
        tag = f"[{i + 1}/{n_flows}] {flow['id']}"
        if prompt is None:
            if progress:
                print(f"{tag}: skipped ({skip_reason})", flush=True)
            continue

        payload = payloads[i] if workers > 1 else backend.generate_threats(prompt)
        if not isinstance(payload, dict) or not isinstance(payload.get("threats"), list):
            raise ValueError("Model returned no valid threats array")
        n_before = len(all_threats)
        for t in payload["threats"]:
            if not isinstance(t, dict):
                malformed.append(f"{flow['id']}: threat entry is not an object")
                continue
            t = dict(t)
            t["flow_id"] = flow["id"]
            t["grounded"] = mode not in UNGROUNDED_MODES
            t["mode"] = mode
            try:
                all_threats.append(GeneratedThreat.from_dict(t))
            except TypeError as e:
                # A threat missing a field the tool schema marks `required`. Forced tool calling
                # was assumed to make this impossible and it does hold for the hosted deployments
                # -- but a locally served model can emit an object that omits threat_type, and
                # the whole run then died on one malformed item, discarding every flow already
                # paid for. Dropping the item is right (an entry with no threat_type is not an
                # answer), but dropping it SILENTLY is not: schema compliance is a property of
                # the model under test, so it is counted and surfaced rather than swallowed.
                malformed.append(f"{flow['id']}: {e}")
                continue
        flow_stats[flow["id"]].update({"candidates": len(all_threats) - n_before,
                                      "malformed_dropped": sum(m.startswith(f"{flow['id']}:") for m in malformed)})
        if progress:
            print(f"{tag}: {len(all_threats) - n_before} threat(s)", flush=True)

    if malformed:
        if progress:
            print(f"[schema] dropped {len(malformed)} malformed threat(s): "
                  f"{malformed[0]}" + (f" (+{len(malformed) - 1} more)" if len(malformed) > 1
                                       else ""), flush=True)
        if stats is not None:
            stats["malformed_dropped"] = len(malformed)
            stats["malformed"] = malformed
    elif stats is not None:
        stats["malformed_dropped"] = 0
        stats["malformed"] = []

    if stats is not None:
        stats["flows"] = flow_stats
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
