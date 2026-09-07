"""Fuse source-code evidence into an already-derived DFD -- the enrichment stage.

Week 12 measured the image adapter's split personality: structure survives the modality nearly
intact (17/17 flow ids on KidsTube), but flow descriptions come back ~60% thinner, because a
diagram's edge label never carried the field enumerations dfd.json holds -- and descriptions feed
generation/prompt.py directly. The source adapter has the OPPOSITE profile: rich data semantics,
broken structure (its own granularity; the gold cannot anchor). This stage tests whether those
failure modes are complementary: keep the DFD whose STRUCTURE is trusted (hand-authored, or
image-derived with ids intact) and layer on the SEMANTICS only code carries.

Two invariants govern everything here:

  * STRUCTURE IS READ-ONLY. Elements, ids, and endpoints are never touched; a flow description
    only ever GROWS, with the original text preserved as its prefix. An enriched image DFD
    therefore still reproduces the hand DFD's flow ids, the hand gold applies verbatim
    (denominator 41/41), and any score difference is attributable to the added semantics alone.

  * ENRICHMENT NEVER WRITES INTO provenance. provenance answers "where did this flow come from"
    (bbox for the image arm, nothing for the hand DFD), and schema.py holds each entry to exactly
    one citation vocabulary. Enrichment evidence lives under flow["enrichment"] instead -- a
    fact_id in provenance would also flip build_kidstube_derived_gold.cites_code_facts() to True
    and silently reroute gold resolution from the identity path to fact-id re-anchoring, changing
    the DENOMINATOR of every score this experiment exists to compare.

Three arms, mirroring the source adapter's ladder rung for rung:

  enrich_facts      deterministic token overlap between a fact's content and a flow's endpoints
                    and description. No LLM anywhere. Crude on purpose: it is the bar the llm arm
                    has to clear, not the proposal.
  enrich_llm        one call; the model maps facts to flows citing the CLOSED fact-id vocabulary.
                    An enrichment citing no resolvable fact is dropped (_accept_enrichments) --
                    the same discipline as synthesize.py's _accept_flows, "don't hallucinate" as
                    an invariant rather than an instruction.
  enrich_llm_naive  one call over RAW SOURCE, citing an OPEN {file, line} vocabulary the model
                    locates itself. No fact list, no closed vocabulary, and deliberately no
                    confabulation guard -- see _accept_enrichments_naive.

Why the third arm exists. The project's claim is that a closed vocabulary makes citation validity
1.00 BY CONSTRUCTION, and that an open vocabulary is the ablation showing what the closure buys.
synthesize.py measures exactly that (llm vs llm_naive). Until this arm, enrichment did not: the
fusion result was reported at citation 1.00 with no open-vocabulary counterpart, so the number was
guaranteed rather than earned.

It also removes a limitation the closed arms cannot. extract.py's patterns are matched to
Express/Mongoose/React idioms and its file discovery globs *.js, so both closed arms are twice
constrained -- by framework AND by language. This arm reads text, so it inherits neither: it
discovers files through extract.source_files_any() across ~30 suffixes, which is what makes
enrichment applicable to a system this repo has no parser for. What it gives up in exchange is the
guarantee; that trade is the measurement (naive_citation_validity).

verify_enrichment() re-derives both invariants and every citation against the artifacts, with no
model in the loop, so an enrichment run carries the same style of deterministic verification
report as every other arm in this repo.
"""
from __future__ import annotations

import copy
import re

from adapters.schema import CodeFact
from adapters.synthesize import render_facts

MODE_ENRICH_FACTS = "enrich_facts"
MODE_ENRICH_LLM = "enrich_llm"
MODE_ENRICH_LLM_NAIVE = "enrich_llm_naive"
ENRICH_ARMS = (MODE_ENRICH_FACTS, MODE_ENRICH_LLM, MODE_ENRICH_LLM_NAIVE)
# The arms that read source through a model, so callers can ask "does this need a source root or
# a fact list?" without hard-coding the arm names.
NAIVE_ARMS = (MODE_ENRICH_LLM_NAIVE,)

ENRICH_MAX_TOKENS = 8000
# Raw source is bulk where a fact list is a summary: KidsTube's 492 facts render to ~40k chars,
# its source to several times that, and a larger repo does not fit any context window at all. The
# budget is therefore explicit and its consequences are REPORTED rather than silently absorbed --
# an arm that quietly dropped half a repository would produce thin enrichments that look like a
# model failure. Files are included in sorted order until the budget is spent, and every omission
# is recorded in _meta so coverage is a number in the report, not an assumption.
SOURCE_MAX_CHARS = 600_000
# The deterministic arm attaches at most this many facts per flow. More would bury the original
# description under boilerplate; the arm is a bar, not a proposal, and a low cap keeps it honest
# about being one.
FACTS_ARM_MAX_PER_FLOW = 4
# Appended enrichment is delimited so "description only ever grows" is checkable byte-for-byte
# and a reader can always see where the derived text ends and the fused evidence begins.
MARKER = " [code: "


ENRICH_TOOL_SCHEMA = {
    "name": "emit_flow_enrichments",
    "description": "Per-flow notes on what data moves, grounded in the extracted code facts.",
    "input_schema": {
        "type": "object",
        "properties": {
            "enrichments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "flow_id": {"type": "string",
                                    "description": "An id from the FLOWS list. Never invent one."},
                        "data_note": {"type": "string",
                                      "description": "What DATA the cited facts show moving: "
                                                     "field names, identifiers, credentials, "
                                                     "media. 'registration payload (email, "
                                                     "password, government-ID image)' beats "
                                                     "'user data'."},
                        "fact_ids": {"type": "array", "items": {"type": "string"},
                                     "description": "Ids from the CODE FACTS list evidencing "
                                                    "THIS flow's payload or endpoints. At least "
                                                    "one; never an id not in the list."},
                    },
                    "required": ["flow_id", "data_note", "fact_ids"],
                },
            },
        },
        "required": ["enrichments"],
    },
}


_ENRICH_PROMPT = """\
You are ENRICHING an existing Data Flow Diagram for LINDDUN Pro privacy threat modeling. The
DFD's structure is fixed and is NOT yours to change. Your only job: for each flow, say what DATA
moves across it -- field names, identifiers, credentials, media -- using DETERMINISTICALLY
EXTRACTED CODE FACTS as the only evidence. You are not reading the source; you are reading facts
a parser produced from it, and each fact id is citable.

CODE FACTS:
{facts}

FLOWS (fixed -- enrich these; never add, remove, or rename one):
{flows}

Rules:
- flow_id MUST be an id from the FLOWS list above. Never invent one.
- fact_ids MUST come from the CODE FACTS list, at least one per enrichment, and the cited facts
  must actually evidence THIS flow's payload or endpoints -- not some other edge's.
- data_note states what the cited facts show moving. Do not restate what the flow's description
  already says; add what the code knows and the diagram could not.
- Skip a flow no fact evidences. Silence is correct there; a guess is not.

Respond using the emit_flow_enrichments tool.\
"""


ENRICH_NAIVE_TOOL_SCHEMA = {
    "name": "emit_flow_enrichments",
    "description": "Per-flow notes on what data moves, grounded in source you locate yourself.",
    "input_schema": {
        "type": "object",
        "properties": {
            "enrichments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "flow_id": {"type": "string",
                                    "description": "An id from the FLOWS list. Never invent one."},
                        "data_note": {"type": "string",
                                      "description": "What DATA the cited source shows moving: "
                                                     "field names, identifiers, credentials, "
                                                     "media. 'registration payload (email, "
                                                     "password, government-ID image)' beats "
                                                     "'user data'."},
                        "citations": {
                            "type": "array",
                            "description": "The one or two most decisive {file, line} locations "
                                           "in the source above evidencing THIS flow's payload.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "file": {"type": "string",
                                             "description": "Path exactly as shown after '--- '."},
                                    "line": {"type": "integer",
                                             "description": "Line number as shown in the gutter."},
                                },
                                "required": ["file", "line"],
                            },
                        },
                    },
                    "required": ["flow_id", "data_note", "citations"],
                },
            },
        },
        "required": ["enrichments"],
    },
}


# The single variable separating this prompt from _ENRICH_PROMPT: the model reads RAW SOURCE and
# self-reports {file, line} instead of reading a parser's fact list and picking an id from a closed
# vocabulary. The task, the structure-is-fixed framing, the "skip a flow with no evidence" rule and
# the data_note guidance are held identical, so a difference in the numbers is attributable to the
# citation vocabulary rather than to prompt drift -- the same discipline synthesize.py holds
# between its `llm` and `llm_naive` arms.
_ENRICH_PROMPT_NAIVE = """\
You are ENRICHING an existing Data Flow Diagram for LINDDUN Pro privacy threat modeling. The
DFD's structure is fixed and is NOT yours to change. Your only job: for each flow, say what DATA
moves across it -- field names, identifiers, credentials, media -- reading the SOURCE CODE below
directly. Every file is shown with its line numbers, and you cite evidence as a {{file, line}}
location you locate yourself. There is no pre-extracted fact list and no id vocabulary.

SOURCE (path, then line-numbered contents):
{source}

FLOWS (fixed -- enrich these; never add, remove, or rename one):
{flows}

Rules:
- flow_id MUST be an id from the FLOWS list above. Never invent one.
- citations are {{file, line}} pairs pointing at the source above. Cite the line where the
  evidence actually lives -- the handler that reads or writes, the payload being assembled, the
  persistence call. Cite the one or two most decisive locations, not every line involved.
- A cited location must evidence THIS flow's payload or endpoints -- not some other edge's.
- data_note states what the cited source shows moving. Do not restate what the flow's description
  already says; add what the code knows and the diagram could not.
- Skip a flow the source does not evidence. Silence is correct there; a guess is not.

Respond using the emit_flow_enrichments tool.\
"""


def render_source_any(source_root, max_chars: int = SOURCE_MAX_CHARS) -> tuple[str, list[str]]:
    """(line-numbered source block, files omitted for budget).

    Deliberately NOT adapters.synthesize.render_source: that one discovers files through
    extract.source_files(), which globs *.js because everything downstream of it parses
    JavaScript. Inheriting a parser's suffix filter in an arm that never parses would leave this
    arm JS-only -- pattern-independent but still language-locked, which is exactly the limitation
    it exists to remove.

    Line numbers are shown for the same reason the naive synthesis arm shows them: the closed arm
    hands the model fact ids on a plate, so the fair open-vocabulary analogue hands it line
    numbers on a plate and still lets it point anywhere. A citation that then fails to resolve is
    genuine misattribution rather than the model miscounting lines it could not see.
    """
    from pathlib import Path

    from adapters.extract import source_files_any

    root = Path(source_root)
    blocks, omitted, used = [], [], 0
    for path in source_files_any(root):
        rel = str(path.relative_to(root)).replace("\\", "/")
        text = path.read_text(errors="replace")
        numbered = "\n".join(f"{i:5}| {line}" for i, line in enumerate(text.splitlines(), 1))
        block = f"--- {rel}\n{numbered}"
        if used + len(block) > max_chars:
            omitted.append(rel)
            continue
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks), omitted


def _render_flows(dfd: dict) -> str:
    els = {e["id"]: e for e in dfd["elements"]}

    def name(eid: str) -> str:
        return els.get(eid, {}).get("name", eid)

    return "\n".join(f"  {f['id']:6} {name(f['source'])} -> {name(f['destination'])}: "
                     f"{f.get('description', '')}" for f in dfd["flows"])


def _accept_enrichments(raw: list[dict], flow_ids: set[str],
                        fact_ids: set[str]) -> tuple[dict[str, dict], list[str]]:
    """Keep only enrichments naming a real flow and citing the closed vocabulary.

    Returns ({flow_id: {"data_note", "fact_ids"}}, rejections). Same shape of guard as
    synthesize.py's _accept_flows: an entry citing zero resolvable facts is dropped, not
    kept-with-a-warning, so fused text can never enter a description without evidence behind it.
    """
    kept: dict[str, dict] = {}
    rejected: list[str] = []
    for e in raw:
        fid = e.get("flow_id")
        if fid not in flow_ids:
            rejected.append(f"{fid or '<no flow_id>'}: not a flow in this DFD")
            continue
        if fid in kept:
            rejected.append(f"{fid}: duplicate enrichment")
            continue
        note = (e.get("data_note") or "").strip()
        if not note:
            rejected.append(f"{fid}: empty data_note")
            continue
        cited = [c for c in (e.get("fact_ids") or []) if c in fact_ids]
        if not cited:
            rejected.append(f"{fid}: cites no resolvable fact "
                            f"(claimed {e.get('fact_ids') or []})")
            continue
        kept[fid] = {"data_note": note, "fact_ids": cited}
    return kept, rejected


def _accept_enrichments_naive(raw: list[dict], flow_ids: set[str]) -> tuple[dict[str, dict],
                                                                          list[str]]:
    """Keep enrichments naming a real flow. Citations are cleaned but NEVER used to drop one.

    Two guards, and the difference between them is the experiment:

      * flow_id must be a real flow, and the original description is still preserved as a prefix
        upstream. Those are the structure-read-only invariant, which is arm-independent -- an
        enrichment inventing a flow would corrupt the DFD whatever vocabulary it cites in.

      * a citation that resolves to nothing does NOT drop the enrichment, unlike the closed arm's
        _accept_enrichments. That guard is what makes closed-vocabulary citation validity ~1.00
        by construction, so applying it here would manufacture the very number this arm exists to
        measure. Malformed entries (no file, non-integer line) are dropped so the artifact stays
        schema-valid, but an enrichment citing a file that does not exist is kept, written, and
        counted against citation validity by verify_enrichment().
    """
    kept: dict[str, dict] = {}
    rejected: list[str] = []
    for e in raw:
        fid = e.get("flow_id")
        if fid not in flow_ids:
            rejected.append(f"{fid or '<no flow_id>'}: not a flow in this DFD")
            continue
        if fid in kept:
            rejected.append(f"{fid}: duplicate enrichment")
            continue
        note = (e.get("data_note") or "").strip()
        if not note:
            rejected.append(f"{fid}: empty data_note")
            continue
        cites = []
        for c in (e.get("citations") or []):
            if not isinstance(c, dict):
                continue
            file, line = c.get("file"), c.get("line")
            if not isinstance(file, str) or not file.strip():
                continue
            try:
                cites.append({"file": file.strip(), "line": int(line)})
            except (TypeError, ValueError):
                continue
        kept[fid] = {"data_note": note, "citations": cites}
    return kept, rejected


# --------------------------------------------------------------------------------------------
# enrich_facts -- the deterministic bar
# --------------------------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
# Only connective noise. Domain words ("user", "video") stay in: the arm's crudeness is the
# point, and a curated stoplist would smuggle judgment into a stage sold as judgment-free.
_STOP = {"the", "and", "for", "with", "from", "into", "that", "this", "http", "https", "api"}


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(text.lower())} - _STOP


def _fact_phrase(f: CodeFact) -> str:
    """A compact, deterministic rendering for description text: construct + its fields."""
    fields = ", ".join(f"{k}={v}" for k, v in f.fields.items()
                       if v not in (None, []) and k != "from_fact_id")
    phrase = f"{f.construct}({fields})" if fields else f.construct
    return phrase if len(phrase) <= 110 else phrase[:107] + "..."


def _match_deterministic(dfd: dict, facts: list[CodeFact]) -> tuple[dict[str, dict], list[str]]:
    """Token overlap between fact content and flow context. No LLM, no thresholds tuned per
    scenario: a fact attaches when at least two of its tokens appear in the flow's endpoint
    names or description, top FACTS_ARM_MAX_PER_FLOW by (overlap, id) for determinism."""
    els = {e["id"]: e for e in dfd["elements"]}
    fact_tok = [(f, _tokens(f"{f.construct} {f.file} "
                            + " ".join(f"{k} {v}" for k, v in f.fields.items())))
                for f in facts]
    kept: dict[str, dict] = {}
    for fl in dfd["flows"]:
        ctx = _tokens(f"{els.get(fl['source'], {}).get('name', '')} "
                      f"{els.get(fl['destination'], {}).get('name', '')} "
                      f"{fl.get('description', '')}")
        scored = sorted(((len(tok & ctx), f) for f, tok in fact_tok if len(tok & ctx) >= 2),
                        key=lambda p: (-p[0], p[1].id))
        top = [f for _, f in scored[:FACTS_ARM_MAX_PER_FLOW]]
        if top:
            kept[fl["id"]] = {"data_note": "; ".join(_fact_phrase(f) for f in top),
                              "fact_ids": [f.id for f in top]}
    return kept, []


# --------------------------------------------------------------------------------------------
# The stage
# --------------------------------------------------------------------------------------------

def enrich_dfd(dfd: dict, facts: list[CodeFact], arm: str = MODE_ENRICH_LLM,
               provider: str | None = None, model: str | None = None,
               verbose: bool = True, source_root=None, backend=None,
               source_max_chars: int = SOURCE_MAX_CHARS) -> dict:
    """Returns a NEW dfd dict; the input is never mutated. See the module docstring for the two
    invariants this function exists to hold.

    `source_root` is required by (and only used by) the naive arm, which reads raw source instead
    of a fact list; `facts` is ignored there and may be empty. Keeping both parameters rather than
    overloading one means a caller cannot accidentally hand a fact list to the arm whose entire
    premise is not having one.
    """
    if arm not in ENRICH_ARMS:
        raise ValueError(f"arm must be one of {ENRICH_ARMS}, got {arm!r}")
    if arm in NAIVE_ARMS and source_root is None:
        raise ValueError(f"arm {arm!r} reads raw source and requires source_root=")

    out = copy.deepcopy(dfd)
    flow_ids = {f["id"] for f in out["flows"]}
    fact_ids = {f.id for f in facts}
    omitted: list[str] = []

    if arm == MODE_ENRICH_FACTS:
        accepted, rejected = _match_deterministic(out, facts)
        backend_name = model_name = "none"          # deterministic: explicitly no model
    elif arm == MODE_ENRICH_LLM_NAIVE:
        from generation.llm_backend import get_llm_backend
        backend = backend if backend is not None else get_llm_backend(provider, model)
        source, omitted = render_source_any(source_root, max_chars=source_max_chars)
        prompt = _ENRICH_PROMPT_NAIVE.format(source=source, flows=_render_flows(out))
        raw = backend.call_tool(prompt, ENRICH_NAIVE_TOOL_SCHEMA,
                                max_tokens=ENRICH_MAX_TOKENS).get("enrichments", [])
        accepted, rejected = _accept_enrichments_naive(raw, flow_ids)
        backend_name, model_name = backend.name, backend.model
    else:
        from generation.llm_backend import get_llm_backend
        backend = backend if backend is not None else get_llm_backend(provider, model)
        prompt = _ENRICH_PROMPT.format(facts=render_facts(facts), flows=_render_flows(out))
        raw = backend.call_tool(prompt, ENRICH_TOOL_SCHEMA,
                                max_tokens=ENRICH_MAX_TOKENS).get("enrichments", [])
        accepted, rejected = _accept_enrichments(raw, flow_ids, fact_ids)
        backend_name, model_name = backend.name, backend.model

    for fl in out["flows"]:
        e = accepted.get(fl["id"])
        if e:
            fl["description"] = f"{fl.get('description', '')}{MARKER}{e['data_note']}]"
            # The citation key differs by vocabulary and is never both: a reader (or
            # verify_enrichment) can tell which vocabulary produced an entry from the entry
            # itself, without consulting _meta.
            ev = ({"citations": e["citations"]} if arm in NAIVE_ARMS
                  else {"fact_ids": e["fact_ids"]})
            fl["enrichment"] = {"arm": arm, **ev, "note": e["data_note"]}

    out.setdefault("_meta", {})
    out["_meta"]["enrichment"] = {
        "arm": arm, "backend": backend_name, "model": model_name,
        "n_flows_enriched": len(accepted), "n_flows": len(out["flows"]),
        "rejected": rejected,
    }
    if arm in NAIVE_ARMS:
        # Coverage is part of the condition: a thin enrichment over a truncated repository is a
        # budget result, not a model result, and the two must never be confusable after the fact.
        out["_meta"]["enrichment"]["source_root"] = str(source_root)
        out["_meta"]["enrichment"]["source_files_omitted"] = omitted
        out["_meta"]["enrichment"]["source_max_chars"] = source_max_chars
    if verbose:
        print(f"  enrichment ({arm}): {len(accepted)}/{len(out['flows'])} flows enriched, "
              f"{len(rejected)} rejected")
    return out


# --------------------------------------------------------------------------------------------
# Verification -- deterministic, no model in the loop
# --------------------------------------------------------------------------------------------

def verify_enrichment(original: dict, enriched: dict,
                      facts: list[CodeFact]) -> list[str]:
    """Every way an enrichment run could have broken its contract, re-derived from the
    artifacts. Empty list = holds. Mirrors the shape of the repo's other verifiers: the checks
    run on what was WRITTEN, never on what the stage claims about itself."""
    problems: list[str] = []
    fact_ids = {f.id for f in facts}

    if enriched["elements"] != original["elements"]:
        problems.append("elements changed -- enrichment must never touch them")

    orig_flows = {f["id"]: f for f in original["flows"]}
    enr_flows = {f["id"]: f for f in enriched["flows"]}
    if set(orig_flows) != set(enr_flows):
        problems.append(f"flow id set changed: {sorted(set(orig_flows) ^ set(enr_flows))}")

    for fid in set(orig_flows) & set(enr_flows):
        o, e = orig_flows[fid], enr_flows[fid]
        if (o["source"], o["destination"]) != (e["source"], e["destination"]):
            problems.append(f"{fid}: endpoints changed")
        if not e.get("description", "").startswith(o.get("description", "")):
            problems.append(f"{fid}: original description not preserved as prefix")
        if o.get("provenance") != e.get("provenance"):
            problems.append(f"{fid}: provenance changed -- enrichment cites via 'enrichment', "
                            f"never provenance")
        # Closed vocabulary only. _accept_enrichments already guarantees this, so a failure here
        # is a bug in the stage rather than a model error -- which is why it is a contract
        # violation. The open vocabulary is deliberately NOT checked here: an unresolvable
        # file:line is the naive arm's finding, not a broken contract, and is reported as a rate
        # by naive_citation_validity() instead.
        for c in e.get("enrichment", {}).get("fact_ids", []):
            if c not in fact_ids:
                problems.append(f"{fid}: enrichment cites unresolvable fact id {c!r}")

    # The gold-resolution invariant, stated as itself: nothing may have introduced a fact_id
    # into ANY provenance entry, or resolve_gold would silently change scoring denominators.
    for item in enriched.get("elements", []) + enriched.get("flows", []):
        for p in item.get("provenance", []):
            if "fact_id" in p:
                problems.append(f"{item.get('id')}: fact_id in provenance -- this DFD would be "
                                f"re-anchored instead of scored against the hand gold")
    return problems


def naive_citation_validity(enriched: dict, source_root) -> dict:
    """Re-derive every open {file, line} citation against the actual source. No model in the loop.

    This is the number the arm exists to produce. In the closed arm it is ~1.00 by construction --
    a fact id either is or is not in a list the stage itself supplied -- and therefore says
    nothing. Here a citation can point at a file that does not exist, or past the end of one that
    does, and the rate at which that happens is a measurement of the vocabulary, not a bug.

    The two failure modes are kept apart for the same reason verify_dfd.py keeps them apart:
    'nope.js:1 does not exist' and 'server.js:99999 is past the end' are different mistakes from
    'server.js:5 exists', and collapsing them would hide which one the model is making.

    Returns counts plus `validity` = resolvable / total, or None when nothing was cited (a rate
    over zero citations would be a fabricated 1.00).
    """
    from pathlib import Path

    from adapters.extract import source_files_any

    # NOT verify_dfd._source_line_counts, which walks with extract.source_files() and so only
    # counts *.js. Verifying an open citation against a JS-only file index would mark every
    # citation into a .py/.rb/.sql file "no such file" and report a validity of 0.00 for a
    # perfectly correct run -- the same inherited-suffix-filter trap render_source_any exists to
    # avoid, one layer down. The index must be built by the walker the arm actually read from.
    root = Path(source_root)
    line_counts = {
        str(p.relative_to(root)).replace("\\", "/"): len(p.read_text(errors="replace").splitlines())
        for p in source_files_any(root)
    }
    total = unknown_file = out_of_range = 0
    bad: list[str] = []
    for fl in enriched.get("flows", []):
        for c in fl.get("enrichment", {}).get("citations", []):
            total += 1
            file, line = c.get("file"), c.get("line")
            if file not in line_counts:
                unknown_file += 1
                bad.append(f"{fl['id']}: {file}:{line} -- no such file in source")
            elif not (1 <= line <= line_counts[file]):
                out_of_range += 1
                bad.append(f"{fl['id']}: {file}:{line} -- past end of file "
                           f"({line_counts[file]} lines)")
    resolvable = total - unknown_file - out_of_range
    return {
        "n_citations": total,
        "n_resolvable": resolvable,
        "n_unknown_file": unknown_file,
        "n_line_out_of_range": out_of_range,
        "validity": round(resolvable / total, 4) if total else None,
        "unresolvable": bad,
    }


def format_enrichment_report(original: dict, enriched: dict, facts: list[CodeFact],
                             source_root=None) -> str:
    problems = verify_enrichment(original, enriched, facts)
    meta = enriched.get("_meta", {}).get("enrichment", {})
    o_desc = [f.get("description", "") for f in original["flows"]]
    e_desc = [f.get("description", "") for f in enriched["flows"]]
    mean = lambda xs: sum(xs) / len(xs) if xs else 0.0

    lines = [
        f"Enrichment verification -- arm={meta.get('arm', '?')} model={meta.get('model', '?')}",
        f"  flows enriched        {meta.get('n_flows_enriched', '?')}/{len(enriched['flows'])}",
        f"  mean description len  {mean([len(d) for d in o_desc]):.0f} -> "
        f"{mean([len(d) for d in e_desc]):.0f} chars",
        f"  rejected enrichments  {len(meta.get('rejected', []))}",
        *(f"    rejected: {r}" for r in meta.get("rejected", [])),
    ]

    if meta.get("arm") in NAIVE_ARMS:
        omitted = meta.get("source_files_omitted", [])
        lines += [
            "",
            f"  source coverage       {'ALL files' if not omitted else str(len(omitted)) + ' file(s) omitted for budget'}",
            *(f"    omitted: {f}" for f in omitted[:10]),
            *([f"    ... and {len(omitted) - 10} more"] if len(omitted) > 10 else []),
        ]
        if source_root is not None:
            cv = naive_citation_validity(enriched, source_root)
            lines += [
                f"  citation validity     "
                + (f"{cv['validity']:.2f} ({cv['n_resolvable']}/{cv['n_citations']} resolve)"
                   if cv["validity"] is not None else "-- (no citations emitted)"),
                f"    unknown file        {cv['n_unknown_file']}",
                f"    line out of range   {cv['n_line_out_of_range']}",
                *(f"    {b}" for b in cv["unresolvable"][:10]),
            ]
        else:
            # Never print a rate that was not computed: an open-vocabulary arm reported without
            # its source root has an UNKNOWN citation validity, not a passing one.
            lines.append("  citation validity     not checked (no source_root given)")

    lines += [
        "",
        f"  contract: {'HOLDS' if not problems else 'VIOLATED'}",
        *(f"    {p}" for p in problems),
    ]
    return "\n".join(lines)
