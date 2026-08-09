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

Two arms, mirroring the source adapter's ladder:

  enrich_facts   deterministic token overlap between a fact's content and a flow's endpoints and
                 description. No LLM anywhere. Crude on purpose: it is the bar the llm arm has to
                 clear, not the proposal.
  enrich_llm     one call; the model maps facts to flows citing the CLOSED fact-id vocabulary.
                 An enrichment citing no resolvable fact is dropped (_accept_enrichments) -- the
                 same discipline as synthesize.py's _accept_flows, "don't hallucinate" as an
                 invariant rather than an instruction.

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
ENRICH_ARMS = (MODE_ENRICH_FACTS, MODE_ENRICH_LLM)

ENRICH_MAX_TOKENS = 8000
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
               verbose: bool = True) -> dict:
    """Returns a NEW dfd dict; the input is never mutated. See the module docstring for the two
    invariants this function exists to hold."""
    if arm not in ENRICH_ARMS:
        raise ValueError(f"arm must be one of {ENRICH_ARMS}, got {arm!r}")

    out = copy.deepcopy(dfd)
    flow_ids = {f["id"] for f in out["flows"]}
    fact_ids = {f.id for f in facts}

    if arm == MODE_ENRICH_FACTS:
        accepted, rejected = _match_deterministic(out, facts)
        backend_name = model_name = "none"          # deterministic: explicitly no model
    else:
        from generation.llm_backend import get_llm_backend
        backend = get_llm_backend(provider, model)
        prompt = _ENRICH_PROMPT.format(facts=render_facts(facts), flows=_render_flows(out))
        raw = backend.call_tool(prompt, ENRICH_TOOL_SCHEMA,
                                max_tokens=ENRICH_MAX_TOKENS).get("enrichments", [])
        accepted, rejected = _accept_enrichments(raw, flow_ids, fact_ids)
        backend_name, model_name = backend.name, backend.model

    for fl in out["flows"]:
        e = accepted.get(fl["id"])
        if e:
            fl["description"] = f"{fl.get('description', '')}{MARKER}{e['data_note']}]"
            fl["enrichment"] = {"arm": arm, "fact_ids": e["fact_ids"], "note": e["data_note"]}

    out.setdefault("_meta", {})
    out["_meta"]["enrichment"] = {
        "arm": arm, "backend": backend_name, "model": model_name,
        "n_flows_enriched": len(accepted), "n_flows": len(out["flows"]),
        "rejected": rejected,
    }
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


def format_enrichment_report(original: dict, enriched: dict, facts: list[CodeFact]) -> str:
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
        "",
        f"  contract: {'HOLDS' if not problems else 'VIOLATED'}",
        *(f"    {p}" for p in problems),
    ]
    return "\n".join(lines)
