"""Pass 2: facts -> DFD.

Three arms, mirroring the repo's own grounded/RAG/ungrounded ablation one level up:

  facts_only  no LLM at all. Deterministic assembly straight from the resolved facts.
  llm         the resolved fact list, cited by a CLOSED vocabulary of fact ids.      (M2)
  llm_naive   raw source text, cited by an OPEN vocabulary of {file, line}.          (M3)

facts_only exists because process clustering here is nearly 1:1 with mounted routers and
DataStores are 1:1 with resolved collections -- a deterministic assembler gets most of the way
there on its own. Shipping only the LLM arm would leave no way to tell whether the LLM earned
its place, and a project whose headline is "deterministic grounding beats fuzzy grounding" should
test the deterministic arm of its own new subsystem. This arm is the bar the LLM has to clear.

What facts_only provably cannot do, and what M2 measures: naming ("Authentication Service", not
"/api/auth"), abstraction leaps, granularity judgement (collapsing 15 /api/subprofiles/* routes
into one process), and omission (deciding routes/users.js is or isn't its own process). Those are
real jobs. This module does none of them, on purpose.

It also does not invent. Every element here is the mechanical consequence of a fact, so the
planned-but-unimplemented parts of the hand DFD -- P4 (AI Recommendation Engine), EE3
(Third-Party Advertisers) -- are structurally unreachable from this arm. That is the correct
outcome, and it is why the derivability ceiling (adapters/evaluate.py) is 10/12 rather than 12/12.
"""
from __future__ import annotations
from dataclasses import dataclass

from adapters.resolve import MountTable
from adapters.schema import (DFD_ELEMENTS_TOOL_SCHEMA, DFD_FLOWS_TOOL_SCHEMA, CodeFact)
from retrieval.interaction_context import ELEMENT_TYPES

MODE_FACTS_ONLY = "facts_only"
MODE_LLM = "llm"
MODE_LLM_NAIVE = "llm_naive"

# A whole-DFD payload is far larger than one flow's threats. Azure truncates mid-JSON with no
# error when the budget is short -- the tool call just fails to parse, which reads as a model
# failure rather than a budget one. See generation/llm_backend.DEFAULT_MAX_TOKENS.
SYNTHESIS_MAX_TOKENS = 8000

# Constructs whose presence in the prompt would tell the model nothing about the system's data
# flows while crowding out the facts that do. Import bindings are the bulk of them: 146 of
# KidsTube's 492 facts are `const x = require(...)` / `import x from '...'`, which matter to the
# RESOLVER (they are how models and mounts get linked) but say nothing an analyst would draw.
PROMPT_SUPPRESSED_CONSTRUCTS = {"require_binding", "es_import_binding", "module_export",
                                "mongoose_schema", "env_default"}


@dataclass
class _Element:
    id: str
    type: str
    name: str
    fact_ids: list[str]
    rationale: str


def _index(facts: list[CodeFact]) -> dict[str, CodeFact]:
    return {f.id: f for f in facts}


def _by_construct(facts: list[CodeFact], construct: str) -> list[CodeFact]:
    return [f for f in facts if f.construct == construct]


def synthesize_facts_only(facts: list[CodeFact], scenario_name: str = "") -> dict:
    """Assemble a DFD from resolved facts with no model in the loop.

    Rules, each a direct consequence of a fact type:
      ExternalEntity  one per distinct role named by a role_check
      Process         one per express_mount (a mounted router is a service)
      DataStore       one per distinct resolved collection / filesystem path / web storage area
      Flow            EE->P   a role is checked on a route under that mount (the request)
                      P->EE   ...and that route is a GET (the response carries data back)
                      P->DS   a write db_access, or an upload, on a route under that mount
                      DS->P   a read db_access on a route under that mount
    """
    mounts = MountTable.build(facts)
    route_to_mount = {r.fact_id: r.mount_path for r in mounts.routes}
    route_method = {r.fact_id: r.method for r in mounts.routes}

    elements: list[_Element] = []
    by_mount: dict[str, str] = {}
    by_collection: dict[str, str] = {}
    by_fs_path: dict[str, str] = {}
    by_storage: dict[str, str] = {}
    by_role: dict[str, str] = {}

    roles: dict[str, list[str]] = {}
    for f in _by_construct(facts, "role_check"):
        for role in f.fields.get("roles") or []:
            roles.setdefault(role, []).append(f.id)
    for i, (role, fact_ids) in enumerate(sorted(roles.items()), 1):
        eid = f"EE{i}"
        by_role[role] = eid
        elements.append(_Element(eid, "ExternalEntity", f"{role} (actor role)", sorted(fact_ids),
                                 f"{len(fact_ids)} role checks name the role {role!r}"))

    mount_facts = {f.fields["mount_path"]: f for f in _by_construct(facts, "express_mount")}
    routes_by_mount = mounts.by_mount()
    for i, (mount, f) in enumerate(sorted(mount_facts.items()), 1):
        pid = f"P{i}"
        by_mount[mount] = pid
        cited = [f.id] + sorted(r.fact_id for r in routes_by_mount.get(mount, []))
        elements.append(_Element(pid, "Process", mount, cited,
                                 f"router {f.fields['router_file']} mounted at {mount} serving "
                                 f"{len(routes_by_mount.get(mount, []))} routes"))

    ds_i = 0
    for f in sorted(_by_construct(facts, "mongo_collection"), key=lambda x: x.fields["collection"]):
        collection = f.fields["collection"]
        if collection in by_collection:
            continue
        ds_i += 1
        by_collection[collection] = f"DS{ds_i}"
        elements.append(_Element(f"DS{ds_i}", "DataStore", f"MongoDB {collection} collection",
                                 [f.id], f"model {f.fields['model_name']!r} -> collection "
                                         f"{collection!r} via {f.fields['resolved_via']}"))

    fs_facts: dict[str, list[str]] = {}
    for f in _by_construct(facts, "fs_location"):
        fs_facts.setdefault(f.fields["fs_path"], []).append(f.id)
    for path, fact_ids in sorted(fs_facts.items()):
        ds_i += 1
        by_fs_path[path] = f"DS{ds_i}"
        elements.append(_Element(f"DS{ds_i}", "DataStore", f"File system ({path})",
                                 sorted(fact_ids), f"filesystem writes/reads target {path}"))

    storage_facts: dict[str, list[str]] = {}
    for f in _by_construct(facts, "web_storage_access"):
        storage_facts.setdefault(f.fields["store"], []).append(f.id)
    for store, fact_ids in sorted(storage_facts.items()):
        ds_i += 1
        by_storage[store] = f"DS{ds_i}"
        keys = sorted({x.fields.get("key") for x in _by_construct(facts, "web_storage_access")
                       if x.fields["store"] == store and x.fields.get("key")})
        elements.append(_Element(f"DS{ds_i}", "DataStore", f"Browser {store}", sorted(fact_ids),
                                 f"browser {store} keys: {', '.join(keys)}"))

    flows: list[dict] = []
    seen: dict[tuple[str, str, str], dict] = {}

    def add_flow(src: str, dst: str, intent: str, description: str, fact_id: str):
        key = (src, dst, intent)
        if key in seen:
            if fact_id not in seen[key]["provenance_ids"]:
                seen[key]["provenance_ids"].append(fact_id)
            return
        flow = {"source": src, "destination": dst, "description": description,
                "intent": intent, "provenance_ids": [fact_id]}
        seen[key] = flow
        flows.append(flow)

    for f in _by_construct(facts, "role_check"):
        route_id = f.fields.get("route_fact_id")
        mount = route_to_mount.get(route_id) if route_id else None
        if mount is None:
            continue
        pid = by_mount[mount]
        for role in f.fields.get("roles") or []:
            eid = by_role[role]
            add_flow(eid, pid, "request", f"{role} requests {mount}", f.id)
            if route_method.get(route_id) == "GET":
                add_flow(pid, eid, "response", f"{mount} returns data to {role}", f.id)

    for f in _by_construct(facts, "db_access"):
        route_id = f.fields.get("route_fact_id")
        mount = route_to_mount.get(route_id) if route_id else None
        collection = f.fields["collection"]
        if mount is None or collection not in by_collection:
            continue
        pid, dsid = by_mount[mount], by_collection[collection]
        if f.fields["access"] == "write":
            add_flow(pid, dsid, "db_write", f"{mount} writes {collection}", f.id)
        else:
            add_flow(dsid, pid, "db_read", f"{mount} reads {collection}", f.id)

    binding_file = {(f.file, f.fields["local_name"]): f.fields.get("resolved_file")
                    for f in facts if f.construct == "require_binding"}
    fs_by_file: dict[str, list[CodeFact]] = {}
    for f in _by_construct(facts, "fs_location"):
        fs_by_file.setdefault(f.file, []).append(f)

    for f in _by_construct(facts, "multer_use"):
        route_id = f.fields.get("route_fact_id")
        mount = route_to_mount.get(route_id) if route_id else None
        if mount is None:
            continue
        uploader_file = binding_file.get((f.file, f.fields.get("uploader")))
        targets = fs_by_file.get(uploader_file, []) if uploader_file else fs_by_file.get(f.file, [])
        for t in targets:
            dsid = by_fs_path.get(t.fields["fs_path"])
            if dsid:
                add_flow(by_mount[mount], dsid, "file_write",
                         f"{mount} stores uploaded {f.fields.get('field')} in "
                         f"{t.fields['fs_path']}", f.id)

    for i, flow in enumerate(flows, 1):
        flow["id"] = f"DF{i}"

    return {
        "_meta": {"scenario": f"{scenario_name or 'unnamed system'} (derived from source, "
                              f"{MODE_FACTS_ONLY})",
                  "adapter_mode": MODE_FACTS_ONLY},
        "elements": [{"id": e.id, "type": e.type, "name": e.name,
                      "provenance": [{"fact_id": fid} for fid in e.fact_ids],
                      "rationale": e.rationale} for e in elements],
        "flows": [{"id": f["id"], "source": f["source"], "destination": f["destination"],
                   "description": f["description"],
                   "provenance": [{"fact_id": fid} for fid in f["provenance_ids"]],
                   "intent": f["intent"]} for f in flows],
    }


# ---------------------------------------------------------------------------------------------
# llm arm
# ---------------------------------------------------------------------------------------------

def render_fact(f: CodeFact) -> str:
    """One fact as a citable prompt line.

    The `derived` marker is not decoration. "users" appears in no line of KidsTube -- it is
    inferred by re-implementing Mongoose's pluralisation. A model told that file:line came from a
    parser, and separately told which values were computed rather than read, can reason about how
    far to trust each. Flattening the two into one confident-looking list would teach it that
    everything here is equally solid, which is the opposite of what this project is arguing.
    """
    where = f"{f.file}:{f.line}" if f.line else f.file
    parts = []
    for k, v in f.fields.items():
        if v is None or v == [] or k in ("from_fact_id",):
            continue
        parts.append(f"{k}={v!r}")
    tail = ""
    if f.derived:
        tail = "  (DERIVED: computed by rule, not present in any source line)"
    elif f.confidence != "high":
        tail = f"  (confidence: {f.confidence})"
    return f"[{f.id}] {f.construct:22} {where}\n        " + "  ".join(parts) + tail


def render_facts(facts: list[CodeFact]) -> str:
    keep = [f for f in facts if f.construct not in PROMPT_SUPPRESSED_CONSTRUCTS]
    by_file: dict[str, list[CodeFact]] = {}
    for f in keep:
        by_file.setdefault(f.file, []).append(f)
    blocks = []
    for file in sorted(by_file):
        lines = "\n".join(render_fact(f) for f in sorted(by_file[file], key=lambda x: x.line))
        blocks.append(f"--- {file}\n{lines}")
    return "\n".join(blocks)


_PREAMBLE = """\
You are deriving a Data Flow Diagram (DFD) for LINDDUN Pro privacy threat modeling from
DETERMINISTICALLY EXTRACTED FACTS about a source repository. You are NOT reading the source; you
are reading facts a parser produced from it. Each fact's file:line came from that parser, not
from prose, and each fact id is citable.

DFD element types (LINDDUN Pro):
  ExternalEntity  an actor outside the system (a person or third party who sends/receives data)
  Process         a component that transforms, routes, or acts on data
  DataStore       somewhere data comes to rest

CODE FACTS:
{facts}
"""

_ELEMENTS_INSTRUCTIONS = """\
Emit the elements a privacy analyst would draw for this system.

Rules:
- fact_ids MUST come from the list above. Never emit a file:line yourself; never invent an id.
- Cite evidence that actually supports the type you claim. A DataStore cites persistence facts
  (mongo_collection / fs_location / web_storage_access); a Process cites express_mount /
  express_route / db_access; an ExternalEntity cites role_check / http_route_binding.
- Group at the granularity a human analyst would use: one Process per coherent service, not one
  per route. A router serving 15 related endpoints is one process.
- NAME things as an analyst would on a diagram -- "Authentication Service", not "/api/auth";
  "Parent User", not "parent (actor role)". The route path is evidence, not a name.
- Distinguish actors by role rather than lumping them into one "user": the role_check facts tell
  you which roles this system actually recognises.
- Facts describe IMPLEMENTED code only. Do NOT invent elements for features you believe a system
  like this SHOULD have, or that its name suggests, if no fact supports them. An element you
  cannot cite is an element you must not emit.
- If a fact set is ambiguous, say so in uncertainty_note rather than asserting silently.

Respond using the emit_dfd_elements tool.\
"""

_FLOWS_INSTRUCTIONS = """\
These elements were accepted from your previous step:

{elements}

Emit the data flows between them.

Rules:
- source and destination MUST be ids from the ELEMENTS list above.
- fact_ids MUST come from the CODE FACTS list. Every flow cites at least one.
- A flow's cited facts must actually connect ITS two endpoints -- a db_access fact links the
  process whose route encloses it to the collection it names. Do not cite a fact that evidences a
  different edge.
- Flows are DIRECTED. A read and a write between the same pair are two flows, not one.
- Describe what DATA moves, not just that a call happens: "parent registration (email, password,
  government ID)" beats "parent calls /api/auth".
- Do not emit a flow touching an element you did not emit, and do not invent flows for
  functionality no fact supports.

Respond using the emit_dfd_flows tool.\
"""


def _elements_prompt(facts: list[CodeFact]) -> str:
    return _PREAMBLE.format(facts=render_facts(facts)) + "\n" + _ELEMENTS_INSTRUCTIONS


def _flows_prompt(facts: list[CodeFact], elements: list[dict]) -> str:
    rendered = "\n".join(f"  {e['id']:5} {e['type']:14} {e['name']}" for e in elements)
    return (_PREAMBLE.format(facts=render_facts(facts)) + "\n"
            + _FLOWS_INSTRUCTIONS.format(elements=rendered))


def _accept_elements(raw: list[dict], fact_ids: set[str]) -> tuple[list[dict], list[str]]:
    """Keep only well-formed elements citing the closed vocabulary. Returns (kept, rejections).

    An element citing zero resolvable facts is dropped, not kept-with-a-warning. This is the
    structural guard against the failure that would quietly destroy the ceiling analysis: the
    model knows this is a children's video platform and will want to emit an "AI Recommendation
    Engine" and "Third-Party Advertisers" -- the two elements that exist in no code. No fact
    mentions them, so in this arm they are literally uncitable, and dropping uncited elements
    turns "please don't hallucinate" from an instruction into an invariant. (The llm_naive arm
    has no such protection, by design -- that is what it measures.)
    """
    kept, rejected = [], []
    seen: set[str] = set()
    for e in raw:
        eid = e.get("id")
        if not eid or e.get("type") not in ELEMENT_TYPES or not e.get("name"):
            rejected.append(f"{eid or '<no id>'}: malformed (id/type/name)")
            continue
        if eid in seen:
            rejected.append(f"{eid}: duplicate id")
            continue
        cited = [c for c in (e.get("fact_ids") or []) if c in fact_ids]
        bogus = [c for c in (e.get("fact_ids") or []) if c not in fact_ids]
        if not cited:
            rejected.append(f"{eid} ({e.get('name')!r}): cites no resolvable fact "
                            f"(claimed {e.get('fact_ids') or []})")
            continue
        seen.add(eid)
        el = {"id": eid, "type": e["type"], "name": e["name"],
              "provenance": [{"fact_id": c} for c in cited]}
        for opt in ("rationale", "confidence", "uncertainty_note"):
            if e.get(opt):
                el[opt] = e[opt]
        if bogus:
            el["uncertainty_note"] = (el.get("uncertainty_note", "")
                                      + f" [adapter: dropped unresolvable fact ids {bogus}]").strip()
        kept.append(el)
    return kept, rejected


def _accept_flows(raw: list[dict], element_ids: set[str],
                  fact_ids: set[str]) -> tuple[list[dict], list[str]]:
    kept, rejected = [], []
    seen: set[str] = set()
    for f in raw:
        fid = f.get("id")
        if not fid or fid in seen:
            rejected.append(f"{fid or '<no id>'}: missing or duplicate id")
            continue
        if f.get("source") not in element_ids or f.get("destination") not in element_ids:
            rejected.append(f"{fid}: endpoint not an emitted element "
                            f"({f.get('source')} -> {f.get('destination')})")
            continue
        cited = [c for c in (f.get("fact_ids") or []) if c in fact_ids]
        if not cited:
            rejected.append(f"{fid}: cites no resolvable fact")
            continue
        seen.add(fid)
        fl = {"id": fid, "source": f["source"], "destination": f["destination"],
              "description": f.get("description") or f"{f['source']} -> {f['destination']}",
              "provenance": [{"fact_id": c} for c in cited]}
        for opt in ("confidence", "uncertainty_note"):
            if f.get(opt):
                fl[opt] = f[opt]
        kept.append(fl)
    return kept, rejected


def synthesize_llm(facts: list[CodeFact], provider: str | None = None,
                   verbose: bool = True, scenario_name: str = "") -> dict:
    """Two calls: elements, then flows constrained to the accepted element ids.

    Two rather than one because a DFD is a globally consistent graph -- flows reference element
    ids -- so generate.py's per-flow loop is structurally wrong here; but a single monolithic call
    makes the output huge and every error correlated. The elements/flows seam matches LINDDUN's
    own authoring order and lets call 2 be constrained to a closed element-id vocabulary, the same
    trick as call 1's closed fact-id vocabulary.
    """
    from generation.llm_backend import get_llm_backend

    backend = get_llm_backend(provider)
    fact_ids = {f.id for f in facts}

    raw_elements = backend.call_tool(_elements_prompt(facts), DFD_ELEMENTS_TOOL_SCHEMA,
                                     max_tokens=SYNTHESIS_MAX_TOKENS).get("elements", [])
    elements, el_rejected = _accept_elements(raw_elements, fact_ids)
    if not elements:
        raise RuntimeError("the model emitted no citable elements; refusing to write an empty DFD."
                           + (f" Rejections: {el_rejected}" if el_rejected else ""))

    raw_flows = backend.call_tool(_flows_prompt(facts, elements), DFD_FLOWS_TOOL_SCHEMA,
                                  max_tokens=SYNTHESIS_MAX_TOKENS).get("flows", [])
    flows, fl_rejected = _accept_flows(raw_flows, {e["id"] for e in elements}, fact_ids)

    if verbose:
        print(f"  elements: {len(elements)} accepted, {len(el_rejected)} rejected")
        for r in el_rejected:
            print(f"    rejected: {r}")
        print(f"  flows:    {len(flows)} accepted, {len(fl_rejected)} rejected")
        for r in fl_rejected:
            print(f"    rejected: {r}")

    return {
        "_meta": {"scenario": f"{scenario_name or 'unnamed system'} (derived from source, "
                              f"{MODE_LLM})",
                  "adapter_mode": MODE_LLM,
                  "backend": backend.name,
                  "rejected_elements": el_rejected,
                  "rejected_flows": fl_rejected},
        "elements": elements,
        "flows": flows,
    }
