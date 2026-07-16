"""The canonical DFD schema -- the pivot representation every input adapter converges on.

README's stage table has carried "Canonical DFD schema (the general pivot representation,
arbitrary systems)" as not-built with the note "formalize first". This module is that
formalization, and it is deliberately a *validator* rather than a prose document: a schema that
is a doc is a wish; a schema that is a function with a test over every dfd.json in the repo is a
contract that cannot silently drift from the files it claims to describe.

Two shapes coexist, on purpose:

  v1 -- the four hand-authored per-scenario DFDs (kidstube, genomic, family_location,
        smart_home). Elements are {id, type, name}; flows are {id, source, destination,
        description}. No provenance, no trust boundaries. These files are ground truth and are
        deliberately NOT migrated: v1 is a strict subset of v2, so they validate unchanged. That
        is the backward-compatibility proof, and tests/test_kb.py asserts it over all of them.

  v2 -- adds, all optional: per-element/flow `provenance` (where in a source repository this
        element came from), `trust_boundaries`, and `_meta.derived_from`. Emitted by
        adapters/emit.py for scenarios derived from source code.

Every existing consumer of dfd.json (generation/generate.py, generation/verify.py,
eval/match.py, eval/reachability.py, eval/adjudicate.py, cli.py, ingestion/loader.py,
scripts/render_dfd.py) reads only explicit keys and never iterates them or asserts absence, so
v2's additions are inert for all of them -- a v2 DFD runs through the existing pipeline
unchanged. The one rule for NEW consumers: read trust boundaries via
dfd.get("trust_boundaries", []), since all four v1 files lack the key entirely.

Provenance citations are fact ids rather than raw file:line pairs. An id drawn from a closed,
deterministically-produced vocabulary can be checked for membership; a model-emitted file:line
is a self-report of exactly the kind generation/verify.py exists to refuse. The `file`/`line`
form is still accepted here because the `llm_naive` ablation arm deliberately uses an open
citation vocabulary -- that arm exists to measure what happens without the closed one, so the
schema has to be able to represent its output.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import asdict, dataclass, field

from retrieval.interaction_context import ELEMENT_TYPES

SCHEMA_VERSION = 2


@dataclass
class CodeFact:
    """One deterministically-extracted fact about a source repository, with its location.

    Facts are the closed vocabulary a synthesised DFD cites. That is the load-bearing decision of
    the whole adapter: if a model emitted `file:line` directly it could hallucinate a plausible
    line number and we would be back to checking a self-report -- exactly what
    generation/verify.py exists to refuse. An id from a provided list either resolves or does
    not, and the file:line behind it came from a parser, so it is true by construction.

    `derived` marks a field that no source line contains, computed by re-implementing some
    library's rule. The collection name "users" is the canonical case: it appears nowhere in
    KidsTube, and is inferred from mongoose.model('User', ...) via Mongoose's pluralisation. The
    verifier can re-parse a literal but cannot confirm an inference, so the distinction has to be
    visible rather than blurred into "we extracted it". This is the honesty knob: it marks the one
    place the "verified, not asserted" story has a genuine gap.
    """
    id: str
    construct: str
    file: str
    line: int
    end_line: int = 0
    fields: dict = field(default_factory=dict)
    derived: bool = False
    confidence: str = "high"

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "CodeFact":
        return CodeFact(**d)

    @staticmethod
    def make_id(construct: str, file: str, line: int, fields: dict) -> str:
        """Content-derived, so ids stay stable when a new construct type is added later.

        Sequential numbering would renumber every fact the first time we extract a new kind,
        silently invalidating the fact_ids in any already-committed derived DFD. Line number is
        part of the key, so ids do move if the source moves -- which is why _meta.derived_from
        pins the commit SHA the facts were read from.
        """
        key = f"{construct}|{file}|{line}|{json.dumps(fields, sort_keys=True, default=str)}"
        return "F" + hashlib.sha256(key.encode()).hexdigest()[:8]


# Which fact constructs can support a claim about each DFD element type. The adapter's analogue
# of the mapping table's type_applicable check: a DataStore citing only routing facts named a
# store but pointed at the wrong evidence.
SUPPORTING_CONSTRUCTS = {
    "DataStore": {"mongoose_model", "mongoose_schema", "mongo_collection", "fs_write",
                  "fs_location", "express_static_mount", "web_storage_access", "db_connect"},
    "Process": {"express_mount", "express_route", "db_operation", "db_access", "auth_middleware",
                "jwt_operation", "password_hash", "multer_use", "http_client_config",
                "http_route_binding"},
    "ExternalEntity": {"role_check", "ui_component", "http_client_call", "http_route_binding"},
}

_CITATION_RULE = ("Ids from the CODE FACTS list in the prompt. Every item MUST cite at least one. "
                  "Never invent an id; never emit a file:line yourself.")

DFD_ELEMENTS_TOOL_SCHEMA = {
    "name": "emit_dfd_elements",
    "description": "Emit the DFD elements a privacy analyst would draw for this system, each "
                   "citing the code facts that evidence it.",
    "input_schema": {
        "type": "object",
        "properties": {
            "elements": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string",
                               "description": "EE1/EE2... for ExternalEntity, P1/P2... for "
                                              "Process, DS1/DS2... for DataStore."},
                        "type": {"type": "string",
                                 "enum": ["ExternalEntity", "Process", "DataStore"]},
                        "name": {"type": "string",
                                 "description": "The name an analyst would write on the diagram, "
                                                "e.g. 'Authentication Service' -- not the route "
                                                "path or the variable name."},
                        "fact_ids": {"type": "array", "items": {"type": "string"},
                                     "description": _CITATION_RULE},
                        "rationale": {"type": "string",
                                      "description": "One sentence: why these facts are this element."},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        "uncertainty_note": {
                            "type": "string",
                            "description": "If the evidence is thin, or you are inferring beyond "
                                           "what the facts state, say so here rather than "
                                           "asserting it silently."},
                    },
                    "required": ["id", "type", "name", "fact_ids"],
                },
            },
        },
        "required": ["elements"],
    },
}

DFD_FLOWS_TOOL_SCHEMA = {
    "name": "emit_dfd_flows",
    "description": "Emit the data flows between the given elements, each citing the code facts "
                   "that evidence the flow.",
    "input_schema": {
        "type": "object",
        "properties": {
            "flows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "DF1, DF2, ..."},
                        "source": {"type": "string",
                                   "description": "An element id from the ELEMENTS list above."},
                        "destination": {"type": "string",
                                        "description": "An element id from the ELEMENTS list above."},
                        "description": {"type": "string",
                                        "description": "What data moves, e.g. 'parent "
                                                       "registration (email, password, govt ID)'."},
                        "fact_ids": {"type": "array", "items": {"type": "string"},
                                     "description": _CITATION_RULE},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        "uncertainty_note": {"type": "string"},
                    },
                    "required": ["id", "source", "destination", "description", "fact_ids"],
                },
            },
        },
        "required": ["flows"],
    },
}

# llm_naive's variant: an OPEN citation vocabulary. The model emits file:line itself instead of
# picking an id from a provided list. That single difference IS the M3 ablation -- it is the
# adapter-level analogue of `ungrounded`, and the whole point is to measure what citation
# validity does when nothing constrains it. Not an inconsistency; the experiment.
DFD_ELEMENTS_NAIVE_TOOL_SCHEMA = {
    "name": "emit_dfd_elements",
    "description": DFD_ELEMENTS_TOOL_SCHEMA["description"],
    "input_schema": {
        "type": "object",
        "properties": {
            "elements": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        **{k: v for k, v in
                           DFD_ELEMENTS_TOOL_SCHEMA["input_schema"]["properties"]["elements"]
                           ["items"]["properties"].items() if k != "fact_ids"},
                        "citations": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {"file": {"type": "string"},
                                               "line": {"type": "integer"}},
                                "required": ["file", "line"],
                            },
                            "description": "Where in the source this element comes from.",
                        },
                    },
                    "required": ["id", "type", "name", "citations"],
                },
            },
        },
        "required": ["elements"],
    },
}


def schema_version(dfd: dict) -> int:
    """A DFD with no declared version is v1 -- that covers the four hand-authored files, none of
    which will ever be rewritten just to carry a version stamp."""
    return dfd.get("_meta", {}).get("schema_version", 1)


def _validate_provenance(prov, where: str, errors: list[str]) -> None:
    """A provenance entry cites EITHER a fact_id (closed vocabulary, the `llm`/`facts_only` arms)
    OR a file+line (open vocabulary, the `llm_naive` arm) -- never both, never neither. Both at
    once would let a caller quietly disagree with itself about which vocabulary is in force, and
    the whole point of the split is that the two are measured separately."""
    if not isinstance(prov, list):
        errors.append(f"{where}: 'provenance' must be a list")
        return
    for i, p in enumerate(prov):
        if not isinstance(p, dict):
            errors.append(f"{where}: provenance[{i}] must be an object")
            continue
        has_fact = "fact_id" in p
        has_loc = "file" in p and "line" in p
        if has_fact and has_loc:
            errors.append(f"{where}: provenance[{i}] cites both a fact_id and a file:line "
                          f"(pick one vocabulary)")
        elif not has_fact and not has_loc:
            errors.append(f"{where}: provenance[{i}] cites neither a fact_id nor a file+line")
        if has_loc and not isinstance(p.get("line"), int):
            errors.append(f"{where}: provenance[{i}] 'line' must be an int, got {p.get('line')!r}")


def validate_dfd(dfd: dict) -> list[str]:
    """Return every schema violation found; an empty list means the DFD conforms.

    Returns errors rather than raising so one call reports every problem in a file at once --
    an adapter run that emits a structurally broken DFD should show all of it, not just the
    first thing that tripped.

    Orphan elements (no incident flow) are deliberately NOT an error: genomic legitimately has
    sparse ones, and a derived DFD may surface a store nothing reads yet. That is a modeling
    observation, not a schema violation.
    """
    if not isinstance(dfd, dict):
        return ["top level must be an object"]

    errors: list[str] = []

    version = schema_version(dfd)
    if version not in (1, SCHEMA_VERSION):
        errors.append(f"_meta.schema_version {version!r} is not 1 or {SCHEMA_VERSION}")

    elements = dfd.get("elements")
    if not isinstance(elements, list):
        errors.append("'elements' must be a list")
        elements = []

    elem_ids: set[str] = set()
    for i, e in enumerate(elements):
        where = f"elements[{i}]"
        if not isinstance(e, dict):
            errors.append(f"{where}: must be an object")
            continue
        eid = e.get("id")
        if not eid or not isinstance(eid, str):
            errors.append(f"{where}: missing or non-string 'id'")
        elif eid in elem_ids:
            errors.append(f"{where}: duplicate element id {eid!r}")
        else:
            elem_ids.add(eid)
        if e.get("type") not in ELEMENT_TYPES:
            errors.append(f"{where} ({eid}): type {e.get('type')!r} is not one of "
                          f"{sorted(ELEMENT_TYPES)}")
        if not e.get("name"):
            errors.append(f"{where} ({eid}): missing or empty 'name'")
        if "provenance" in e:
            _validate_provenance(e["provenance"], f"{where} ({eid})", errors)

    flows = dfd.get("flows")
    if not isinstance(flows, list):
        errors.append("'flows' must be a list")
        flows = []

    flow_ids: set[str] = set()
    for i, f in enumerate(flows):
        where = f"flows[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where}: must be an object")
            continue
        fid = f.get("id")
        if not fid or not isinstance(fid, str):
            errors.append(f"{where}: missing or non-string 'id'")
        elif fid in flow_ids:
            errors.append(f"{where}: duplicate flow id {fid!r}")
        else:
            flow_ids.add(fid)
        for endpoint in ("source", "destination"):
            ref = f.get(endpoint)
            if not ref:
                errors.append(f"{where} ({fid}): missing '{endpoint}'")
            elif ref not in elem_ids:
                errors.append(f"{where} ({fid}): {endpoint} {ref!r} is not a declared element")
        if not f.get("description"):
            errors.append(f"{where} ({fid}): missing or empty 'description'")
        if "provenance" in f:
            _validate_provenance(f["provenance"], f"{where} ({fid})", errors)

    tbs = dfd.get("trust_boundaries", [])
    if not isinstance(tbs, list):
        errors.append("'trust_boundaries' must be a list")
        tbs = []

    tb_ids: set[str] = set()
    for i, tb in enumerate(tbs):
        where = f"trust_boundaries[{i}]"
        if not isinstance(tb, dict):
            errors.append(f"{where}: must be an object")
            continue
        tid = tb.get("id")
        if not tid or not isinstance(tid, str):
            errors.append(f"{where}: missing or non-string 'id'")
        elif tid in tb_ids:
            errors.append(f"{where}: duplicate trust boundary id {tid!r}")
        else:
            tb_ids.add(tid)
        if not tb.get("name"):
            errors.append(f"{where} ({tid}): missing or empty 'name'")
        contains = tb.get("contains", [])
        if not isinstance(contains, list):
            errors.append(f"{where} ({tid}): 'contains' must be a list")
            contains = []
        for cid in contains:
            if cid not in elem_ids:
                errors.append(f"{where} ({tid}): contains {cid!r}, which is not a declared element")
        if "provenance" in tb:
            _validate_provenance(tb["provenance"], f"{where} ({tid})", errors)

    for i, e in enumerate(elements):
        if not isinstance(e, dict):
            continue
        tb_ref = e.get("trust_boundary")
        if tb_ref and tb_ref not in tb_ids:
            errors.append(f"elements[{i}] ({e.get('id')}): trust_boundary {tb_ref!r} is not a "
                          f"declared trust boundary")

    for i, f in enumerate(flows):
        if not isinstance(f, dict):
            continue
        for cb in f.get("crosses_boundaries", []) or []:
            if cb not in tb_ids:
                errors.append(f"flows[{i}] ({f.get('id')}): crosses_boundaries cites {cb!r}, "
                              f"which is not a declared trust boundary")

    return errors


if __name__ == "__main__":
    import json
    import sys

    import config

    bad = 0
    for path in sorted((config.KB_DIR / "scenarios").glob("*/dfd.json")):
        errs = validate_dfd(json.loads(path.read_text()))
        label = f"v{schema_version(json.loads(path.read_text()))}"
        if errs:
            bad += 1
            print(f"FAIL {path.parent.name} ({label})")
            for e in errs:
                print(f"       {e}")
        else:
            print(f"ok   {path.parent.name} ({label})")
    sys.exit(1 if bad else 0)
