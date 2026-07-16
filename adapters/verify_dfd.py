"""Pass 3: independently re-derive every citation in a derived DFD. Zero LLM calls, ever.

This module is the adapter's generation/verify.py, and deliberately mirrors its structure: a
dataclass of independent booleans, a `reasons` list, an `all_valid` property. There, a generated
threat's cited tree node and DFD location are re-checked against the knowledge base rather than
trusted from the model's own output. Here, a derived element's cited code location is re-checked
against the source rather than trusted from the model's own output. Same argument, one level up:
if the DFD -- the artifact every threat's location citation is verified *against* -- were itself
an unverified LLM output, the trust problem would not be solved, only relocated.

Nothing here calls a model. A verifier that asks a model whether the model was right is not a
verifier; it relocates the self-report problem this whole project exists to refuse.

What this buys, stated plainly. In the `llm` arm citations_resolvable will be ~1.00 trivially,
because the closed fact-id vocabulary makes it so. That is not a weakness -- it is the same shape
as the project's existing headline (grounded 1.00 by construction, RAG/ungrounded 0.92-0.97). The
`llm_naive` arm, with its open file:line vocabulary, is where it drops, and the drop is the
finding.

What this does NOT buy, equally plainly: citation integrity is not modeling correctness. The hand
DFD models DF16 as P1 -> DS5 ("JWT stored in localStorage"), but the code fact is
localStorage.setItem('token', ...) in frontend/src/contexts/AuthContext.js -- the *frontend*
writes it. That is a legitimate analyst abstraction (the browser is the user's side of the trust
boundary), and no deterministic checker can confirm it. `evidence_connects_endpoints` will reject
such a flow, correctly, and that rejection is a statement about evidence, not about whether the
analyst was right.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

from adapters.extract import extract_repo
from adapters.resolve import resolve_facts
from adapters.schema import SUPPORTING_CONSTRUCTS, CodeFact

NOT_CHECKED = "not_checked"


@dataclass
class ElementVerification:
    element_id: str
    citations_resolvable: bool
    evidence_type_consistent: bool
    facts_present: object          # True | False | NOT_CHECKED
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return (self.citations_resolvable and self.evidence_type_consistent
                and self.facts_present is not False)


NOT_APPLICABLE = "not_applicable"


@dataclass
class FlowVerification:
    flow_id: str
    citations_resolvable: bool
    endpoints_declared: bool
    evidence_connects_endpoints: bool   # UNORDERED: does the cited evidence link these two?
    direction_matches_evidence: object  # True | False | NOT_APPLICABLE -- a modeling convention
    facts_present: object
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        """Citation integrity only. `direction_matches_evidence` is deliberately excluded.

        These were one check until a run showed why they must not be. The model draws a database
        interaction as Process -> DataStore whether the operation reads or writes -- the *query*
        direction. A read's data moves the other way, so a combined check scored 36 of run 3's
        flows as citation failures. They were not: every citation was real, resolvable, and about
        the right pair of elements. Only the arrow convention differed.

        And the model's convention is the hand DFD's own: kidstube/dfd.json's DF9 is "P2 -> DS3,
        store/RETRIEVE video metadata" -- a read drawn Process -> DataStore. So the stricter
        reading would have penalised the model for agreeing with the ground truth, and reported
        an integrity failure that did not exist.

        Direction is a modeling choice this verifier has no standing to adjudicate. It is measured
        and reported, never folded into a correctness rate.
        """
        return (self.citations_resolvable and self.endpoints_declared
                and self.evidence_connects_endpoints and self.facts_present is not False)


def _cited_ids(item: dict) -> list[str]:
    return [p["fact_id"] for p in item.get("provenance", []) if "fact_id" in p]


def _cited_locations(item: dict) -> list[tuple[str, int]]:
    return [(p["file"], p["line"]) for p in item.get("provenance", [])
            if "file" in p and "line" in p]


def _fact_key(f: CodeFact) -> tuple:
    """Identity of a fact for set-membership re-derivation.

    Deliberately NOT the fact id, and not a stored source excerpt. The id is content-derived from
    exactly these components, so comparing ids would be circular; a stored excerpt is itself a
    self-report of the extractor and is whitespace-brittle. Re-running the extractor over the
    source and checking membership by (construct, file, line) is genuine independent
    re-derivation -- the exact analogue of verify.py re-loading threat_trees.json rather than
    trusting threat.tree_node.
    """
    return (f.construct, f.file, f.line)


def _reextract(source_root: Path) -> dict[str, CodeFact]:
    return {f.id: f for f in resolve_facts(extract_repo(source_root))}


def verify_element(element: dict, facts_by_id: dict[str, CodeFact],
                   reextracted: dict[str, CodeFact] | None) -> ElementVerification:
    reasons: list[str] = []
    cited = _cited_ids(element)
    locations = _cited_locations(element)

    unresolvable = [c for c in cited if c not in facts_by_id]
    citations_resolvable = bool(cited or locations) and not unresolvable
    if not cited and not locations:
        reasons.append("cites nothing at all")
    for c in unresolvable:
        reasons.append(f"fact id {c!r} does not exist in the fact vocabulary")

    resolved = [facts_by_id[c] for c in cited if c in facts_by_id]
    supporting = SUPPORTING_CONSTRUCTS.get(element.get("type"), set())
    evidence_type_consistent = any(f.construct in supporting for f in resolved)
    if resolved and not evidence_type_consistent:
        reasons.append(f"type {element.get('type')!r} is not supported by any cited construct "
                       f"{sorted({f.construct for f in resolved})}; expected one of "
                       f"{sorted(supporting)}")
    if not resolved:
        evidence_type_consistent = False

    if reextracted is None:
        facts_present: object = NOT_CHECKED
    else:
        present_keys = {_fact_key(f) for f in reextracted.values()}
        missing = [f for f in resolved if not f.derived and _fact_key(f) not in present_keys]
        facts_present = not missing
        for f in missing:
            reasons.append(f"fact {f.id} claims {f.construct} at {f.file}:{f.line}, "
                           f"but re-parsing the source finds no such construct there")

    return ElementVerification(element_id=element.get("id", "<no id>"),
                               citations_resolvable=citations_resolvable,
                               evidence_type_consistent=evidence_type_consistent,
                               facts_present=facts_present, reasons=reasons)


def _element_collections(element: dict, facts_by_id: dict[str, CodeFact]) -> set[str]:
    out = set()
    for c in _cited_ids(element):
        f = facts_by_id.get(c)
        if f and f.fields.get("collection"):
            out.add(f.fields["collection"])
        if f and f.fields.get("fs_path"):
            out.add(f.fields["fs_path"])
        if f and f.construct == "web_storage_access":
            out.add(f.fields.get("store"))
    return out


def _element_routes(element: dict, facts_by_id: dict[str, CodeFact],
                    route_to_mount: dict[str, str]) -> set[str]:
    """Every route fact id this element's evidence covers, directly or via its mount."""
    out = set()
    mounts = set()
    for c in _cited_ids(element):
        f = facts_by_id.get(c)
        if not f:
            continue
        if f.construct == "express_route":
            out.add(f.id)
        if f.construct == "express_mount":
            mounts.add(f.fields.get("mount_path"))
    if mounts:
        out |= {rid for rid, m in route_to_mount.items() if m in mounts}
    return out


def verify_flow(flow: dict, elements_by_id: dict[str, dict], facts_by_id: dict[str, CodeFact],
                route_to_mount: dict[str, str],
                reextracted: dict[str, CodeFact] | None) -> FlowVerification:
    reasons: list[str] = []
    cited = _cited_ids(flow)

    unresolvable = [c for c in cited if c not in facts_by_id]
    citations_resolvable = bool(cited) and not unresolvable
    for c in unresolvable:
        reasons.append(f"fact id {c!r} does not exist in the fact vocabulary")
    if not cited:
        reasons.append("cites nothing at all")

    src = elements_by_id.get(flow.get("source"))
    dst = elements_by_id.get(flow.get("destination"))
    endpoints_declared = src is not None and dst is not None
    if not endpoints_declared:
        reasons.append(f"endpoint not a declared element: {flow.get('source')} -> "
                       f"{flow.get('destination')}")

    evidence_connects = False
    direction: object = NOT_APPLICABLE
    if endpoints_declared:
        resolved = [facts_by_id[c] for c in cited if c in facts_by_id]
        for f in resolved:
            if f.construct == "db_access":
                # Unordered: whichever endpoint is the process whose route encloses this op, the
                # other must be the collection it names. Whether the arrow then points the way
                # the data moves is a separate question, answered below.
                for proc, store, proc_is_source in ((src, dst, True), (dst, src, False)):
                    route_ok = f.fields.get("route_fact_id") in _element_routes(
                        proc, facts_by_id, route_to_mount)
                    store_ok = f.fields.get("collection") in _element_collections(store, facts_by_id)
                    if route_ok and store_ok:
                        evidence_connects = True
                        # Data moves Process -> DataStore on a write, DataStore -> Process on a
                        # read. Recorded, not scored.
                        direction = proc_is_source == (f.fields.get("access") == "write")
                        break
                if evidence_connects:
                    break
            if f.construct in ("http_route_binding", "role_check"):
                proc = dst if dst.get("type") == "Process" else src
                if f.fields.get("route_fact_id") in _element_routes(proc, facts_by_id,
                                                                     route_to_mount):
                    evidence_connects = True
                    break
            if f.construct in ("multer_use", "fs_location", "express_static_mount", "fs_write"):
                store = dst if dst.get("type") == "DataStore" else src
                if _element_collections(store, facts_by_id):
                    evidence_connects = True
                    break
            if f.construct == "web_storage_access":
                store = dst if dst.get("type") == "DataStore" else src
                if f.fields.get("store") in _element_collections(store, facts_by_id):
                    evidence_connects = True
                    break
        if not evidence_connects:
            reasons.append(
                f"no cited fact actually connects {flow.get('source')} to "
                f"{flow.get('destination')}: the citation is real but it evidences a different "
                f"edge (or an abstraction the code does not state)")

    if reextracted is None:
        facts_present: object = NOT_CHECKED
    else:
        present_keys = {_fact_key(f) for f in reextracted.values()}
        missing = [facts_by_id[c] for c in cited
                   if c in facts_by_id and not facts_by_id[c].derived
                   and _fact_key(facts_by_id[c]) not in present_keys]
        facts_present = not missing
        for f in missing:
            reasons.append(f"fact {f.id} claims {f.construct} at {f.file}:{f.line}, "
                           f"but re-parsing the source finds no such construct there")

    return FlowVerification(flow_id=flow.get("id", "<no id>"),
                            citations_resolvable=citations_resolvable,
                            endpoints_declared=endpoints_declared,
                            evidence_connects_endpoints=evidence_connects,
                            direction_matches_evidence=direction,
                            facts_present=facts_present, reasons=reasons)


def verify_dfd(dfd: dict, facts: list[CodeFact],
               source_root: Path | None = None) -> tuple[list[ElementVerification],
                                                         list[FlowVerification]]:
    """Verify every element and flow.

    `source_root` given: re-run the extractor and check every cited fact is genuinely re-derivable
    from the source. The strong check.
    `source_root` omitted: report facts_present as NOT_CHECKED -- never as True. An unavailable
    check that reads as a pass is the single easiest way to fake a 1.00, and the number would be
    indistinguishable from a real one.
    """
    facts_by_id = {f.id: f for f in facts}
    reextracted = _reextract(source_root) if source_root else None

    from adapters.resolve import MountTable
    route_to_mount = {r.fact_id: r.mount_path for r in MountTable.build(facts).routes}

    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    ev = [verify_element(e, facts_by_id, reextracted) for e in dfd["elements"]]
    fv = [verify_flow(f, elements_by_id, facts_by_id, route_to_mount, reextracted)
          for f in dfd["flows"]]
    return ev, fv


def _rate(items: list, attr: str) -> float:
    """Rate over items where the check actually ran. NOT_CHECKED / NOT_APPLICABLE are excluded
    from the denominator rather than counted either way -- a check that did not run must not be
    able to move a number in either direction."""
    if not items:
        return 0.0
    vals = [getattr(i, attr) for i in items]
    checked = [v for v in vals if v is not NOT_CHECKED and v is not NOT_APPLICABLE]
    if not checked:
        return float("nan")
    return sum(1 for v in checked if v) / len(checked)


def format_verification_report(ev: list[ElementVerification], fv: list[FlowVerification],
                               source_checked: bool) -> str:
    def pct(x):
        return "not_checked" if x != x else f"{x:.2f}"

    lines = [
        "DFD citation correctness (independently re-derived, not self-reported):",
        f"  elements checked                {len(ev):3}",
        f"  flows checked                   {len(fv):3}",
        "",
        f"  citations_resolvable_rate       {pct(_rate(ev, 'citations_resolvable'))}   (elements)",
        f"  evidence_type_consistent_rate   {pct(_rate(ev, 'evidence_type_consistent'))}   (elements)",
        f"  facts_present_rate              {pct(_rate(ev, 'facts_present'))}   (elements)",
        f"  element_all_valid_rate          {pct(_rate(ev, 'all_valid'))}",
        "",
        f"  flow_citations_resolvable_rate  {pct(_rate(fv, 'citations_resolvable'))}",
        f"  evidence_connects_rate          {pct(_rate(fv, 'evidence_connects_endpoints'))}",
        f"  flow_all_valid_rate             {pct(_rate(fv, 'all_valid'))}",
        "",
        "Modeling convention (reported, NOT part of any correctness rate -- the verifier has no",
        "standing to adjudicate which way an analyst draws an arrow):",
        f"  direction_matches_evidence      {pct(_rate(fv, 'direction_matches_evidence'))}   "
        f"(data-flow direction; the hand DFD's own DF9 draws a read Process->DataStore)",
    ]
    if not source_checked:
        lines += ["",
                  "  NOTE: facts_present is not_checked -- no --source-root was given, so cited",
                  "  file:line locations were NOT re-parsed against the source. Only fact-id",
                  "  resolution and evidence-type consistency were verified. This is reported",
                  "  rather than silently counted as a pass."]
    failures = [v for v in ev if not v.all_valid] + [v for v in fv if not v.all_valid]
    if failures:
        lines += ["", "Failures:"]
        for v in failures:
            ident = getattr(v, "element_id", None) or getattr(v, "flow_id", "?")
            for r in v.reasons:
                lines.append(f"  {ident:5} {r}")
    return "\n".join(lines)
