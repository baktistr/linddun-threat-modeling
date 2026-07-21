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


def _combine_all_valid(checks: tuple) -> object:
    """Fold independent checks into one verdict that never fakes a pass.

    Any hard False loses. If nothing was a failure but every check was unrunnable (NOT_CHECKED --
    e.g. an open file:line citation verified with no --source-root to re-parse against), the verdict
    is itself NOT_CHECKED, so _rate() excludes it rather than counting the unchecked item as valid.
    A check that could not run must not be able to manufacture a 1.00 -- the same rule facts_present
    already followed, now applied to the open-vocabulary checks the llm_naive arm introduces.
    """
    if any(c is False for c in checks):
        return False
    if all(c is NOT_CHECKED for c in checks):
        return NOT_CHECKED
    return True


@dataclass
class ElementVerification:
    element_id: str
    citations_resolvable: object   # True | False | NOT_CHECKED (open citation, no source to check)
    evidence_type_consistent: object
    facts_present: object          # True | False | NOT_CHECKED
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> object:
        return _combine_all_valid((self.citations_resolvable, self.evidence_type_consistent,
                                   self.facts_present))


NOT_APPLICABLE = "not_applicable"


@dataclass
class FlowVerification:
    flow_id: str
    citations_resolvable: object
    endpoints_declared: bool
    evidence_connects_endpoints: object  # UNORDERED link; True|False|NOT_CHECKED (open, no source)
    direction_matches_evidence: object   # True | False | NOT_APPLICABLE -- a modeling convention
    facts_present: object
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> object:
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
        if not self.endpoints_declared:
            return False
        return _combine_all_valid((self.citations_resolvable, self.evidence_connects_endpoints,
                                   self.facts_present))


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


def _loc_index(reextracted: dict[str, CodeFact]) -> dict[tuple[str, int], list[CodeFact]]:
    """Re-extracted facts keyed by (file, line), so an open file:line citation can be resolved to
    the construct(s) actually parsed there -- the open-vocabulary analogue of the fact-id lookup."""
    idx: dict[tuple[str, int], list[CodeFact]] = {}
    for f in reextracted.values():
        idx.setdefault((f.file, f.line), []).append(f)
    return idx


def _source_line_counts(source_root: Path) -> dict[str, int]:
    """Lines per source file, so a cited file:line can be checked for being a REAL location before
    asking whether a construct sits there. Distinguishes 'server.js:99999 / nope.js:1 does not
    exist' (citations_resolvable) from 'server.js:5 exists but holds no modelable construct'
    (facts_present) -- two distinct ways an open citation can be wrong, mirroring the closed arm's
    id-in-vocabulary vs. construct-re-derivable split."""
    from adapters.extract import source_files
    counts: dict[str, int] = {}
    for path in source_files(source_root):
        rel = str(path.relative_to(source_root)).replace("\\", "/")
        counts[rel] = len(path.read_text(errors="replace").splitlines())
    return counts


def _resolve_item_facts(item: dict, facts_by_id: dict[str, CodeFact],
                        loc_index: dict[tuple[str, int], list[CodeFact]] | None) -> list[CodeFact]:
    """Facts an item's citations resolve to, across BOTH vocabularies.

    A fact_id resolves through the closed vocabulary; a {file, line} resolves through the
    re-extracted source (loc_index). When no source was given loc_index is None and open citations
    contribute nothing -- the caller reports the relevant checks NOT_CHECKED rather than treating an
    unresolvable open citation as resolving to nothing.
    """
    out = [facts_by_id[c] for c in _cited_ids(item) if c in facts_by_id]
    if loc_index is not None:
        for loc in _cited_locations(item):
            out.extend(loc_index.get(loc, []))
    return out


def _bad_locations(item: dict, line_counts: dict[str, int] | None) -> list[tuple[str, int]]:
    """Cited file:line pairs that are not a real location -- unknown file or line out of range.
    None line_counts means the source was not given, so no location can be checked (the caller
    turns that into NOT_CHECKED rather than a pass or a fail)."""
    if line_counts is None:
        return []
    bad = []
    for file, line in _cited_locations(item):
        n = line_counts.get(file)
        if n is None or not (1 <= line <= n):
            bad.append((file, line))
    return bad


def verify_element(element: dict, facts_by_id: dict[str, CodeFact], resolved: list[CodeFact],
                   reextracted: dict[str, CodeFact] | None,
                   loc_index: dict[tuple[str, int], list[CodeFact]] | None,
                   line_counts: dict[str, int] | None) -> ElementVerification:
    reasons: list[str] = []
    cited = _cited_ids(element)
    locations = _cited_locations(element)
    has_open = bool(locations)
    open_checkable = loc_index is not None   # open citations need a source to re-derive against

    # -- citations_resolvable: every citation points at something real. For a fact_id that means
    #    membership in the closed vocabulary (always checkable); for a file:line it means the
    #    location exists in the source at all (checkable only with --source-root).
    unresolvable_ids = [c for c in cited if c not in facts_by_id]
    for c in unresolvable_ids:
        reasons.append(f"fact id {c!r} does not exist in the fact vocabulary")
    if not cited and not locations:
        reasons.append("cites nothing at all")

    if has_open and not open_checkable:
        citations_resolvable: object = NOT_CHECKED
    else:
        bad_locs = _bad_locations(element, line_counts)
        for file, line in bad_locs:
            reasons.append(f"cited {file}:{line} is not a real source location "
                           f"(file absent or line out of range)")
        citations_resolvable = bool(cited or locations) and not unresolvable_ids and not bad_locs

    # -- evidence_type_consistent: some resolved construct actually supports the claimed type.
    supporting = SUPPORTING_CONSTRUCTS.get(element.get("type"), set())
    if has_open and not open_checkable:
        evidence_type_consistent: object = NOT_CHECKED
    else:
        evidence_type_consistent = any(f.construct in supporting for f in resolved)
        if resolved and not evidence_type_consistent:
            reasons.append(f"type {element.get('type')!r} is not supported by any cited construct "
                           f"{sorted({f.construct for f in resolved})}; expected one of "
                           f"{sorted(supporting)}")
        if not resolved:
            evidence_type_consistent = False

    # -- facts_present: re-parsing the source finds the cited construct. For a fact_id that is the
    #    committed fact re-derived by (construct, file, line); for a file:line it is a construct
    #    actually parsed at that location. Both need --source-root; without it, NOT_CHECKED.
    if reextracted is None:
        facts_present: object = NOT_CHECKED
    else:
        present_keys = {_fact_key(f) for f in reextracted.values()}
        missing = [facts_by_id[c] for c in cited
                   if c in facts_by_id and not facts_by_id[c].derived
                   and _fact_key(facts_by_id[c]) not in present_keys]
        for f in missing:
            reasons.append(f"fact {f.id} claims {f.construct} at {f.file}:{f.line}, "
                           f"but re-parsing the source finds no such construct there")
        loc_missing = [loc for loc in locations if not (loc_index or {}).get(loc)]
        for file, line in loc_missing:
            reasons.append(f"cited {file}:{line} holds no extracted construct in the re-parsed "
                           f"source")
        facts_present = not missing and not loc_missing

    return ElementVerification(element_id=element.get("id", "<no id>"),
                               citations_resolvable=citations_resolvable,
                               evidence_type_consistent=evidence_type_consistent,
                               facts_present=facts_present, reasons=reasons)


def _collections_from_facts(facts: list[CodeFact]) -> set[str]:
    out = set()
    for f in facts:
        if f.fields.get("collection"):
            out.add(f.fields["collection"])
        if f.fields.get("fs_path"):
            out.add(f.fields["fs_path"])
        if f.construct == "web_storage_access":
            out.add(f.fields.get("store"))
    return out


def _routes_from_facts(facts: list[CodeFact], route_to_mount: dict[str, str]) -> set[str]:
    """Every route fact id these facts cover, directly or via a mount they name."""
    out = set()
    mounts = set()
    for f in facts:
        if f.construct == "express_route":
            out.add(f.id)
        if f.construct == "express_mount":
            mounts.add(f.fields.get("mount_path"))
    if mounts:
        out |= {rid for rid, m in route_to_mount.items() if m in mounts}
    return out


def verify_flow(flow: dict, elements_by_id: dict[str, dict], element_facts: dict[str, list[CodeFact]],
                flow_facts: list[CodeFact], facts_by_id: dict[str, CodeFact],
                route_to_mount: dict[str, str],
                reextracted: dict[str, CodeFact] | None,
                loc_index: dict[tuple[str, int], list[CodeFact]] | None,
                line_counts: dict[str, int] | None) -> FlowVerification:
    reasons: list[str] = []
    cited = _cited_ids(flow)
    locations = _cited_locations(flow)
    has_open = bool(locations)
    open_checkable = loc_index is not None

    unresolvable_ids = [c for c in cited if c not in facts_by_id]
    for c in unresolvable_ids:
        reasons.append(f"fact id {c!r} does not exist in the fact vocabulary")
    if not cited and not locations:
        reasons.append("cites nothing at all")

    if has_open and not open_checkable:
        citations_resolvable: object = NOT_CHECKED
    else:
        bad_locs = _bad_locations(flow, line_counts)
        for file, line in bad_locs:
            reasons.append(f"cited {file}:{line} is not a real source location "
                           f"(file absent or line out of range)")
        citations_resolvable = bool(cited or locations) and not unresolvable_ids and not bad_locs

    src = elements_by_id.get(flow.get("source"))
    dst = elements_by_id.get(flow.get("destination"))
    endpoints_declared = src is not None and dst is not None
    if not endpoints_declared:
        reasons.append(f"endpoint not a declared element: {flow.get('source')} -> "
                       f"{flow.get('destination')}")

    # evidence_connects runs off the RESOLVED facts of the flow and its endpoints, so it works
    # unchanged whether those came from fact ids (closed arms) or file:line (llm_naive). It needs
    # the resolution, though: an open-cited flow verified without --source-root has no facts to run
    # it on, so it reports NOT_CHECKED rather than a fabricated pass or fail.
    direction: object = NOT_APPLICABLE
    if not endpoints_declared:
        evidence_connects: object = False
    elif has_open and not open_checkable:
        evidence_connects = NOT_CHECKED
    else:
        src_facts = element_facts.get(flow.get("source"), [])
        dst_facts = element_facts.get(flow.get("destination"), [])
        connected = False
        for f in flow_facts:
            if f.construct == "db_access":
                # Unordered: whichever endpoint is the process whose route encloses this op, the
                # other must be the collection it names. Whether the arrow then points the way
                # the data moves is a separate question, answered below.
                for proc_facts, store_facts, proc_is_source in ((src_facts, dst_facts, True),
                                                                (dst_facts, src_facts, False)):
                    route_ok = f.fields.get("route_fact_id") in _routes_from_facts(
                        proc_facts, route_to_mount)
                    store_ok = f.fields.get("collection") in _collections_from_facts(store_facts)
                    if route_ok and store_ok:
                        connected = True
                        # Data moves Process -> DataStore on a write, DataStore -> Process on a
                        # read. Recorded, not scored.
                        direction = proc_is_source == (f.fields.get("access") == "write")
                        break
                if connected:
                    break
            if f.construct in ("http_route_binding", "role_check"):
                proc_facts = dst_facts if dst.get("type") == "Process" else src_facts
                if f.fields.get("route_fact_id") in _routes_from_facts(proc_facts, route_to_mount):
                    connected = True
                    break
            if f.construct in ("multer_use", "fs_location", "express_static_mount", "fs_write"):
                store_facts = dst_facts if dst.get("type") == "DataStore" else src_facts
                if _collections_from_facts(store_facts):
                    connected = True
                    break
            if f.construct == "web_storage_access":
                store_facts = dst_facts if dst.get("type") == "DataStore" else src_facts
                if f.fields.get("store") in _collections_from_facts(store_facts):
                    connected = True
                    break
        evidence_connects = connected
        if not connected:
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
        for f in missing:
            reasons.append(f"fact {f.id} claims {f.construct} at {f.file}:{f.line}, "
                           f"but re-parsing the source finds no such construct there")
        loc_missing = [loc for loc in locations if not (loc_index or {}).get(loc)]
        for file, line in loc_missing:
            reasons.append(f"cited {file}:{line} holds no extracted construct in the re-parsed "
                           f"source")
        facts_present = not missing and not loc_missing

    return FlowVerification(flow_id=flow.get("id", "<no id>"),
                            citations_resolvable=citations_resolvable,
                            endpoints_declared=endpoints_declared,
                            evidence_connects_endpoints=evidence_connects,
                            direction_matches_evidence=direction,
                            facts_present=facts_present, reasons=reasons)


def verify_dfd(dfd: dict, facts: list[CodeFact],
               source_root: Path | None = None) -> tuple[list[ElementVerification],
                                                         list[FlowVerification]]:
    """Verify every element and flow, across both citation vocabularies.

    `source_root` given: re-run the extractor and re-parse the raw source, then check every cited
    fact id / file:line is genuinely re-derivable from the source. The strong check, and the ONLY
    way an open (llm_naive) citation can be checked at all.
    `source_root` omitted: report facts_present -- and, for open citations, citations_resolvable and
    evidence -- as NOT_CHECKED, never as True. An unavailable check that reads as a pass is the
    single easiest way to fake a 1.00, and the number would be indistinguishable from a real one.
    """
    facts_by_id = {f.id: f for f in facts}
    reextracted = _reextract(source_root) if source_root else None
    loc_index = _loc_index(reextracted) if reextracted is not None else None
    line_counts = _source_line_counts(source_root) if source_root else None

    from adapters.resolve import MountTable
    route_to_mount = {r.fact_id: r.mount_path for r in MountTable.build(facts).routes}

    elements_by_id = {e["id"]: e for e in dfd["elements"]}
    element_facts = {e["id"]: _resolve_item_facts(e, facts_by_id, loc_index)
                     for e in dfd["elements"]}
    ev = [verify_element(e, facts_by_id, element_facts[e["id"]], reextracted, loc_index, line_counts)
          for e in dfd["elements"]]
    fv = [verify_flow(f, elements_by_id, element_facts,
                      _resolve_item_facts(f, facts_by_id, loc_index), facts_by_id, route_to_mount,
                      reextracted, loc_index, line_counts)
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
