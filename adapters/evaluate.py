"""Score a derived DFD against the hand-authored one, separating adapter failure from ceiling.

This is the DFD-level analogue of eval/reachability.py, and deliberately mirrors its vocabulary
and its shape. There, a gold threat sitting on a flow the mapping table doesn't model was never
generatable, so counting it as a recall miss would blame the model for a structural fact about
the methodology. Here, a hand-authored DFD element that no code implements was never derivable,
so counting it as adapter error would blame the adapter for a structural fact about the
codebase.

For KidsTube that is not hypothetical. system_description.md marks P4 (AI Recommendation Engine)
and EE3 (Third-Party Advertisers) -- and therefore DF13 (DS2->P4) and DF14 (P4->EE3) -- as
"(planned)". They exist in the system description and in the hand DFD; they exist in no line of
Privacy-Engineering-CMU/KidsTube-PE. No source-code adapter can ever produce them, so the
ceiling is 10/12 elements and 15/17 flows.

That ceiling is computed from adapters/data/<scenario>_hand_keys.json's `implemented` flags,
which transcribe the system description's own "(planned)" markers -- it is data, not a constant
in this file. A scenario added without a maintained key map raises rather than silently
reporting a wrong ceiling.

Three buckets, exactly parallel to reachability's:
  structurally_underivable ~ structurally_unreachable : no code could produce it. The ceiling.
  derivable_but_missed     ~ reachable_but_missed     : the code has it, the adapter didn't. Real.
  unresolved_key           ~ unresolved_location      : no computable provenance key, so it could
                                                        never be matched either way. Exists so a
                                                        future scenario can't hide a gap behind a
                                                        missing key.
"""
from __future__ import annotations
from dataclasses import dataclass

from adapters.align import ElementAlignment, FlowAlignment, HandKey

DERIVABLE_BUT_MISSED = "derivable_but_missed"
STRUCTURALLY_UNDERIVABLE = "structurally_underivable"
UNRESOLVED_KEY = "unresolved_key"


@dataclass
class DerivabilityCounts:
    matched: int
    derivable_but_missed: int
    structurally_underivable: int
    unresolved_key: int

    @property
    def total(self) -> int:
        return (self.matched + self.derivable_but_missed
                + self.structurally_underivable + self.unresolved_key)

    @property
    def raw_recall(self) -> float:
        """Against every hand-authored item, including the ones no code could produce."""
        return self.matched / self.total if self.total else 0.0

    @property
    def derivable_recall(self) -> float:
        """Against only the items the adapter could ever have derived. The honest number."""
        denom = self.matched + self.derivable_but_missed
        return self.matched / denom if denom else 0.0


@dataclass
class AdapterScores:
    elements: DerivabilityCounts
    flows: DerivabilityCounts
    n_derived_elements: int
    n_derived_flows: int
    n_matched_derived_elements: int
    n_matched_derived_flows: int
    element_granularity_ratio: float
    granularity_ratio: float
    n_ambiguous_flows: int

    @property
    def element_precision_raw(self) -> float:
        """Lower bound: every unmatched derived element counted as wrong. Some will be real
        privacy surface the hand DFD simply never modeled -- KidsTube's routes/users.js exposes
        an admin-only bulk user listing that the hand analysis has no element for. Distinguishing
        those requires a human, exactly as at the threat level (eval/adjudicate.py); until that
        pass runs, this number is a floor, not a verdict."""
        return (self.n_matched_derived_elements / self.n_derived_elements
                if self.n_derived_elements else 0.0)

    @property
    def flow_precision_raw(self) -> float:
        return (self.n_matched_derived_flows / self.n_derived_flows
                if self.n_derived_flows else 0.0)


def ceiling_elements(hand_keys: dict[str, HandKey]) -> set[str]:
    return {eid for eid, hk in hand_keys.items() if not hk.implemented}


def ceiling_flows(hand_dfd: dict, underivable_elements: set[str]) -> set[str]:
    """A flow is underivable if either endpoint is. DF13 (DS2->P4) and DF14 (P4->EE3) both touch
    a planned element, so neither can be derived even though DS2 and EE3's own status differ."""
    return {f["id"] for f in hand_dfd["flows"]
            if f["source"] in underivable_elements or f["destination"] in underivable_elements}


def classify_hand_element(element_id: str, hand_keys: dict[str, HandKey]) -> str:
    """Classify one UNMATCHED hand element. Call only for elements the alignment missed --
    a matched element is matched regardless of its flags, same contract as
    eval/reachability.classify_gold_threat()."""
    hk = hand_keys[element_id]
    if not hk.implemented:
        return STRUCTURALLY_UNDERIVABLE
    if not hk.computable:
        return UNRESOLVED_KEY
    return DERIVABLE_BUT_MISSED


def element_derivability(hand_keys: dict[str, HandKey],
                         alignment: ElementAlignment) -> DerivabilityCounts:
    counts = {DERIVABLE_BUT_MISSED: 0, STRUCTURALLY_UNDERIVABLE: 0, UNRESOLVED_KEY: 0}
    for eid in hand_keys:
        if eid in alignment.hand_to_derived:
            continue
        counts[classify_hand_element(eid, hand_keys)] += 1
    return DerivabilityCounts(matched=len(alignment.hand_to_derived), **counts)


def flow_derivability(hand_dfd: dict, hand_keys: dict[str, HandKey],
                      alignment: FlowAlignment) -> DerivabilityCounts:
    underivable = ceiling_elements(hand_keys)
    unresolvable = {eid for eid, hk in hand_keys.items() if hk.implemented and not hk.computable}
    counts = {DERIVABLE_BUT_MISSED: 0, STRUCTURALLY_UNDERIVABLE: 0, UNRESOLVED_KEY: 0}
    for f in hand_dfd["flows"]:
        if f["id"] in alignment.hand_to_derived:
            continue
        endpoints = {f["source"], f["destination"]}
        if endpoints & underivable:
            counts[STRUCTURALLY_UNDERIVABLE] += 1
        elif endpoints & unresolvable:
            counts[UNRESOLVED_KEY] += 1
        else:
            counts[DERIVABLE_BUT_MISSED] += 1
    return DerivabilityCounts(matched=len(alignment.hand_to_derived), **counts)


def score(derived_dfd: dict, hand_dfd: dict, hand_keys: dict[str, HandKey],
          elements: ElementAlignment, flows: FlowAlignment) -> AdapterScores:
    return AdapterScores(
        elements=element_derivability(hand_keys, elements),
        flows=flow_derivability(hand_dfd, hand_keys, flows),
        n_derived_elements=len(derived_dfd["elements"]),
        n_derived_flows=len(derived_dfd["flows"]),
        n_matched_derived_elements=len(elements.derived_to_hand),
        n_matched_derived_flows=len(flows.derived_to_hand),
        element_granularity_ratio=elements.granularity_ratio,
        granularity_ratio=flows.granularity_ratio,
        n_ambiguous_flows=len(flows.ambiguous),
    )


def _breakdown_block(label: str, c: DerivabilityCounts, ceiling_note: str) -> list[str]:
    return [
        f"{label} derivability (hand-authored items not matched by the derived DFD):",
        f"  matched                       {c.matched:3}",
        f"  derivable_but_missed          {c.derivable_but_missed:3}   (implemented in code -- real adapter recall failure)",
        f"  structurally_underivable      {c.structurally_underivable:3}   ({ceiling_note})",
        f"  unresolved_key                {c.unresolved_key:3}   (no computable provenance key -- can never be matched)",
        f"  recall (raw, vs all {c.total:2}):        {c.raw_recall:.2f}",
        f"  recall (derivability-adjusted): {c.derivable_recall:.2f}",
    ]


def format_report(scenario: str, derived_scenario: str, s: AdapterScores,
                  elements: ElementAlignment, flows: FlowAlignment) -> str:
    lines = [
        f"Adapter evaluation: {derived_scenario} vs. hand-authored {scenario}",
        "",
        *_breakdown_block("Element", s.elements,
                          'system_description.md marks these "(planned)"; they are in no code'),
        "",
        *_breakdown_block("Flow", s.flows, "an endpoint is a planned, unimplemented element"),
        "",
        "Precision (automated lower bound -- unmatched derived items counted as wrong):",
        f"  element_precision_raw         {s.element_precision_raw:.2f}   ({s.n_matched_derived_elements}/{s.n_derived_elements})",
        f"  flow_precision_raw            {s.flow_precision_raw:.2f}   ({s.n_matched_derived_flows}/{s.n_derived_flows})",
        "",
        "Granularity (reported, never scored -- a finer view is not an error):",
        f"  element_granularity_ratio     {s.element_granularity_ratio:.2f}   (derived elements per matched hand element)",
        f"  flow_granularity_ratio        {s.granularity_ratio:.2f}   (derived flows per matched hand flow)",
        f"  ambiguous_flow_resolutions    {s.n_ambiguous_flows:3}   (same-pair hand flows split by description similarity)",
    ]
    if elements.unmatched_derived:
        lines += ["", "Unmatched derived elements (adjudicate; do not assume spurious):",
                  *(f"  {eid}" for eid in elements.unmatched_derived)]
    if elements.unmatched_hand:
        lines += ["", "Unmatched hand elements:",
                  *(f"  {eid}" for eid in elements.unmatched_hand)]
    return "\n".join(lines)
