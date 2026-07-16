"""End-to-end eval: load generated + gold threats for a scenario, match, score per LINDDUN
category, independently verify citations, classify unmatched gold threats by reachability, and
print a report."""
from __future__ import annotations
import json

import config
from generation.generate import load_generated
from generation.verify import verify_threat
from eval.match import (LOCATION_ANCHORED, gold_flow_id, gold_location_convention, match_threats)
from eval.metrics import (per_category_scores, per_node_scores, citation_correctness,
                          CATEGORY_NAMES, LINDDUN_TYPES)
from eval.reachability import reachability_breakdown
from eval.adjudicate import worklist_path, human_corrected_precision


def _node_titles() -> dict[str, str]:
    trees = json.loads((config.KB_DIR / "linddun" / "threat_trees.json").read_text())["threat_types"]
    return {nid: n.get("title", "") for tt in trees.values() for nid, n in tt.get("nodes", {}).items()}


def _load_gold(scenario: str) -> list[dict]:
    path = config.KB_DIR / "scenarios" / scenario / "gold_standard_threats.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No gold_standard_threats.json for scenario '{scenario}' -- eval requires a "
            f"gold-backed scenario (expected {path})."
        )
    return json.loads(path.read_text())["threats"]


def _load_dfd(scenario: str) -> dict:
    return json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())


def _load_panoptic_categories() -> dict[str, str]:
    cw = json.loads((config.KB_DIR / "linddun" / "panoptic_crosswalk.json").read_text())
    return cw["panoptic_categories"]


def run_eval_panoptic(scenario: str, generated_path: str) -> str:
    """PANOPTIC-framework report: matches on panoptic_action membership in the gold threat's own
    panoptic_actions list (not LINDDUN threat_type/tree_node), scored per PANOPTIC category. See
    eval/match.py::match_threats_panoptic and eval/metrics.py::per_panoptic_category_scores."""
    from eval.match import match_threats_panoptic
    from eval.metrics import per_panoptic_category_scores
    from eval.reachability import reachability_breakdown_panoptic

    generated = load_generated(generated_path)
    gold = _load_gold(scenario)
    dfd = _load_dfd(scenario)
    categories = _load_panoptic_categories()

    match = match_threats_panoptic(generated, gold, scenario=scenario, dfd=dfd)
    scores = per_panoptic_category_scores(generated, gold, match.gen_to_gold, match.matched_gold_ids)
    n_panoptic_generated = sum(1 for t in generated if t.panoptic_action)

    lines = [
        f"Eval report (PANOPTIC framework): scenario={scenario} generated={generated_path}",
        f"  n_generated={len(generated)} (with panoptic_action: {n_panoptic_generated}) n_gold={len(gold)}",
        "",
        "NOTE: matches on panoptic_action membership in the gold threat's own panoptic_actions "
        "list, plus same-flow location (dfd_source_id/dfd_destination_id) -- not LINDDUN "
        "threat_type/tree_node. See knowledge_base/panoptic/taxonomy.json and "
        "knowledge_base/linddun/panoptic_crosswalk.json.",
        "",
        f"{'Cat':<6} {'Name':<26} {'TP':>4} {'FP':>4} {'FN':>4} {'P':>6} {'R':>6} {'F1':>6}",
    ]
    tot_tp = tot_fp = tot_fn = 0
    for cat in sorted(categories):
        s = scores.get(cat)
        if s is None:
            continue
        tot_tp += s.tp
        tot_fp += s.fp
        tot_fn += s.fn
        lines.append(f"{cat:<6} {categories[cat]:<26} {s.tp:>4} {s.fp:>4} {s.fn:>4} "
                      f"{s.precision:>6.2f} {s.recall:>6.2f} {s.f1:>6.2f}")

    overall_p = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else 0.0
    overall_r = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 0.0
    overall_f1 = 2 * overall_p * overall_r / (overall_p + overall_r) if (overall_p + overall_r) else 0.0
    lines.append(f"{'ALL':<6} {'':<26} {tot_tp:>4} {tot_fp:>4} {tot_fn:>4} "
                 f"{overall_p:>6.2f} {overall_r:>6.2f} {overall_f1:>6.2f}")

    rc = reachability_breakdown_panoptic(gold, scenario, dfd, match.matched_gold_ids)
    lines.append("")
    lines.append("Reachability breakdown (gold threats not matched):")
    lines.append(f"  reachable_but_missed        {rc.reachable_but_missed:>4}   "
                  "(real recall failures -- flow valid, no LLM match)")
    lines.append(f"  unresolved_location          {rc.unresolved_location:>4}   "
                  "(no single flow to anchor to -- can never be matched)")
    lines.append("  (PANOPTIC mode has no structural-gate concept -- every flow is attempted, "
                 "so there is no structurally_unreachable count here, unlike the LINDDUN report)")
    lines.append(f"  recall (raw, vs all gold):        {overall_r:.2f}")
    lines.append(f"  recall (reachable-adjusted):      {rc.reachable_recall:.2f}   "
                  "(tp / (tp + reachable_but_missed))")
    return "\n".join(lines)


def run_eval(scenario: str, generated_path: str, strict: bool = False, by_node: bool = False,
            framework: str = "linddun") -> str:
    if framework == "panoptic":
        return run_eval_panoptic(scenario, generated_path)

    generated = load_generated(generated_path)
    gold = _load_gold(scenario)
    dfd = _load_dfd(scenario)

    match = match_threats(generated, gold, scenario=scenario, dfd=dfd, strict=strict)
    scores = per_category_scores(generated, gold, match.gen_to_gold, match.matched_gold_ids)
    verifications = [verify_threat(t, dfd) for t in generated]
    citation_stats = citation_correctness(verifications)

    lines = [
        f"Eval report: scenario={scenario} generated={generated_path}",
        f"  n_generated={len(generated)} n_gold={len(gold)} strict_node_match={strict}",
        "",
    ]
    # Which anchoring note applies is a property of the gold catalog, not of the scenario's name:
    # keying this off `scenario != "kidstube"` told kidstube_derived -- whose gold is flow-anchored
    # like the catalog it was re-anchored from -- that it was being matched on Figure 11 fields it
    # does not have. Read it from the same helper the matcher itself uses so the report cannot
    # describe a different procedure than the one that ran.
    if gold_location_convention(gold) == LOCATION_ANCHORED:
        n_unresolved = sum(1 for t in gold if t.get("dfd_location_confidence") == "unresolved")
        lines += [
            "NOTE: matching uses gold's dfd_source_id/dfd_destination_id (Appendix F Figure 11) "
            f"against the generated threat's flow in dfd.json. {n_unresolved} gold threats have "
            "dfd_location_confidence=unresolved and can never be matched (see WEEK3_REPORT.md).",
            "",
        ]
    else:
        n_unanchored = sum(1 for t in gold if not gold_flow_id(t))
        if n_unanchored:
            lines += [
                f"NOTE: matching uses the flow id embedded in gold's `interaction` (e.g. [DF1]). "
                f"{n_unanchored} gold threats carry no flow id and can never be matched -- see "
                f"this scenario's gold `_meta.unanchored_reason`.",
                "",
            ]

    lines.append(f"{'Type':<4} {'Name':<18} {'TP':>4} {'FP':>4} {'FN':>4} {'P':>6} {'R':>6} {'F1':>6}")
    tot_tp = tot_fp = tot_fn = 0
    for tt in LINDDUN_TYPES:
        s = scores[tt]
        tot_tp += s.tp
        tot_fp += s.fp
        tot_fn += s.fn
        marker = "  *" if tt in ("Nc", "U") else ""
        lines.append(f"{tt:<4} {CATEGORY_NAMES[tt]:<18} {s.tp:>4} {s.fp:>4} {s.fn:>4} "
                      f"{s.precision:>6.2f} {s.recall:>6.2f} {s.f1:>6.2f}{marker}")

    overall_p = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else 0.0
    overall_r = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 0.0
    overall_f1 = 2 * overall_p * overall_r / (overall_p + overall_r) if (overall_p + overall_r) else 0.0
    lines.append(f"{'ALL':<4} {'':<18} {tot_tp:>4} {tot_fp:>4} {tot_fn:>4} "
                 f"{overall_p:>6.2f} {overall_r:>6.2f} {overall_f1:>6.2f}")
    lines.append("(* Non-compliance and Unawareness -- flagged as hardest to automate)")
    lines.append("")
    lines.append("Citation correctness (independently verified against the knowledge base, not self-reported):")
    for k, v in citation_stats.items():
        if k == "n":
            continue
        lines.append(f"  {k:<24} {v:.2f}")
    lines.append(f"  n_threats_checked        {citation_stats['n']}")

    rc = reachability_breakdown(gold, scenario, dfd, match.matched_gold_ids)
    lines.append("")
    lines.append("Reachability breakdown (gold threats not matched):")
    lines.append(f"  reachable_but_missed        {rc.reachable_but_missed:>4}   "
                  "(real recall failures -- flow valid, no LLM match)")
    lines.append(f"  structurally_unreachable     {rc.structurally_unreachable:>4}   "
                  "(flow's element-type pair not in mapping_table.json)")
    lines.append(f"  unresolved_location          {rc.unresolved_location:>4}   "
                  "(no single flow to anchor to -- can never be matched)")
    lines.append(f"  recall (raw, vs all gold):        {overall_r:.2f}")
    lines.append(f"  recall (reachable-adjusted):      {rc.reachable_recall:.2f}   "
                  "(tp / (tp + reachable_but_missed))")

    mode = generated[0].mode if generated else None
    hcp = human_corrected_precision(tot_tp, tot_fp, worklist_path(scenario, mode)) if mode else None
    lines.append("")
    lines.append("Human-corrected precision (gold standards are curated catalogs, not exhaustive "
                 "-- automated precision above is a conservative lower bound):")
    if hcp is None:
        lines.append(f"  not available -- run `python cli.py adjudicate --scenario {scenario} "
                     f"--generated {generated_path}` to label a sample of the {tot_fp} unmatched "
                     "(FP) threats above as spurious / valid-but-uncatalogued / borderline.")
    else:
        lines.append(f"  n_fp_total={hcp.n_fp_total} n_labeled={hcp.n_labeled} "
                     f"(spurious={hcp.spurious} valid_uncatalogued={hcp.valid_uncatalogued} "
                     f"borderline={hcp.borderline})")
        lines.append(f"  precision_raw (lower bound):           {hcp.precision_raw:.2f}")
        review_note = "exact, full review" if hcp.is_full_review else "extrapolated from sample"
        lines.append(f"  precision_corrected (point estimate):  {hcp.precision_corrected:.2f}   ({review_note})")

    if by_node:
        node_scores = per_node_scores(generated, gold, match.gen_to_gold, match.matched_gold_ids)
        titles = _node_titles()
        nonzero = {n: s for n, s in node_scores.items() if s.tp or s.fp or s.fn}
        lines.append("")
        lines.append("Per-node breakdown (nonzero rows only):")
        lines.append(f"{'Node':<10} {'Title':<42} {'TP':>4} {'FP':>4} {'FN':>4}")
        for n in sorted(nonzero):
            s = nonzero[n]
            lines.append(f"{n:<10} {titles.get(n, '')[:42]:<42} {s.tp:>4} {s.fp:>4} {s.fn:>4}")
        missed = sorted((s for s in nonzero.values() if s.fn), key=lambda s: -s.fn)[:10]
        if missed:
            lines.append("")
            lines.append("Top missed tree nodes (by FN):")
            for s in missed:
                lines.append(f"  {s.threat_type:<10} {titles.get(s.threat_type, '')[:50]:<50} FN={s.fn}")
    return "\n".join(lines)
