"""End-to-end eval: load generated + gold threats for a scenario, match, score per LINDDUN
category, independently verify citations, and print a report."""
from __future__ import annotations
import json

import config
from generation.generate import load_generated
from generation.verify import verify_threat
from eval.match import match_threats
from eval.metrics import per_category_scores, citation_correctness, CATEGORY_NAMES, LINDDUN_TYPES


def _load_gold(scenario: str) -> list[dict]:
    path = config.KB_DIR / "scenarios" / scenario / "gold_standard_threats.json"
    return json.loads(path.read_text())["threats"]


def _load_dfd(scenario: str) -> dict:
    return json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())


def run_eval(scenario: str, generated_path: str, strict: bool = False) -> str:
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
    if scenario != "kidstube":
        n_unresolved = sum(1 for t in gold if t.get("dfd_location_confidence") == "unresolved")
        lines += [
            "NOTE: matching uses gold's dfd_source_id/dfd_destination_id (Appendix F Figure 11) "
            f"against the generated threat's flow in dfd.json. {n_unresolved} gold threats have "
            "dfd_location_confidence=unresolved and can never be matched (see WEEK3_REPORT.md).",
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
    return "\n".join(lines)
