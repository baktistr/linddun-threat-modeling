#!/usr/bin/env python3
"""Accuracy check for the genomic gold standard against the NIST source figures.

The gold standard (knowledge_base/scenarios/genomic/gold_standard_threats.json) was
transcribed primarily from NIST Appendix G **Figure 20** (validations). This script
corroborates it against two *independent* signals:

  1. Figure 24 (Ranked Threats) — a separate transcription of node / feasibility /
     difficulty / ranking value, embedded below as FIG24.
  2. NIST's own ranking formula (SP 1800-43C Tables 18 + 19):
        ranking_value = combination_value(feasibility, difficulty) x type_weight
     This ties feasibility, difficulty, threat-type, and ranking together, so a
     wrong cell in any of them breaks the identity.

A row is CORROBORATED when Figure 20 and Figure 24 agree on node/feasibility/
difficulty AND the formula holds. Otherwise it is FLAGGED for manual inspection
against references/nist-sp-1800-43c/appendix/media/Appendix-Figure{11,20,24}.png.

Usage:  python scripts/verify_genomic.py
"""
import json
from pathlib import Path

GOLD = Path(__file__).parent.parent / "knowledge_base" / "scenarios" / "genomic" / "gold_standard_threats.json"

# NIST Table 18: combination value (feasibility x difficulty)
COMBO = {
    "Plausible":     {"Negligible": 1.0, "Minor": 0.8, "Moderate": 0.6, "Significant": 0.4, "Severe": 0.2},
    "Indeterminate": {"Negligible": 0.9, "Minor": 0.7, "Moderate": 0.5, "Significant": 0.3, "Severe": 0.1},
    "Implausible":   {"Negligible": 0.8, "Minor": 0.6, "Moderate": 0.4, "Significant": 0.2, "Severe": 0.0},
}
# NIST Table 19: LINDDUN type weight
WEIGHT = {"Dd": 1.0, "I": 0.85, "L": 0.7, "Nc": 0.5, "U": 0.5, "D": 0.3, "Nr": 0.2}

# Independent transcription of Figure 24 (Ranked Threats): id -> (node, feasibility, difficulty, ranking)
FIG24 = {
    1:("L.2.1.2","Plausible","Moderate",0.42), 2:("L.2.1.2","Plausible","Significant",0.28),
    3:("L.2.1.2","Plausible","Moderate",0.42), 4:("L.2.1.2","Plausible","Moderate",0.42),
    5:("L.2.1.2","Plausible","Minor",0.56), 6:("L.2.1.2","Plausible","Significant",0.28),
    7:("L.2.1.2","Plausible","Moderate",0.42), 8:("L.2.1.2","Plausible","Moderate",0.42),
    9:("L.2.1.2","Plausible","Significant",0.28), 10:("L.2.1.2","Plausible","Moderate",0.42),
    11:("L.2.1.2","Plausible","Moderate",0.42), 12:("L.2.1.2","Plausible","Significant",0.28),
    13:("L.2.1.2","Plausible","Moderate",0.42), 14:("L.2.2.1","Plausible","Moderate",0.42),
    15:("L.2.2.1","Plausible","Moderate",0.42), 16:("L.2.2.2","Plausible","Negligible",0.7),
    17:("L.2.2.2","Plausible","Negligible",0.7), 18:("I.1.1","Plausible","Moderate",0.51),
    19:("I.1.1","Implausible","Moderate",0.34), 20:("I.1.1","Plausible","Moderate",0.51),
    21:("I.1.1","Plausible","Moderate",0.51), 22:("I.1.1","Plausible","Moderate",0.51),
    23:("I.1.1","Plausible","Moderate",0.51), 24:("I.1.1","Implausible","Moderate",0.34),
    25:("I.1.2","Plausible","Moderate",0.51), 26:("I.2.1.1","Plausible","Moderate",0.51),
    27:("I.2.1.1","Plausible","Moderate",0.51), 28:("I.2.3","Plausible","Minor",0.68),
    29:("I.2.3","Plausible","Minor",0.68), 30:("I.2.3","Plausible","Minor",0.68),
    31:("I.2.3","Plausible","Minor",0.68), 32:("Nr.1.1","Implausible","Significant",0.04),
    33:("Nr.1.1","Plausible","Severe",0.04), 34:("Nr.1.1","Plausible","Severe",0.04),
    35:("Nr.1.1","Plausible","Significant",0.08), 36:("Nr.1.1","Plausible","Severe",0.04),
    37:("Nr.1.1","Plausible","Severe",0.04), 38:("Nr.1.1","Plausible","Significant",0.08),
    39:("Nr.1.1","Plausible","Significant",0.08), 40:("Nr.2","Implausible","Severe",0.0),
    41:("Nr.2","Implausible","Severe",0.0), 42:("D.1","Plausible","Significant",0.12),
    43:("D.1","Plausible","Significant",0.12), 44:("D.1","Implausible","Severe",0.0),
    45:("D.2","Plausible","Significant",0.12), 46:("D.2","Plausible","Significant",0.12),
    47:("D.2","Plausible","Significant",0.12), 48:("D.2","Plausible","Significant",0.12),
    49:("D.2","Plausible","Significant",0.12), 50:("Dd.2.1","Plausible","Moderate",0.6),
    51:("Dd.3.1","Plausible","Minor",0.8), 52:("Dd.3.4","Plausible","Moderate",0.6),
    53:("Dd.3.4","Plausible","Moderate",0.6), 54:("Dd.3.4","Plausible","Moderate",0.6),
    55:("Dd.4.1.2","Plausible","Minor",0.8), 56:("Dd.4.2","Plausible","Minor",0.8),
    57:("Dd.4.2","Plausible","Minor",0.8), 58:("Dd.4.2","Plausible","Minor",0.8),
    59:("U.1.1","Plausible","Severe",0.1), 60:("U.1.1","Plausible","Severe",0.1),
    61:("U.1.1","Plausible","Severe",0.1), 62:("U.1.1","Plausible","Severe",0.1),
    63:("U.1.1","Plausible","Severe",0.1), 64:("U.1.1","Plausible","Severe",0.1),
    65:("U.1.1","Plausible","Minor",0.4), 66:("U.1.1","Plausible","Minor",0.4),
    67:("U.1.1","Plausible","Minor",0.4), 68:("U.1.1","Plausible","Minor",0.4),
    69:("U.1.1","Plausible","Minor",0.4), 70:("U.1.1","Plausible","Minor",0.4),
    71:("U.1.1","Plausible","Minor",0.4), 72:("U.1.1","Plausible","Minor",0.4),
    73:("U.1.1","Plausible","Minor",0.4), 74:("U.1.1","Plausible","Minor",0.4),
    75:("U.1.1","Plausible","Minor",0.4), 76:("U.1.1","Plausible","Minor",0.4),
    77:("U.1.1","Plausible","Minor",0.4), 78:("U.1.1","Plausible","Minor",0.4),
    79:("U.1.1","Plausible","Minor",0.4), 80:("U.1.2","Plausible","Negligible",0.5),
    81:("U.1.2","Plausible","Negligible",0.5), 82:("U.1.2","Plausible","Negligible",0.5),
    83:("U.2.1","Plausible","Minor",0.4), 84:("U.2.2","Plausible","Significant",0.2),
    85:("U.2.2","Plausible","Significant",0.2), 86:("U.2.2","Plausible","Significant",0.2),
    87:("U.2.3","Plausible","Significant",0.2), 88:("U.2.3","Plausible","Significant",0.2),
    89:("U.2.3","Plausible","Significant",0.2), 90:("U.2.3","Plausible","Significant",0.2),
    91:("Nc.2","Plausible","Moderate",0.3), 92:("Nc.2","Plausible","Moderate",0.3),
    93:("Nc.2","Plausible","Moderate",0.3), 94:("Nc.2","Plausible","Moderate",0.3),
    95:("Nc.2","Plausible","Minor",0.4), 96:("Nc.4","Implausible","Moderate",0.2),
    97:("Nc.4","Plausible","Moderate",0.3), 98:("Nc.4","Plausible","Moderate",0.3),
    99:("Nc.4","Implausible","Moderate",0.2),
}


def audit(gold):
    """Return (corroborated_count, flagged) without printing. Reusable by tests."""
    corroborated, flagged = 0, []
    for t in gold:
        tid = t["id"]
        issues = []

        # formula identity (ties feasibility, difficulty, type, ranking)
        try:
            comp = round(COMBO[t["feasibility"]][t["difficulty"]] * WEIGHT[t["threat_type"]], 3)
            if abs(comp - t["ranking_value"]) >= 0.005:
                issues.append(f"formula: {t['feasibility']}x{t['difficulty']}x{t['threat_type']} -> {comp} != ranking {t['ranking_value']}")
        except KeyError as e:
            issues.append(f"formula: unknown value {e}")

        # cross-check vs Figure 24 (independent transcription)
        if tid in FIG24:
            f_node, f_feas, f_diff, f_rank = FIG24[tid]
            if f_node != t["nist_node"]:
                issues.append(f"node: Fig20={t['nist_node']} vs Fig24={f_node}")
            if f_feas != t["feasibility"]:
                issues.append(f"feasibility: Fig20={t['feasibility']} vs Fig24={f_feas}")
            if f_diff != t["difficulty"]:
                issues.append(f"difficulty: Fig20={t['difficulty']} vs Fig24={f_diff}")
            if abs(f_rank - t["ranking_value"]) >= 0.005:
                issues.append(f"ranking: gold={t['ranking_value']} vs Fig24={f_rank}")
        else:
            issues.append("no Figure 24 row to cross-check")

        if t.get("transcription_confidence") == "low":
            issues.append("description flagged low-confidence (illegible in Fig20)")

        if issues:
            flagged.append((tid, t["nist_node"], issues))
        else:
            corroborated += 1

    return corroborated, flagged


def formula_failures(flagged):
    """Subset of flagged rows whose ranking violates NIST's own formula (Tables 18/19)."""
    return [(tid, node, issues) for tid, node, issues in flagged
            if any(i.startswith("formula:") for i in issues)]


def main():
    gold = json.loads(GOLD.read_text())["threats"]
    corroborated, flagged = audit(gold)
    print(f"CORROBORATED (Fig20 == Fig24 and NIST formula holds): {corroborated}/{len(gold)}")
    print(f"FLAGGED for manual check against the source figures: {len(flagged)}\n")
    for tid, node, issues in flagged:
        print(f"  #{tid} ({node}):")
        for i in issues:
            print(f"      - {i}")
    print("\nManual check: references/nist-sp-1800-43c/appendix/media/Appendix-Figure{20,24}.png "
          "(node/feasibility/difficulty/ranking) and Figure11.png (DFD source/destination/context).")


if __name__ == "__main__":
    main()
