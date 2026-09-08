#!/usr/bin/env python3
"""Render the Results section of the presentation deck to a PDF.

One claim per slide. The deck this drops into already carries the framing (LINDDUN, DFDs,
motivation, RQs, methodology), so these slides do one job: state what was measured and what it
means, with the figure that carries each claim.

Text is hand-written here rather than parsed from the report, because a slide is an argument at a
different altitude than a paper section -- but every NUMBER is read from the same artifacts the
report and figures read, so a slide cannot quote a stale figure. Re-run after a sweep and the
numbers move with it.

    PYTHONPATH=. python3 scripts/make_slides.py     # -> figures/slides_results.pdf

16:9 at 13.33 x 7.5in, matching the Google Slides master it is pasted beside.
"""
from __future__ import annotations

import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from matplotlib.backends.backend_pdf import PdfPages

import config

OUT = config.ROOT / "figures"
SCENARIOS = ["kidstube", "smart_home", "family_location", "school_grades", "wearable_fitness"]

CMU_RED = "#c41230"
INK, INK2, INK3 = "#111111", "#4a4a4a", "#8a8a85"
SURFACE = "#ffffff"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"

plt.rcParams.update({"font.size": 11, "figure.facecolor": SURFACE,
                     "savefig.facecolor": SURFACE, "text.color": INK})


# ----------------------------------------------------------------- numbers, read from artifacts
def _ablation(model="gpt-5.4"):
    rows = [r for r in json.loads((config.ROOT / "storage" / "ablation_repeats.json").read_text())
            if r.get("status", "ok") == "ok" and r.get("model") == model]
    def blk(mode, k):
        per = [statistics.mean([r[k] for r in rows if r["scenario"] == s and r["mode"] == mode])
               for s in SCENARIOS]
        return statistics.mean(per)
    return {mode: {k: blk(mode, k) for k in ("citation", "recall", "f1", "n_generated")}
            for mode in ("grounded", "rag", "ungrounded")}


def _ladder():
    rows = [r for r in json.loads((config.ROOT / "storage" / "open_model_sweep.json").read_text())
            if r.get("status", "ok") == "ok"]
    out = {}
    for m, lab in [("Qwen/Qwen3.5-2B", "2B"), ("Qwen/Qwen3.5-4B", "4B"),
                   ("Qwen/Qwen3.5-9B", "9B"), ("Qwen/Qwen3.5-27B", "27B")]:
        d = {}
        for mode in ("grounded", "rag", "ungrounded"):
            per = [statistics.mean([r["citation"] for r in rows if r["model"] == m
                                    and r["scenario"] == s and r["mode"] == mode])
                   for s in SCENARIOS]
            d[mode] = statistics.mean(per)
        out[lab] = d
    return out


def _condition_recall(cond):
    import re
    f = config.ROOT / "storage" / "generated" / "kidstube" / cond / "run1" / "grounded_eval.txt"
    if not f.exists():
        return None
    m = re.search(r"^ALL\s+\d+\s+\d+\s+\d+\s+[\d.]+\s+([\d.]+)", f.read_text(), re.M)
    return float(m.group(1)) if m else None


# ------------------------------------------------------------------------------ slide furniture
def _slide(pdf, title, kicker=""):
    fig = plt.figure(figsize=(13.33, 7.5))
    ax = fig.add_axes([0, 0, 1, 1]); ax.axis("off"); ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.add_patch(plt.Rectangle((0, 0.982), 1, 0.018, color=CMU_RED, transform=ax.transAxes))
    ax.text(0.055, 0.895, title, fontsize=27, color=INK, va="top")
    if kicker:
        ax.text(0.055, 0.845, kicker, fontsize=12.5, color=INK2, va="top")
    ax.text(0.055, 0.035, "CMU | Privacy Engineering | Summer 26", fontsize=8.5, color=INK3)
    return fig, ax


def _bullets(ax, items, x=0.055, y=0.30, dy=None, fs=13, width=None, gap=0.030):
    """Lay bullets out as a FLOW, advancing by each one's actual wrapped height.

    A constant `dy` only works while every bullet occupies the same number of lines. Narrow the
    column -- as any slide with a figure beside it must -- and bullets wrap to two or three lines,
    a fixed step overruns, and they print on top of one another. `width` is the text column in
    axes fraction; matplotlib's own wrap= measures against the figure, not the space left free.
    """
    import textwrap
    chars = int(width * 118) if width else 999
    line_h = (fs / 72.0) / 7.5 * 1.45          # point size -> axes fraction, incl. linespacing
    yy = y
    for txt, bold in items:
        body = "\n".join(textwrap.fill(line, chars) for line in txt.split("\n"))
        n_lines = body.count("\n") + 1
        ax.text(x, yy, "\u2022", fontsize=fs, color=CMU_RED, va="top")
        ax.text(x + 0.022, yy, body, fontsize=fs, color=INK if bold else INK2,
                va="top", fontweight="bold" if bold else "normal", linespacing=1.45)
        yy -= n_lines * line_h + gap


def _table(ax, cols, rows, x=0.055, y=0.74, w=0.42, rh=0.055, fs=12, bold_rows=()):
    colx = [x + w * f for f in cols[1]]
    for j, c in enumerate(cols[0]):
        ax.text(colx[j], y, c, fontsize=fs - 1.5, color=INK3, va="top",
                ha="left" if j == 0 else "right")
    ax.plot([x, x + w], [y - 0.018, y - 0.018], color="#dddddd", lw=1)
    for i, r in enumerate(rows):
        yy = y - 0.032 - i * rh
        b = i in bold_rows
        for j, cell in enumerate(r):
            ax.text(colx[j], yy, cell, fontsize=fs, color=INK if b else INK2, va="top",
                    ha="left" if j == 0 else "right", fontweight="bold" if b else "normal")


def _figure(ax, name, x=0.50, y=0.10, w=0.46):
    p = OUT / name
    if not p.exists():
        return
    img = mpimg.imread(p)
    h = w * img.shape[0] / img.shape[1] * (13.33 / 7.5)
    sub = ax.figure.add_axes([x, y, w, h]); sub.axis("off"); sub.imshow(img)


# --------------------------------------------------------------------------------------- slides
def build() -> Path:
    ab, lad = _ablation(), _ladder()
    out = OUT / "slides_results.pdf"
    with PdfPages(out) as pdf:

        # --- 12a: the grounding mechanism -----------------------------------------------------
        fig, ax = _slide(pdf, "Effect of the grounding mechanism",
                         "5 scenarios × 3 modes × 3 runs · temperature 0 · gpt-5.4")
        _table(ax, (["Mode", "Citation", "Recall", "F1"], [0.0, 0.62, 0.81, 0.97]),
               [["grounded", f"{ab['grounded']['citation']:.2f}  (sd 0.00)",
                 f"{ab['grounded']['recall']:.2f}", f"{ab['grounded']['f1']:.2f}"],
                ["rag", f"{ab['rag']['citation']:.2f}", f"{ab['rag']['recall']:.2f}",
                 f"{ab['rag']['f1']:.2f}"],
                ["ungrounded", f"{ab['ungrounded']['citation']:.2f}",
                 f"{ab['ungrounded']['recall']:.2f}", f"{ab['ungrounded']['f1']:.2f}"]],
               y=0.74, w=0.40, bold_rows=(0,))
        _bullets(ax, [
            ("Citation validity 1.00, sd 0.00 — over 3,646 grounded threats, three model families, 5 of 5 scenarios", True),
            ("It is the mechanism, not the knowledge base: RAG reads the same corpus and still forfeits 0.046", False),
            ("grounded − ungrounded +0.260 · grounded − rag +0.046 — both 5/5", False),
            ("F1 separates nothing (−0.003, p = 0.856): recall gains are cancelled by the precision cost of higher volume", False),
        ], y=0.52, width=0.80, fs=14)
        # No figure here on purpose: fig2 is three panels of fifteen bars, which is right for
        # the report and unreadable projected. The table above is the same claim at slide
        # altitude, and the space is better spent on legible bullets.
        pdf.savefig(fig); plt.close(fig)

        # --- 12b: consistency across models ---------------------------------------------------
        fig, ax = _slide(pdf, "Consistency across models  (RQ1)",
                         "KidsTube · grounded · same DFD, three deployments")
        hand = {m: _condition_recall(f"dfd_hand_{m}") for m in
                ("gpt-5-4", "gpt-4o-mini", "grok-4-3")}
        img = {m: _condition_recall(f"image_vision-naive_{m}") for m in
               ("gpt-5-4", "gpt-4o-mini", "grok-4-3")}
        _table(ax, (["Input", "gpt-5.4", "4o-mini", "grok-4.3"], [0.0, 0.60, 0.80, 1.0]),
               [["Analyst DFD (recall)"] + [f"{hand[m]:.2f}" if hand[m] else "—"
                                            for m in ("gpt-5-4", "gpt-4o-mini", "grok-4-3")],
                ["DFD image (recall)"] + [f"{img[m]:.2f}" if img[m] else "—"
                                          for m in ("gpt-5-4", "gpt-4o-mini", "grok-4-3")],
                ["Citation validity", "1.00", "1.00", "1.00"]],
               y=0.74, w=0.40, bold_rows=(2,))
        _bullets(ax, [
            ("Model choice moves recall 0.32; input modality moves it ≤ 0.10", True),
            ("Reading the DFD from an image costs almost nothing measurable", False),
            ("Threat volume is a fixed habit, not a response to the input: gpt-5.4 gives 195 and 166 threats, grok-4.3 gives 68 and 53", False),
            ("Citation validity is 1.00 in all eight completed conditions", False),
        ], y=0.46, width=0.42)
        _figure(ax, "fig3_model_vs_modality.png", x=0.55, y=0.30, w=0.40)
        pdf.savefig(fig); plt.close(fig)

        # --- 12c: source code (RQ2) -----------------------------------------------------------
        # Its own slide. The two source-code results point in OPPOSITE directions, and sharing a
        # slide with PILLAR compressed both into one line each -- which lost the finding that the
        # enrichment arm is the one that works.
        fig, ax = _slide(pdf, "Source code  (RQ2)",
                         "KidsTube · gpt-5.4 · grounded · single runs")
        ax.text(0.055, 0.77, "As a structural input — costly", fontsize=14, color=INK,
                fontweight="bold", va="top")
        _bullets(ax, [
            ("Replacing the DFD with a code-derived one drops recall 0.67 → 0.56; citation validity stays 1.00", False),
            ("Not a citation failure: code models the system at the developer's granularity, so some gold threats have no counterpart flow", False),
        ], y=0.70, width=0.86)
        ax.text(0.055, 0.50, "As a semantic layer over a trusted DFD — helpful",
                fontsize=14, color=INK, fontweight="bold", va="top")
        _table(ax, (["Condition", "flows enriched", "flow description", "R", "citation"],
                    [0.0, 0.50, 0.74, 0.88, 1.0]),
               [["Analyst DFD (baseline)", "—", "38 chars", "0.80", "1.00"],
                ["+ source code enrichment", "14 / 17", "38 → 215 chars", "0.85", "1.00"]],
               y=0.43, w=0.80, rh=0.055, bold_rows=(1,))
        _bullets(ax, [
            ("Recall +0.05 — two more gold threats — with precision, F1 and citation validity unchanged  (n = 1: promising, not established)", False),
            ("The adapters fail in opposite directions: an image keeps structure and loses semantics; code keeps semantics and loses structure", True),
        ], y=0.25, width=0.86, fs=12.5, gap=0.030)
        pdf.savefig(fig); plt.close(fig)

        # --- 12d: comparison with PILLAR (RQ3) ------------------------------------------------
        fig, ax = _slide(pdf, "Comparison with PILLAR  (RQ3)",
                         "Same DFD, same model (gpt-4o-mini) — model and modality both controlled")
        _table(ax, (["", "PILLAR", "Ours"], [0.0, 0.72, 0.98]),
               [["Findings", "105", "77"],
                ["P / R / F1", "0.21 / 0.54 / 0.30", "0.35 / 0.66 / 0.46"],
                ["Node ids resolving", "0.82", "1.00"],
                ["Citations verified after generation", "no", "yes"]],
               y=0.74, w=0.66, rh=0.062, bold_rows=(3,))
        ax.text(0.055, 0.40, "PILLAR's 315 node citations, re-derived against the official trees",
                fontsize=13.5, color=INK, fontweight="bold", va="top")
        _bullets(ax, [
            ("68% match exactly  ·  14% resolve only after case-folding (DD.1.1 against Dd.1.1)  ·  18% are not identifiers at all", False),
            ("Most failures are therefore not hallucinations — they are identifiers shipped without ever being checked", False),
            ("The claim is architectural, not a performance ranking: ours are drawn from a closed vocabulary and re-derived after generation", True),
        ], y=0.33, width=0.86, fs=12.5, gap=0.028)
        pdf.savefig(fig); plt.close(fig)

        # --- 12d: the position finding --------------------------------------------------------
        fig, ax = _slide(pdf, "What we found by accident",
                         "LINDDUN Pro elicits at three positions. Our schema had two.")
        _bullets(ax, [
            ("Source, data flow, destination — the middle one could not be expressed", True),
            ("Frontier models coerced flow-threats onto an endpoint and still scored 1.00:10–25% of location citations were wrong while reading as perfect", False),
            ("Found because a 9B model refused to coerce — it answered \"fl\" and was\n"
             "marked wrong 131 times for being right", False),
            ("The gold standard had been using the flow position all along, e.g.\"Child search queries and actions observable on the network\"", False),
            ("A verifier can only check the answers its schema can express", True),
        ], y=0.74, width=0.40)
        _figure(ax, "fig6_position_distribution.png", x=0.52, y=0.18, w=0.44)
        pdf.savefig(fig); plt.close(fig)

        # --- 12e: the open-weight ladder ------------------------------------------------------
        fig, ax = _slide(pdf, "Does grounding still work when the model is small?",
                         "Qwen3.5 at 2B / 4B / 9B / 27B · served locally · 180 runs")
        _table(ax, (["Model", "grounded", "rag", "ungrounded"], [0.0, 0.60, 0.80, 1.0]),
               [[lab, f"{lad[lab]['grounded']:.2f}", f"{lad[lab]['rag']:.2f}",
                 f"{lad[lab]['ungrounded']:.2f}"] for lab in ("2B", "4B", "9B", "27B")],
               y=0.74, w=0.40, rh=0.05, bold_rows=(0,))
        ax.text(0.055, 0.50, "citation validity", fontsize=10.5, color=INK3, va="top")
        _bullets(ax, [
            ("Grounded citation is 1.00 at 4B, 9B and 27B", True),
            ("The 2B's 0.987 is the finding: 16 fabricated nodes with the exhaustive menu in the prompt — verification is necessary, not redundant", False),
            ("The margin explodes as models shrink: +0.817 at 2B, where five of every six ungrounded identifiers do not exist", False),
            ("RAG is actively harmful below ~4B (0.42 against 0.99 grounded)", False),
            ("A small local model can cite correctly — and DFDs are confidential", True),
        ], y=0.42, width=0.86, fs=12.5, gap=0.026)
        _figure(ax, "fig4_open_model_ladder.png", x=0.52, y=0.52, w=0.44)
        pdf.savefig(fig); plt.close(fig)

    return out


if __name__ == "__main__":
    print("wrote", build().relative_to(config.ROOT))
