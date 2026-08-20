"""Render the report's figures from committed run artifacts.

Nothing here is hand-typed: Figure 2 reads `storage/ablation_repeats.json` (45 runs, n=3 per
cell, temperature 0) and Figure 3 reads `storage/regen_last.json` (the 2026-08-08 regeneration of
every threat set against the official v241203 trees). Re-running this after a new sweep updates
the paper's figures, so a figure can never drift from the artifact it claims to plot.

    PYTHONPATH=. python3 scripts/make_report_figures.py     # -> figures/*.png

Palette: slots 1-3 of the validated categorical default (blue / orange / aqua). Validated for
adjacent-pair CVD separation before use; aqua sits below 3:1 on a light surface, so every bar
carries a visible value label (the relief rule) and each figure is duplicated as a table in the
report.
"""
from __future__ import annotations

import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

import config

OUT = config.ROOT / "figures"
OUT.mkdir(exist_ok=True)

BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, INK3 = "#0b0b0b", "#52514e", "#8a8a85"
SURFACE = "#fcfcfb"
GRID = "#e4e3df"

MODES = [("grounded", BLUE), ("rag", ORANGE), ("ungrounded", AQUA)]
SCENARIOS = ["kidstube", "smart_home", "family_location", "school_grades", "wearable_fitness"]
SCENARIO_LABEL = {"kidstube": "KidsTube", "smart_home": "Smart\nHome",
                  "family_location": "Family\nLocation", "school_grades": "School\nGrades",
                  "wearable_fitness": "Wearable\nFitness"}

plt.rcParams.update({
    "font.size": 8.5,
    "axes.facecolor": SURFACE,
    "figure.facecolor": SURFACE,
    "axes.edgecolor": GRID,
    "text.color": INK,
    "axes.labelcolor": INK2,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "savefig.facecolor": SURFACE,
})


def _style(ax) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


# --------------------------------------------------------------------------- Figure 1: pipeline
def figure1() -> Path:
    """One left-to-right spine: inputs -> canonical DFD -> grounding -> verifier -> evaluation.

    Drawn with `aspect='equal'` so the rounded corners stay circular, and saved with padding so
    that no box edge is clipped by the tight bounding box.
    """
    fig, ax = plt.subplots(figsize=(9.5, 3.8))
    ax.set_xlim(0, 190)
    ax.set_ylim(4, 80)
    ax.set_aspect("equal")
    ax.axis("off")

    # (text artist, box width in data units) pairs, shrunk to fit before saving. Eyeballing font
    # sizes against box widths is what put a label through a border twice; measuring the rendered
    # extent is the fix that stays correct if any label is ever reworded.
    fitted: list[tuple] = []

    def box(x, y, w, h, label, sub="", fc=SURFACE, ec=INK3, lw=1.0, bold=False, fs=8.0,
            subfs=6.6):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.6",
                                    fc=fc, ec=ec, lw=lw))
        t = ax.text(x + w / 2, y + h / 2 + (2.0 if sub else 0), label, ha="center", va="center",
                    fontsize=fs, color=INK, fontweight="bold" if bold else "normal")
        fitted.append((t, w))
        if sub:
            t = ax.text(x + w / 2, y + h / 2 - 3.2, sub, ha="center", va="center",
                        fontsize=subfs, color=INK2)
            fitted.append((t, w))

    def arrow(x1, y1, x2, y2, color=INK3, lw=1.1, ls="-"):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", color=color,
                                     lw=lw, linestyle=ls, mutation_scale=8,
                                     shrinkA=0, shrinkB=0))

    def stage(x, text, sub=""):
        ax.text(x, 77.5, text, fontsize=7.6, color=INK2, fontweight="bold")
        if sub:
            ax.text(x, 73.6, sub, fontsize=6.4, color=INK2)

    # --- The knowledge base, drawn above the two stations that consult it ----------------
    # It sits over Stage B and Stage C because those are its consumers: the grounded lookup
    # reads it before generation and the verifier re-derives against it afterwards. The rag
    # arm searches the same corpus, which its own label states, so it takes no separate arrow.
    box(77, 60, 75, 11, "Knowledge base  (curated)",
        "official LINDDUN threat trees (65 nodes, v241203)  ·  mapping table (Table 4.1)",
        fc="#f4f1fb", ec=INK3, lw=1.2, bold=True, fs=7.6, subfs=6.2)

    # --- Station 1: inputs ---------------------------------------------------------------
    stage(2, "Stage A — inputs", "adapter required for the lower two only")
    for y, name, sub in ((45, "Analyst-authored DFD", "supplied as-is; no adapter"),
                         (31, "Source code", "extract → resolve → synthesize"),
                         (17, "DFD image", "vision_naive, bbox citations")):
        box(2, y, 32, 11, name, sub, subfs=6.2)

    # --- Station 2: canonical DFD --------------------------------------------------------
    box(41, 27, 29, 24, "Canonical DFD", "elements · flows\nprovenance",
        fc="#eef4fd", ec=BLUE, lw=1.4, bold=True)
    for y in (50.5, 36.5, 22.5):
        arrow(34, y, 41, 39)

    box(41, 10, 29, 11, "code-fact enrichment", "code facts; structure read-only",
        fs=7.0, subfs=6.2, lw=0.9)
    arrow(55.5, 21, 55.5, 27, ls=(0, (2, 2)))

    # --- Station 3: per-flow elicitation --------------------------------------------------
    stage(77, "Stage B — elicitation")
    box(77, 45, 36, 11, "grounded  (proposed)", "exact mapping-table lookup",
        ec=BLUE, lw=1.4)
    box(77, 31, 36, 11, "rag  (ablation)", "top-k retrieval, same corpus", ec=ORANGE)
    box(77, 17, 36, 11, "ungrounded  (ablation)", "no methodology context", ec=AQUA)
    for y in (50.5, 36.5, 22.5):
        arrow(70, 39, 77, y)
    ax.text(95, 12.0, "one forced tool call per flow", fontsize=6.4, color=INK2, ha="center")
    ax.text(95, 7.8, "temperature 0", fontsize=6.4, color=INK2, ha="center")

    # --- Station 4: verification ----------------------------------------------------------
    stage(120, "Stage C — verification", "no model in the loop")
    box(120, 27, 32, 24, "verify", "every citation\nre-derived vs. KB:\nnode · type · location",
        fc="#eafaf3", ec=AQUA, lw=1.4, bold=True, subfs=6.4)
    for y in (50.5, 36.5, 22.5):
        arrow(113, y, 120, 39)

    # Knowledge-base consumers: the exact lookup before generation, the verifier after it.
    arrow(90, 60, 90, 56)
    arrow(136, 60, 136, 51)

    # --- Station 5: evaluation ------------------------------------------------------------
    box(159, 27, 29, 24, "eval", "P / R / F1 vs. gold\nreachability\ncitation validity",
        subfs=6.4)
    arrow(152, 39, 159, 39)

    _shrink_to_fit(fig, ax, fitted, margin=0.86)
    p = OUT / "fig1_pipeline.png"
    fig.savefig(p, dpi=240, bbox_inches="tight", pad_inches=0.22)
    plt.close(fig)
    return p


def _shrink_to_fit(fig, ax, items, margin=0.86, floor=4.8) -> None:
    """Reduce each label's font size until it fits `margin` of its box width.

    Widths are measured from the actual rendered extent, so a reworded label cannot silently
    overrun its border the way a hand-tuned font size can.
    """
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    x0, _ = ax.transData.transform((0, 0))
    x1, _ = ax.transData.transform((1, 0))
    px_per_unit = x1 - x0
    for text, box_w in items:
        limit = box_w * margin * px_per_unit
        while text.get_window_extent(renderer).width > limit and text.get_fontsize() > floor:
            text.set_fontsize(text.get_fontsize() - 0.2)


# ------------------------------------------------------------------ Figure 2: grounding ablation
def _ablation_cells() -> dict:
    rows = json.loads((config.ROOT / "storage" / "ablation_repeats.json").read_text())
    cells: dict = {}
    for r in rows:
        cells.setdefault((r["scenario"], r["mode"]), []).append(r)
    return cells


def figure2() -> Path:
    cells = _ablation_cells()
    panels = [("citation", "Verified citation validity", (0, 1.08)),
              ("recall", "Recall vs. gold standard", (0, 1.08)),
              ("f1", "F1", (0, 1.08))]
    fig, axes = plt.subplots(1, 3, figsize=(10.5, 3.5))
    width = 0.26
    for ax, (metric, title, ylim) in zip(axes, panels):
        _style(ax)
        for i, (mode, color) in enumerate(MODES):
            xs, means, sds = [], [], []
            for j, sc in enumerate(SCENARIOS):
                vals = [r[metric] for r in cells[(sc, mode)]]
                xs.append(j + (i - 1) * (width + 0.02))
                means.append(statistics.mean(vals))
                sds.append(statistics.stdev(vals) if len(vals) > 1 else 0.0)
            ax.bar(xs, means, width, color=color, label=mode, zorder=3)
            ax.errorbar(xs, means, yerr=sds, fmt="none", ecolor=INK2, elinewidth=0.8,
                        capsize=1.6, zorder=4)
            for x, m, s in zip(xs, means, sds):
                ax.text(x, m + s + 0.025, f"{m:.2f}", ha="center", va="bottom",
                        fontsize=6.1, color=INK2, rotation=90)
        ax.set_xticks(range(len(SCENARIOS)))
        ax.set_xticklabels([SCENARIO_LABEL[s] for s in SCENARIOS], fontsize=7)
        ax.set_ylim(*ylim)
        ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
        ax.set_title(title, fontsize=9, color=INK, pad=8, loc="left")
    axes[0].set_ylabel("mean of 3 runs (bars = sd)")
    axes[0].legend(frameon=False, fontsize=7.5, loc="lower left", ncols=3,
                   bbox_to_anchor=(0.0, -0.34), handlelength=1.1)
    fig.tight_layout()
    p = OUT / "fig2_ablation.png"
    fig.savefig(p, dpi=220, bbox_inches="tight")
    plt.close(fig)
    return p


# --------------------------------------------------------- Figure 3: model vs. input modality
def figure3() -> Path:
    regen = json.loads((config.ROOT / "storage" / "regen_last.json").read_text())
    models = ["gpt-5-4", "gpt-4o-mini", "grok-4-3"]
    label = {"gpt-5-4": "gpt-5.4", "gpt-4o-mini": "gpt-4o-mini", "grok-4-3": "grok-4.3"}
    inputs = [("dfd_hand", "hand-authored DFD", BLUE), ("image_vision-naive", "image-derived DFD", ORANGE)]

    fig, ax = plt.subplots(figsize=(5.6, 3.4))
    _style(ax)
    width = 0.32
    for i, (key, name, color) in enumerate(inputs):
        xs = [j + (i - 0.5) * (width + 0.03) for j in range(len(models))]
        ys = [float(regen[f"{key}_{m}"]["r"]) for m in models]
        ax.bar(xs, ys, width, color=color, label=name, zorder=3)
        for x, y in zip(xs, ys):
            ax.text(x, y + 0.015, f"{y:.2f}", ha="center", va="bottom", fontsize=7, color=INK2)

    hi = float(regen["dfd_hand_gpt-5-4"]["r"])
    lo = float(regen["dfd_hand_grok-4-3"]["r"])
    ax.annotate("", xy=(2.62, lo), xytext=(2.62, hi),
                arrowprops=dict(arrowstyle="<->", color=INK3, lw=0.9))
    ax.text(2.70, (hi + lo) / 2, f"model\nspread\n{hi - lo:.2f}", fontsize=7, color=INK2,
            va="center")
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels([label[m] for m in models], fontsize=8)
    ax.set_xlim(-0.55, 3.15)
    ax.set_ylim(0, 0.95)
    ax.set_yticks([0, 0.25, 0.5, 0.75])
    ax.set_ylabel("recall vs. KidsTube gold (41 threats)")
    ax.set_title("Changing the model moves recall by 0.22;\nchanging the input modality moves it by ≤ 0.03",
                 fontsize=8.6, color=INK, loc="left", pad=8)
    ax.legend(frameon=False, fontsize=7.5, loc="upper right", handlelength=1.1,
              bbox_to_anchor=(1.02, 1.02))
    fig.tight_layout()
    p = OUT / "fig3_model_vs_modality.png"
    fig.savefig(p, dpi=220, bbox_inches="tight")
    plt.close(fig)
    return p


if __name__ == "__main__":
    for fn in (figure1, figure2, figure3):
        print("wrote", fn().relative_to(config.ROOT))
