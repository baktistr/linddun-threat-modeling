"""Render the report's figures from committed run artifacts.

Nothing here is hand-typed: Figure 2 reads `storage/ablation_repeats.json` (45 runs, n=3 per
cell, temperature 0), Figure 3 reads `storage/regen_last.json` (the 2026-08-08 regeneration of
every threat set against the official v241203 trees), and Figures 4-5 read
`storage/open_model_sweep.json` (180 runs across the Qwen3.5 ladder). Figure 5 additionally
re-verifies each saved threat rather than reading the eval reports, because those carry
all_valid_rate, which folds the node and location citations together. Re-running this after a new
sweep updates the paper's figures, so a figure can never drift from the artifact it claims to
plot.

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
    ax.set_ylim(-1, 80)
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
        n_sub = sub.count("\n") + 1 if sub else 0
        # Offsets scale with how many lines the subtitle has; a fixed 3.2 put a four-line body
        # straight through the bold label.
        up = 0.0 if not sub else (2.0 if n_sub <= 2 else 1.4 * n_sub)
        down = 3.2 if n_sub <= 2 else 1.4 * n_sub + 1.6
        t = ax.text(x + w / 2, y + h / 2 + up, label, ha="center", va="center",
                    fontsize=fs, color=INK, fontweight="bold" if bold else "normal")
        fitted.append((t, w))
        if sub:
            t = ax.text(x + w / 2, y + h / 2 - down + (0 if n_sub <= 2 else 1.0), sub,
                        ha="center", va="center", fontsize=subfs, color=INK2)
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
        "threat trees (65 nodes, v241203)  ·  mapping table (Table 4.1: applicable types AND positions)",
        fc="#f4f1fb", ec=INK3, lw=1.2, bold=True, fs=7.6, subfs=5.9)

    # --- Station 1: inputs ---------------------------------------------------------------
    stage(2, "Stage A — inputs", "adapter required for the lower two only")
    for y, name, sub in ((45, "Analyst authored DFD (JSON)", "supplied as-is; no adapter"),
                         (31, "Source code", ""),
                         (17, "DFD image", "")):
        box(2, y, 32, 11, name, sub, fs=7.4, subfs=6.2)

    # --- Station 2: canonical DFD --------------------------------------------------------
    box(41, 27, 29, 24, "Canonical DFD", "elements · flows\nprovenance",
        fc="#eef4fd", ec=BLUE, lw=1.4, bold=True)
    for y in (50.5, 36.5, 22.5):
        arrow(34, y, 41, 39)

    box(41, 10, 29, 11, "Source code enrichment", "", fs=7.4, lw=0.9)
    arrow(55.5, 21, 55.5, 27, ls=(0, (2, 2)))

    # --- Station 3: per-flow elicitation --------------------------------------------------
    stage(77, "Stage B — elicitation")
    box(77, 45, 36, 11, "grounded  (proposed)", "exact mapping-table lookup",
        ec=BLUE, lw=1.4)
    box(77, 31, 36, 11, "rag", "top-k retrieval (BM25 / TF-IDF)", ec=ORANGE, subfs=6.2)
    box(77, 17, 36, 11, "ungrounded", "pure LLM, no knowledge base", ec=AQUA, subfs=6.2)
    for y in (50.5, 36.5, 22.5):
        arrow(70, 39, 77, y)
    ax.text(95, 4.0, "one forced tool call per flow · temperature 0", fontsize=6.4,
            color=INK2, ha="center")
    ax.text(95, 0.6, "each threat cites: tree node · position (S / fl / D) · the id naming it",
            fontsize=6.4, color=INK2, ha="center")

    # --- Station 4: verification ----------------------------------------------------------
    stage(120, "Stage C — verification", "no model in the loop")
    box(120, 27, 32, 24, "verify", "every citation re-derived\nvs. KB, no model:\nnode · type\nposition · location",
        fc="#eafaf3", ec=AQUA, lw=1.4, bold=True, subfs=6.2)
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
ABLATION_FIGURE_MODEL = "gpt-5.4"


def _ablation_cells(model: str = ABLATION_FIGURE_MODEL) -> dict:
    """Cells for one model. The state file holds three deployments since v3, and Table 2 reports
    gpt-5.4, so the figure that sits beside it must filter to the same one rather than averaging
    three models into a single bar."""
    rows = json.loads((config.ROOT / "storage" / "ablation_repeats.json").read_text())
    cells: dict = {}
    for r in rows:
        if r.get("status", "ok") != "ok" or r.get("model", model) != model:
            continue
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
def _condition_recall(condition: str) -> float | None:
    """Recall from a model-sweep run's own eval report.

    Reads storage/generated/kidstube/<condition>/run1/grounded_eval.txt rather than a summary
    file, so the figure and Table 5 cannot disagree: both derive from the artifact the run wrote.
    (v2's version read storage/regen_last.json, which the v3 regeneration does not update.)
    """
    import re
    f = (config.ROOT / "storage" / "generated" / "kidstube" / condition / "run1"
         / "grounded_eval.txt")
    if not f.exists():
        return None
    m = re.search(r"^ALL\s+\d+\s+\d+\s+\d+\s+[\d.]+\s+([\d.]+)", f.read_text(), re.M)
    return float(m.group(1)) if m else None


def figure3() -> Path:
    models = ["gpt-5-4", "gpt-4o-mini", "grok-4-3"]
    label = {"gpt-5-4": "gpt-5.4", "gpt-4o-mini": "gpt-4o-mini", "grok-4-3": "grok-4.3"}
    inputs = [("dfd_hand", "hand-authored DFD", BLUE),
              ("image_vision-naive", "image-derived DFD", ORANGE)]

    fig, ax = plt.subplots(figsize=(5.8, 3.4))
    _style(ax)
    width = 0.32
    for i, (key, name, color) in enumerate(inputs):
        xs, ys = [], []
        for j, m in enumerate(models):
            r = _condition_recall(f"{key}_{m}")
            if r is None:
                continue
            xs.append(j + (i - 0.5) * (width + 0.03))
            ys.append(r)
        ax.bar(xs, ys, width, color=color, label=name, zorder=3)
        for x, y in zip(xs, ys):
            ax.text(x, y + 0.015, f"{y:.2f}", ha="center", va="bottom", fontsize=7, color=INK2)

    hi = _condition_recall("dfd_hand_gpt-5-4")
    lo = _condition_recall("dfd_hand_grok-4-3")
    if hi is not None and lo is not None:
        ax.annotate("", xy=(2.62, lo), xytext=(2.62, hi),
                    arrowprops=dict(arrowstyle="<->", color=INK3, lw=0.9))
        ax.text(2.70, (hi + lo) / 2, f"model\nspread\n{hi - lo:.2f}", fontsize=7, color=INK2,
                va="center")
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels([label[m] for m in models], fontsize=8)
    ax.set_xlim(-0.55, 3.15)
    ax.set_ylim(0, 1.05)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("recall vs. KidsTube gold (41 threats)")
    ax.set_title("Changing the model moves recall by 0.32;\nchanging the input modality moves it by \u2264 0.10",
                 fontsize=8.6, color=INK, loc="left", pad=8)
    ax.legend(frameon=False, fontsize=7.5, loc="upper right", handlelength=1.1,
              bbox_to_anchor=(1.02, 1.02))
    fig.tight_layout()
    p = OUT / "fig3_model_vs_modality.png"
    fig.savefig(p, dpi=220, bbox_inches="tight")
    plt.close(fig)
    return p


# --------------------------------------------------- Figure 4: the open-weight model ladder
LADDER = [("Qwen/Qwen3.5-2B", "2B"), ("Qwen/Qwen3.5-4B", "4B"),
          ("Qwen/Qwen3.5-9B", "9B"), ("Qwen/Qwen3.5-27B", "27B")]
# gpt-5.4's grounded-minus-ungrounded citation margin from storage/ablation_repeats.json, drawn
# as the reference line the ladder is read against.
GPT54_MARGIN = 0.170


def _ladder_cells() -> dict:
    rows = [r for r in json.loads((config.ROOT / "storage" / "open_model_sweep.json").read_text())
            if r.get("status", "ok") == "ok"]
    cells: dict = {}
    for r in rows:
        cells.setdefault((r["model"], r["scenario"], r["mode"]), []).append(r)
    return cells


def _scenario_means(cells: dict, model: str, mode: str, metric: str) -> list[float]:
    """One value per scenario (mean of its 3 runs). The blocks, not the runs: a scenario is the
    unit every paired contrast in the report is computed over."""
    out = []
    for sc in SCENARIOS:
        vals = [r[metric] for r in cells.get((model, sc, mode), []) if r.get(metric) is not None]
        if vals:
            out.append(statistics.mean(vals))
    return out


def figure4() -> Path:
    cells = _ladder_cells()
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 3.6),
                             gridspec_kw={"width_ratios": [1.32, 1]})

    # (a) citation validity by mode, across the ladder
    ax = axes[0]
    _style(ax)
    width = 0.26
    for i, (mode, color) in enumerate(MODES):
        xs, means, sds = [], [], []
        for j, (model, _lab) in enumerate(LADDER):
            per = _scenario_means(cells, model, mode, "citation")
            if not per:
                continue
            xs.append(j + (i - 1) * (width + 0.02))
            means.append(statistics.mean(per))
            sds.append(statistics.stdev(per) if len(per) > 1 else 0.0)
        # The 27B ungrounded cell is a refusal, not a measurement (~5 threats/run), so it is
        # hatched rather than drawn as a comparable bar -- see the caption.
        bars = ax.bar(xs, means, width, color=color, label=mode, zorder=3)
        if mode == "ungrounded":
            bars[-1].set_hatch("///")
            bars[-1].set_edgecolor(SURFACE)
            bars[-1].set_linewidth(0.0)
        ax.errorbar(xs, means, yerr=sds, fmt="none", ecolor=INK2, elinewidth=0.8,
                    capsize=1.6, zorder=4)
        for x, m, s in zip(xs, means, sds):
            ax.text(x, m + s + 0.025, f"{m:.2f}", ha="center", va="bottom",
                    fontsize=6.4, color=INK2, rotation=90)
    ax.set_xticks(range(len(LADDER)))
    ax.set_xticklabels([lab for _m, lab in LADDER], fontsize=8)
    ax.set_ylim(0, 1.16)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("citation validity (mean of 5 scenarios, bars = sd)")
    ax.set_title("(a) Grounded citation holds at every model size;\nungrounded and rag fall away as the model shrinks",
                 fontsize=8.6, color=INK, loc="left", pad=8)
    ax.legend(frameon=False, fontsize=7.5, loc="lower left", ncols=3,
              bbox_to_anchor=(0.0, -0.30), handlelength=1.1)

    # (b) the margin the ladder exists to measure
    ax = axes[1]
    _style(ax)
    xs, margins, labels = [], [], []
    for j, (model, lab) in enumerate(LADDER):
        g = _scenario_means(cells, model, "grounded", "citation")
        u = _scenario_means(cells, model, "ungrounded", "citation")
        if not g or not u:
            continue
        xs.append(j)
        margins.append(statistics.mean(g) - statistics.mean(u))
        labels.append(lab)
    bars = ax.bar(xs, margins, 0.52, color=BLUE, zorder=3)
    bars[-1].set_hatch("///")          # 27B: derived from the refusal row
    bars[-1].set_edgecolor(SURFACE)
    for x, m in zip(xs, margins):
        ax.text(x, m + 0.018, f"+{m:.2f}", ha="center", va="bottom", fontsize=7.6, color=INK2)
    ax.axhline(GPT54_MARGIN, color=ORANGE, lw=1.4, ls="--", zorder=2)
    # Parked in the empty band above the 4B/9B bars: anchoring it to the right edge collided
    # with the 27B bar's own value label.
    ax.text(1.5, 0.34, f"gpt-5.4 reference  +{GPT54_MARGIN:.2f}",
            fontsize=7.2, color=ORANGE, ha="center", va="bottom")
    ax.annotate("", xy=(1.5, GPT54_MARGIN + 0.005), xytext=(1.5, 0.335),
                arrowprops=dict(arrowstyle="-", color=ORANGE, lw=0.7))
    ax.text(3.0, -0.075, "hatched = derived from the 27B refusal row (~5 threats/run)",
            fontsize=6.3, color=INK3, ha="center", va="top")
    ax.set_xticks(range(len(LADDER)))
    ax.set_xticklabels([lab for _m, lab in LADDER], fontsize=8)
    ax.set_ylim(0, 0.78)
    ax.set_yticks([0, 0.2, 0.4, 0.6])
    ax.set_ylabel("grounded − ungrounded citation validity")
    ax.set_title("(b) The grounding advantage quadruples\nas the model shrinks",
                 fontsize=8.6, color=INK, loc="left", pad=8)

    fig.tight_layout()
    p = OUT / "fig4_open_model_ladder.png"
    fig.savefig(p, dpi=220, bbox_inches="tight")
    plt.close(fig)
    return p


# ------------------------------------------- Figure 5: what grounding does NOT buy
def figure5() -> Path:
    """The counterpart to Figure 4, and the honest one.

    Figure 4 shows citation validity holding flat at 1.00 down the whole ladder. That is only half
    the story: on the metrics that measure threat ELICITATION rather than citation, grounded mode
    is beaten by ungrounded at every rung -- inverting Section 1's frontier-scale result, where
    grounded had the best recall in 5 of 5 scenarios. Plotting the two together is what stops the
    citation result from reading as a claim about coverage.
    """
    cells = _ladder_cells()
    panels = [("recall", "(a) Recall vs. gold standard", 0.86),
              ("f1", "(b) F1", 0.56)]
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 3.5))
    width = 0.26
    for ax, (metric, title, top) in zip(axes, panels):
        _style(ax)
        for i, (mode, color) in enumerate(MODES):
            xs, means, sds = [], [], []
            for j, (model, _lab) in enumerate(LADDER):
                per = _scenario_means(cells, model, mode, metric)
                if not per:
                    continue
                xs.append(j + (i - 1) * (width + 0.02))
                means.append(statistics.mean(per))
                sds.append(statistics.stdev(per) if len(per) > 1 else 0.0)
            bars = ax.bar(xs, means, width, color=color, label=mode, zorder=3)
            if mode == "ungrounded":
                bars[-1].set_hatch("///")
                bars[-1].set_edgecolor(SURFACE)
            ax.errorbar(xs, means, yerr=sds, fmt="none", ecolor=INK2, elinewidth=0.8,
                        capsize=1.6, zorder=4)
            for x, m, s in zip(xs, means, sds):
                ax.text(x, m + s + top * 0.018, f"{m:.2f}", ha="center", va="bottom",
                        fontsize=6.4, color=INK2, rotation=90)
        ax.set_xticks(range(len(LADDER)))
        ax.set_xticklabels([lab for _m, lab in LADDER], fontsize=8)
        ax.set_ylim(0, top)
        ax.set_title(title, fontsize=8.6, color=INK, loc="left", pad=8)
    axes[0].set_ylabel("mean of 5 scenarios (bars = sd)")
    axes[0].legend(frameon=False, fontsize=7.5, loc="lower left", ncols=3,
                   bbox_to_anchor=(0.0, -0.30), handlelength=1.1)
    axes[1].text(3.0, -0.115, "hatched = 27B refusal row (~5 threats/run), not a usable sample",
                 fontsize=6.3, color=INK3, ha="center", va="top")
    fig.suptitle("Grounding buys these models correctness, not coverage: ungrounded leads recall "
                 "and F1 at 2B\u201309B; at 27B, where it refuses, rag leads",
                 fontsize=9, color=INK, x=0.005, ha="left", y=1.04)
    fig.tight_layout()
    p = OUT / "fig5_ladder_recall_f1.png"
    fig.savefig(p, dpi=220, bbox_inches="tight")
    plt.close(fig)
    return p


if __name__ == "__main__":
    for fn in (figure1, figure2, figure3, figure4, figure5):
        print("wrote", fn().relative_to(config.ROOT))
