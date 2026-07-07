"""Renders a scenario's dfd.json as a PNG using standard DFD notation (rectangle = External
Entity, circle = Process, open-topped/bottomed bar = Data Store), matching LINDDUN Pro's own
diagram style. Reachability (solid vs. dashed-red arrow) is computed live via
retrieval/interaction_context.py's effective_type(), so the diagram can't silently drift out of
sync with the actual pipeline behavior.

Layout is manually specified per scenario (POSITIONS below) rather than auto-laid-out -- these
are small, hand-authored demo DFDs, and a manual layout reads far more like a "real" DFD than a
force-directed graph does. Edge labels use a per-flow (side, offset) tuple to place each label on
a chosen perpendicular side of its edge at a chosen distance, since generic collision-avoidance
isn't worth it for eight or nine hand-placed edges.

Run: PYTHONPATH=. python3 scripts/render_dfd.py
"""
from __future__ import annotations
import json
import math

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Ellipse, FancyArrowPatch

import config
from retrieval.interaction_context import get_interaction_context, effective_type

# id -> (x, y). Spread out generously -- labels need room.
POSITIONS = {
    "smart_home": {
        "EE1": (0.0, 5.2), "EE2": (0.0, 0.2),
        "P1": (3.6, 3.2), "P2": (7.4, 3.2),
        "DS1": (3.6, -1.6), "DS2": (7.4, -1.6),
        "EE3": (12.0, 3.2),
    },
    "telehealth_demo": {
        "EE1": (0.0, 6.5), "EE2": (0.0, 2.0), "EE4": (0.0, -3.5),
        "P1": (6.0, 6.5), "DS1": (5.5, 2.0), "P2": (12.0, 2.0),
        "DS2": (7.5, -3.5),
        "EE3": (13.0, 6.5), "EE5": (14.5, -3.5),
    },
}

# per-flow curvature override (arc3 rad); default 0.12. Higher values bow an edge further out,
# used for long edges that must visually clear an intermediate node sitting between them.
RAD_OVERRIDE = {
    "telehealth_demo": {"DF4": 0.45},
}

# short human labels for edges (full descriptions live in dfd.json/system_description.md)
EDGE_LABELS = {
    "smart_home": {
        "DF1": "register / enroll devices", "DF2": "guest access code",
        "DF3": "write sensor events", "DF4": "upload video clips",
        "DF5": "motion alert", "DF6": "push notification",
        "DF7": "usage analytics", "DF8": "retrieve clip",
    },
    "telehealth_demo": {
        "DF1": "submit vitals", "DF2": "store vitals",
        "DF3": "review/annotate EHR", "DF4": "relay genetic results",
        "DF5": "upload sequencing report", "DF6": "pull results",
        "DF7": "risk alert", "DF8": "read vitals history",
        "DF9": "billing/coverage audit",
    },
}

# per-flow (side, distance) for label placement: side is +1/-1 (which perpendicular direction),
# distance nudges along the edge itself (0.5 = midpoint) to separate labels on edges that share
# an endpoint. Tuned by hand after a first render; flows not listed default to (1, 0.5).
LABEL_PLACEMENT = {
    "smart_home": {
        "DF1": (1, 0.42), "DF6": (1, 0.62),
        "DF3": (-1, 0.5), "DF4": (1, 0.5), "DF8": (-1, 0.5),
        "DF5": (1, 0.5), "DF7": (1, 0.5),
        "DF2": (1, 0.5),
    },
    "telehealth_demo": {
        "DF1": (1, 0.5), "DF2": (1, 0.5), "DF3": (1, 0.5),
        "DF4": (1, 0.5, 0.95), "DF7": (1, 0.65),
        "DF5": (1, 0.5), "DF6": (1, 0.22), "DF8": (-1, 0.6),
        "DF9": (-1, 0.68),
    },
}

ROLE_COLOR = {"internal_staff": "#cfe3ff", "external_party": "#f2f2f2"}
EE_DEFAULT_COLOR = "#f2f2f2"
PROCESS_COLOR = "#d9f2d9"
STORE_COLOR = "#fff6cf"


def _entity_size(name: str) -> tuple[float, float]:
    return max(2.2, 0.145 * len(name) + 0.5), 0.9


def _process_size(name: str) -> tuple[float, float]:
    return max(2.4, 0.155 * len(name) + 0.7), 1.15


def _store_size(name: str) -> float:
    return max(2.4, 0.145 * len(name) + 0.5)


def _draw_external_entity(ax, x, y, name, role):
    w, h = _entity_size(name)
    color = ROLE_COLOR.get(role, EE_DEFAULT_COLOR)
    ax.add_patch(Rectangle((x - w / 2, y - h / 2), w, h, facecolor=color,
                            edgecolor="black", linewidth=1.4, zorder=2))
    ax.text(x, y, name, ha="center", va="center", fontsize=9.5, zorder=3)
    return w, h


def _draw_process(ax, x, y, name):
    w, h = _process_size(name)
    ax.add_patch(Ellipse((x, y), w, h, facecolor=PROCESS_COLOR,
                          edgecolor="black", linewidth=1.4, zorder=2))
    ax.text(x, y, name, ha="center", va="center", fontsize=9.5, zorder=3)
    return w, h


def _draw_datastore(ax, x, y, name):
    w = _store_size(name)
    ax.add_patch(Rectangle((x - w / 2, y - 0.4), w, 0.8, facecolor=STORE_COLOR,
                            edgecolor="none", zorder=1))
    ax.plot([x - w / 2, x + w / 2], [y + 0.4, y + 0.4], color="black", linewidth=1.4, zorder=2)
    ax.plot([x - w / 2, x + w / 2], [y - 0.4, y - 0.4], color="black", linewidth=1.4, zorder=2)
    ax.text(x, y, name, ha="center", va="center", fontsize=9.5, zorder=3)
    return w, 0.8


def _node_edge_point(x0, y0, x1, y1, half_w, half_h):
    """Trim the arrow endpoint to the (rectangular-ish) boundary of the node's shape."""
    dx, dy = x1 - x0, y1 - y0
    if dx == 0 and dy == 0:
        return x0, y0
    # scale so the point lands on the node's bounding box edge along this direction
    tx = abs(half_w / dx) if dx != 0 else float("inf")
    ty = abs(half_h / dy) if dy != 0 else float("inf")
    t = min(tx, ty) * 1.08  # small margin so the arrow visibly detaches from the shape
    return x0 + dx * t, y0 + dy * t


def render(scenario: str, out_path=None):
    dfd = json.loads((config.KB_DIR / "scenarios" / scenario / "dfd.json").read_text())
    elements = {e["id"]: e for e in dfd["elements"]}
    positions = POSITIONS[scenario]
    labels = EDGE_LABELS.get(scenario, {})
    placement = LABEL_PLACEMENT.get(scenario, {})
    rad_override = RAD_OVERRIDE.get(scenario, {})

    fig, ax = plt.subplots(figsize=(13, 8.5))

    # pre-compute each node's half-width/half-height for edge trimming
    sizes = {}
    for eid, e in elements.items():
        if eid not in positions:
            continue
        if e["type"] == "ExternalEntity":
            w, h = _entity_size(e["name"])
        elif e["type"] == "Process":
            w, h = _process_size(e["name"])
        else:
            w, h = _store_size(e["name"]), 0.8
        sizes[eid] = (w / 2 + 0.12, h / 2 + 0.12)

    for flow in dfd["flows"]:
        src_id, dst_id = flow["source"], flow["destination"]
        src, dst = elements[src_id], elements[dst_id]
        x0, y0 = positions[src_id]
        x1, y1 = positions[dst_id]
        ctx = get_interaction_context(effective_type(src), effective_type(dst))
        reachable = ctx.valid
        p0 = _node_edge_point(x0, y0, x1, y1, *sizes[src_id])
        p1 = _node_edge_point(x1, y1, x0, y0, *sizes[dst_id])
        rad = rad_override.get(flow["id"], 0.12)
        style = dict(arrowstyle="-|>", mutation_scale=16, linewidth=1.7,
                     connectionstyle=f"arc3,rad={rad}", zorder=1,
                     color="black" if reachable else "#c62828",
                     linestyle="solid" if reachable else (0, (5, 3)))
        ax.add_patch(FancyArrowPatch(p0, p1, **style))

        side, t, *rest = placement.get(flow["id"], (1, 0.5))
        dist = rest[0] if rest else 0.32
        px, py = x0 + (x1 - x0) * t, y0 + (y1 - y0) * t
        dx, dy = x1 - x0, y1 - y0
        length = math.hypot(dx, dy) or 1
        nx, ny = -dy / length * side, dx / length * side
        lx, ly = px + nx * dist, py + ny * dist

        label = f"{flow['id']}: {labels.get(flow['id'], '')}"
        if not reachable:
            label += "\n[SKIPPED — no Process mediates]"
        ax.text(lx, ly, label, ha="center", va="center", fontsize=7.6,
                color="black" if reachable else "#c62828",
                bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="#cccccc", alpha=0.92), zorder=4)

    for eid, (x, y) in positions.items():
        e = elements[eid]
        if e["type"] == "ExternalEntity":
            _draw_external_entity(ax, x, y, e["name"], e.get("role"))
        elif e["type"] == "Process":
            _draw_process(ax, x, y, e["name"])
        else:
            _draw_datastore(ax, x, y, e["name"])

    xs = [p[0] for p in positions.values()]
    ys = [p[1] for p in positions.values()]
    ax.set_xlim(min(xs) - 2.2, max(xs) + 2.2)
    ax.set_ylim(min(ys) - 2.0, max(ys) + 2.0)
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title(dfd["_meta"]["scenario"], fontsize=14, fontweight="bold")

    legend_handles = [
        Rectangle((0, 0), 1, 1, facecolor=EE_DEFAULT_COLOR, edgecolor="black", label="External Entity"),
        Rectangle((0, 0), 1, 1, facecolor=ROLE_COLOR["internal_staff"], edgecolor="black",
                  label="External Entity (role=internal_staff)"),
        Ellipse((0, 0), 1, 1, facecolor=PROCESS_COLOR, edgecolor="black", label="Process"),
        Rectangle((0, 0), 1, 0.4, facecolor=STORE_COLOR, edgecolor="black", label="Data Store"),
    ]
    ax.legend(handles=legend_handles, loc="lower center", bbox_to_anchor=(0.5, -0.06),
              ncol=4, fontsize=8.5, frameon=False)

    out_path = out_path or (config.KB_DIR / "scenarios" / scenario / "dfd.png")
    fig.savefig(out_path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return out_path


if __name__ == "__main__":
    for scenario in ("smart_home", "telehealth_demo"):
        path = render(scenario)
        print(f"Wrote {path}")
