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

# id -> (x, y). Spread out generously -- labels need room. Hand-placed only for scenarios small
# enough that this reads better than an auto-layout (see AUTO_LAYOUT_SCENARIOS below for the rest).
POSITIONS = {
    "smart_home": {
        "EE1": (0.0, 5.2), "EE2": (0.0, 0.2),
        "P1": (3.6, 3.2), "P2": (7.4, 3.2),
        "DS1": (3.6, -1.6), "DS2": (7.4, -1.6),
        "EE3": (12.0, 3.2),
    },
    "kidstube": {
        "EE1": (0.0, 8.0), "EE2": (0.0, -2.0),
        "P1": (5.5, 6.0), "P3": (5.5, 1.5), "P2": (5.5, -4.5),
        "DS1": (5.5, 10.5), "DS4": (10.5, 7.5), "DS5": (10.5, 3.8),
        "DS2": (10.5, -0.8), "DS3": (10.5, -6.5),
        "P4": (17.5, -0.8), "EE3": (23.0, -0.8),
    },
    "family_location": {
        "EE1": (0.0, 6.0), "EE2": (0.0, 0.0),
        "P1": (4.8, 3.0), "P2": (9.6, 6.0),
        "DS2": (4.8, 7.8), "DS1": (9.6, 0.0),
        "EE3": (14.4, 3.0), "EE4": (4.8, -3.8),
    },
}

# per-flow curvature override (arc3 rad); default 0.12. Higher values bow an edge further out,
# used for long edges that must visually clear an intermediate node sitting between them, or to
# fan out multiple parallel edges between the same pair of nodes so they don't overlap.
RAD_OVERRIDE = {
    "kidstube": {
        "DF1": 0.12, "DF3": -0.12,       # EE1<->P1 (register / JWT back)
        "DF4": 0.12, "DF5": -0.12,       # EE2<->P1 (login / JWT back)
        "DF6": 0.18, "DF17": -0.18,      # EE1<->P3 (profile create / history back)
        "DF7": 0.16, "DF10": -0.16,      # P3->DS2 (profile store / watch history), same direction
        "DF8": 0.12, "DF12": -0.12,      # EE2<->P2 (request / stream back)
        "DF11": 0.08,                    # EE1->P2 (upload), long edge past P3
    },
    "family_location": {
        "DF6": -0.30, "DF8": 0.0, "DF10": 0.30,   # three EE1->P1 edges (register / view / invite)
        "DF1": 0.18, "DF13": -0.18,               # two EE2->P1 edges (GPS / SOS)
        "DF9": 0.12,                              # DS1->P1 retrieval, bows opposite DF2
    },
}

# short human labels for edges (full descriptions live in dfd.json/system_description.md)
EDGE_LABELS = {
    "smart_home": {
        "DF1": "register / enroll devices", "DF2": "guest access code",
        "DF3": "write sensor events", "DF4": "upload video clips",
        "DF5": "motion alert", "DF6": "push notification",
        "DF7": "usage analytics", "DF8": "retrieve clip",
    },
    "kidstube": {
        "DF1": "register", "DF2": "store account", "DF3": "JWT + data",
        "DF4": "child login", "DF5": "JWT + profiles", "DF6": "create child profile",
        "DF7": "store profile", "DF8": "search / watch / like", "DF9": "video metadata + files",
        "DF10": "watch history", "DF11": "upload video", "DF12": "stream video",
        "DF13": "browsing data", "DF14": "browsing data (planned)", "DF15": "govt ID image",
        "DF16": "JWT in localStorage", "DF17": "history to parent",
    },
    "family_location": {
        "DF1": "GPS ping", "DF2": "write ping", "DF3": "forward ping",
        "DF4": "read zones", "DF5": "arrival/departure alert", "DF6": "register / set zones",
        "DF7": "store account/zones", "DF8": "request location view", "DF9": "retrieve history",
        "DF10": "invite guardian", "DF11": "grant access + location", "DF12": "usage analytics",
        "DF13": "SOS / check-in",
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
    "kidstube": {
        "DF1": (1, 0.3), "DF3": (-1, 0.3),
        "DF4": (1, 0.45), "DF5": (-1, 0.7),
        "DF2": (1, 0.5), "DF15": (1, 0.5), "DF16": (-1, 0.5),
        "DF6": (1, 0.22), "DF17": (-1, 0.72),
        "DF7": (1, 0.4), "DF10": (-1, 0.65),
        "DF8": (1, 0.35), "DF12": (-1, 0.35),
        "DF9": (1, 0.5), "DF11": (1, 0.88),
        "DF13": (1, 0.5), "DF14": (1, 0.5),
    },
    "family_location": {
        "DF6": (-1, 0.15), "DF8": (1, 0.5), "DF10": (-1, 0.85),
        "DF1": (1, 0.3), "DF13": (-1, 0.7),
        "DF2": (1, 0.5), "DF9": (-1, 0.5),
        "DF3": (1, 0.5), "DF4": (-1, 0.5), "DF5": (1, 0.5),
        "DF7": (1, 0.5), "DF11": (1, 0.5), "DF12": (-1, 0.5),
        "DF10": (-1, 1.15),
    },
}

ROLE_COLOR = {"internal_staff": "#cfe3ff", "external_party": "#f2f2f2"}
EE_DEFAULT_COLOR = "#f2f2f2"
PROCESS_COLOR = "#d9f2d9"
STORE_COLOR = "#fff6cf"


def _entity_size(name: str) -> tuple[float, float]:
    return max(2.2, 0.165 * len(name) + 0.5), 0.9


def _process_size(name: str) -> tuple[float, float]:
    # Ellipses need more width margin than the other two shapes for the same string length,
    # since text runs edge-to-edge inside a rectangle but must clear the ellipse's curve.
    return max(2.4, 0.2 * len(name) + 0.8), 1.15


def _store_size(name: str) -> float:
    return max(2.4, 0.165 * len(name) + 0.5)


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


def _approx_width(e: dict) -> float:
    """Same formulas as _entity_size/_process_size/_store_size, duplicated here (not imported
    from those, which need an axes-independent estimate before any drawing happens) so
    _auto_layout can space columns by each element's actual rendered width instead of a fixed
    constant -- genomic has element names from 6 to 37 characters, so a fixed column spacing
    either wastes space on short names or overlaps on long ones."""
    name = e["name"]
    if e["type"] == "Process":
        return max(2.4, 0.2 * len(name) + 0.8)
    return max(2.2, 0.165 * len(name) + 0.5)


def _auto_layout(dfd: dict) -> dict:
    """Grouped-grid layout for scenarios too large to hand-place (currently only genomic, 32
    elements/39 flows). Groups elements by the leading letters of their id (S/C/R for genomic's
    shared/clinical/research pipelines -- the same grouping the scenario's own system_description
    and NIST's source diagrams use) into horizontal bands. Within each band, rows are packed
    left-to-right using each element's *actual* width (not a fixed column spacing) so long names
    (up to 37 characters here) don't overlap their neighbors. Deliberately not hand-tuned like the
    smaller scenarios -- this reads structure, not polish."""
    import re
    groups: dict[str, list[dict]] = {}
    for e in dfd["elements"]:
        m = re.match(r"[A-Za-z]+", e["id"])
        groups.setdefault(m.group(0) if m else "?", []).append(e)

    positions: dict[str, tuple[float, float]] = {}
    band_y = 0.0
    row_spacing, band_gap, margin = 2.8, 3.6, 0.7
    for key in sorted(groups):
        items = groups[key]
        ncols = max(1, math.ceil(math.sqrt(len(items) * 1.8)))
        nrows = math.ceil(len(items) / ncols)
        for row_idx in range(nrows):
            row_items = items[row_idx * ncols:(row_idx + 1) * ncols]
            x = 0.0
            for e in row_items:
                w = _approx_width(e)
                x += w / 2
                positions[e["id"]] = (x, band_y - row_idx * row_spacing)
                x += w / 2 + margin
        band_y -= nrows * row_spacing + band_gap
    return positions


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
    auto = scenario not in POSITIONS
    positions = POSITIONS[scenario] if not auto else _auto_layout(dfd)
    # Auto-layout scenarios (currently just genomic, 39 flows) skip per-edge text labels --
    # unreadable at that count -- and keep only the solid-vs-dashed-red reachability signal.
    labels = {} if auto else EDGE_LABELS.get(scenario, {})
    placement = {} if auto else LABEL_PLACEMENT.get(scenario, {})
    rad_override = {} if auto else RAD_OVERRIDE.get(scenario, {})

    xs = [p[0] for p in positions.values()]
    ys = [p[1] for p in positions.values()]
    # Scale figure size to the coordinate range (not a fixed constant) -- text has a fixed point
    # size regardless of data-coordinate scale, so a wide layout in a fixed-size figure makes
    # labels visually crowd/overlap the shapes even when their data coordinates don't intersect.
    figsize = (max(13, (max(xs) - min(xs)) * 0.85), max(8.5, (max(ys) - min(ys)) * 0.75))
    fig, ax = plt.subplots(figsize=figsize)

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

        if auto:
            # Too many edges (39) for full descriptive labels to stay readable -- just the flow
            # id, and only for unreachable ones, so the reachability signal (the point of this
            # rendering feature) still stands out against the plain flow-id-only reachable edges.
            if not reachable:
                ax.text(lx, ly, flow["id"], ha="center", va="center", fontsize=6.5,
                        color="#c62828",
                        bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="#c62828", alpha=0.9), zorder=4)
        else:
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
    if auto:
        ax.text(min(xs) - 1.8, max(ys) + 1.4,
                 "Red dashed = structurally unreachable (mapping_table.json has no row for this\n"
                 "interaction type -- grounded generation skips it; flow id shown only for these)",
                 ha="left", va="top", fontsize=8, color="#c62828", style="italic")

    out_path = out_path or (config.KB_DIR / "scenarios" / scenario / "dfd.png")
    fig.savefig(out_path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return out_path


if __name__ == "__main__":
    import sys
    # smart_home already has a dfd.png (Week 4); the rest were missing one until Week 8.
    scenarios = sys.argv[1:] or ("smart_home", "kidstube", "family_location", "genomic")
    for scenario in scenarios:
        path = render(scenario)
        print(f"Wrote {path}")
