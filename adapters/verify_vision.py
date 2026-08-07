"""Pass 3 for the image adapter: re-derive every cited box against the pixels. Zero LLM calls.

The sibling of verify_dfd.py, and the same argument: a derived DFD's citations are re-checked
against the artifact they claim to come from, never trusted from the model's own output. Asking a
model to crop the box and confirm its own reading would relocate the self-report problem, not
solve it, so this module only ever does arithmetic and pixel arithmetic.

Two checks, mirroring verify_dfd's resolvable/present split:

  citations_resolvable   the box is a real location -- inside the image at all. The analogue of
                         "this file exists and has that many lines".
  region_has_content     something is actually DRAWN inside the box. The analogue of "a construct
                         was parsed at that line". Weak on purpose: it proves the box landed on
                         ink, not that the ink is the RIGHT element. A true type check needs shape
                         detection, which is the closed-vocabulary work this arm deliberately
                         omits.

WHY THE SCALE FACTOR EXISTS. On the first live run every box was in-bounds (1.00) but only 0.54
landed on ink -- and the misses were not scattered, they were a single global scaling. The model
reported coordinates in its own resized canvas (~946x784 for a 2081x1724 image) despite being
told the pixel dimensions; rescaling by one factor, 2.2, lifted content coverage to 0.98. So the
citations were real but expressed in an undeclared coordinate system, the pixel analogue of
llm_naive's "real source line, rarely the exact construct line".

Both numbers are reported, never just the flattering one. The uncalibrated rate is what an
open-vocabulary citation is worth as emitted; the calibrated rate is what it is worth once you
have done the work of discovering the frame -- work that needs a deterministic detector, which is
precisely the thing a closed vocabulary would have made unnecessary.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

from adapters.verify_dfd import NOT_CHECKED, _combine_all_valid

# Fraction of a box's pixels that must be non-background before it counts as landing on something
# drawn. Small: an arrow passing through a box is a handful of pixels, and demanding more would
# mark thin-stroke citations as fabricated.
INK_FRACTION = 0.005
# How far from the canvas colour a pixel must sit to count as drawn. This was `INK_THRESHOLD = 200`
# -- "8-bit grey below this is ink" -- which silently encoded ONE assumption: dark marks on a light
# page. That holds for a matplotlib render and inverts completely for a dark-theme export, where
# ~90% of the pixels sit below 200 and the canvas itself reads as ink, so EVERY box lands on
# "content" and region_has_content becomes a check that cannot fail. A check that cannot fail is
# worse than no check. The background is now measured per image and ink is deviation from it; 55 is
# the old threshold's distance from white, so light-background images score exactly as before.
INK_DELTA = 55
SCALE_CANDIDATES = [round(1.0 + i * 0.05, 2) for i in range(0, 61)]   # 1.00 .. 4.00


@dataclass
class BoxVerification:
    item_id: str
    kind: str                       # "element" | "flow"
    citations_resolvable: object    # True | False | NOT_CHECKED
    region_has_content: object
    n_citations: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> object:
        return _combine_all_valid((self.citations_resolvable, self.region_has_content))


def _load_grey(image_path: str | Path):
    import numpy as np
    from PIL import Image
    with Image.open(image_path) as im:
        return np.array(im.convert("L"))


def _boxes(item: dict) -> list[list[int]]:
    return [p["bbox"] for p in item.get("provenance", []) if isinstance(p.get("bbox"), list)]


def _in_bounds(box: list[int], w: int, h: int) -> bool:
    x, y, bw, bh = box
    return x >= 0 and y >= 0 and bw > 0 and bh > 0 and x + bw <= w and y + bh <= h


def background_level(grey) -> int:
    """The canvas colour, read off the image rather than assumed to be white.

    Modal grey. A DFD export is overwhelmingly empty canvas whatever its theme, so the most common
    value IS the background -- which is what makes this measurable rather than a per-tool constant
    someone has to remember to set.
    """
    import numpy as np
    return int(np.bincount(grey.ravel(), minlength=256).argmax())


def _has_ink(grey, box: list[int], scale: float = 1.0, background: int | None = None) -> bool:
    import numpy as np
    h, w = grey.shape
    x, y, bw, bh = (int(v * scale) for v in box)
    crop = grey[max(0, y):min(h, y + bh), max(0, x):min(w, x + bw)]
    if crop.size == 0:
        return False
    bg = background_level(grey) if background is None else background
    drawn = np.abs(crop.astype(np.int16) - bg) > INK_DELTA
    return float(drawn.mean()) > INK_FRACTION


def ink_coverage(dfd: dict, grey, scale: float = 1.0, background: int | None = None) -> float:
    """Fraction of all cited boxes that land on drawn content at the given scale."""
    boxes = [b for item in dfd["elements"] + dfd["flows"] for b in _boxes(item)]
    if not boxes:
        return 0.0
    bg = background_level(grey) if background is None else background
    return sum(_has_ink(grey, b, scale, bg) for b in boxes) / len(boxes)


def calibrate_scale(dfd: dict, grey) -> tuple[float, float]:
    """Find the single global factor that best maps cited coordinates onto the real image.

    Returns (scale, coverage_at_that_scale). Ties break toward 1.0, so a DFD whose citations are
    already in the stated frame is never reported as needing a correction it does not need.
    """
    bg = background_level(grey)          # once, not once per candidate scale
    best = (1.0, ink_coverage(dfd, grey, 1.0, bg))
    for s in SCALE_CANDIDATES:
        cov = ink_coverage(dfd, grey, s, bg)
        if cov > best[1]:
            best = (s, cov)
    return best


def verify_element_or_flow(item: dict, kind: str, grey, w: int, h: int,
                           scale: float = 1.0, background: int | None = None) -> BoxVerification:
    reasons: list[str] = []
    boxes = _boxes(item)
    iid = item.get("id", "<no id>")

    if not boxes:
        reasons.append("cites no image region at all")
        return BoxVerification(iid, kind, False, False, 0, reasons)

    bad = [b for b in boxes if not _in_bounds(b, w, h)]
    for b in bad:
        reasons.append(f"cited box {b} is not inside the {w}x{h} image")

    bg = background_level(grey) if background is None else background
    empty = [b for b in boxes if not _has_ink(grey, b, scale, bg)]
    for b in empty:
        reasons.append(f"cited box {b} holds no drawn content"
                       + (f" (at scale {scale})" if scale != 1.0 else ""))

    return BoxVerification(iid, kind, not bad, not empty, len(boxes), reasons)


def verify_vision_dfd(dfd: dict, image_path: str | Path,
                      scale: float | None = None) -> tuple[list[BoxVerification], float, float]:
    """Verify every cited box. Returns (verifications, scale_used, calibrated_coverage).

    `scale=None` calibrates; pass 1.0 to score the citations exactly as the model stated them.
    """
    grey = _load_grey(image_path)
    h, w = grey.shape
    bg = background_level(grey)
    calibrated, coverage = calibrate_scale(dfd, grey)
    used = calibrated if scale is None else scale
    out = [verify_element_or_flow(e, "element", grey, w, h, used, bg) for e in dfd["elements"]]
    out += [verify_element_or_flow(f, "flow", grey, w, h, used, bg) for f in dfd["flows"]]
    return out, used, coverage


def _rate(items: list, attr: str) -> float:
    """Rate over items where the check actually ran -- verify_dfd._rate's rule, same reason: a
    check that did not run must not be able to move a number in either direction."""
    if not items:
        return 0.0
    checked = [v for v in (getattr(i, attr) for i in items) if v is not NOT_CHECKED]
    if not checked:
        return float("nan")
    return sum(1 for v in checked if v) / len(checked)


def format_verification_report(vs: list[BoxVerification], image_path: str | Path,
                               scale_used: float, dfd: dict, grey=None) -> str:
    from PIL import Image
    with Image.open(image_path) as im:
        w, h = im.size
    grey = _load_grey(image_path) if grey is None else grey

    bg = background_level(grey)
    raw = ink_coverage(dfd, grey, 1.0, bg)
    # Always report what a global rescale COULD buy, even when scoring at 1.0. The gap between
    # the two is the finding; showing only the scored one would hide it in whichever mode the
    # reader happened to run.
    best_scale, cal = calibrate_scale(dfd, grey)
    n_boxes = sum(v.n_citations for v in vs)
    els = [v for v in vs if v.kind == "element"]
    fls = [v for v in vs if v.kind == "flow"]

    def pct(x):
        return "n/a" if x != x else f"{x:.2f}"      # nan == "the check never ran"

    lines = [
        f"Vision DFD verification -- {Path(image_path).name} ({w}x{h})",
        f"  {len(els)} elements, {len(fls)} flows, {n_boxes} cited boxes",
        # Stated, because it decides what counts as ink and it is measured, not assumed. On a
        # dark-theme export a threshold tuned for white paper marks the whole canvas as drawn.
        f"  canvas background grey {bg} ({'light' if bg >= 128 else 'dark'} theme), "
        f"ink = |pixel - {bg}| > {INK_DELTA}",
        "",
        f"  citations_resolvable (box inside the image)   {pct(_rate(vs, 'citations_resolvable'))}",
        f"  region_has_content   (box lands on ink)       {pct(_rate(vs, 'region_has_content'))}",
        f"  all_valid                                     {pct(_rate(vs, 'all_valid'))}",
        "",
        f"  (checks above scored at scale {scale_used})",
        "",
        f"  per-box ink coverage at stated coordinates    {raw:.2f}",
        f"  per-box ink coverage at best global rescale   {cal:.2f}  (scale {best_scale})",
    ]
    if best_scale != 1.0 and cal - raw > 0.05:
        lines.append(f"  -> the citations are real but expressed in a ~{w/best_scale:.0f}x"
                     f"{h/best_scale:.0f} canvas, not the {w}x{h} the model was given.")
    failed = [v for v in vs if v.all_valid is False]
    if failed:
        lines.append("")
        lines.append(f"  {len(failed)} item(s) with citation problems:")
        for v in failed[:20]:
            lines.append(f"    {v.item_id}: {v.reasons[0]}")
    return "\n".join(lines)
