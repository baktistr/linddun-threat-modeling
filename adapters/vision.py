"""DFD image -> DFD. The third input adapter, alongside source code and a hand-authored dfd.json.

    image ──> dfd.json ──> pipeline
    source ──> facts ──> dfd.json ──> pipeline

One arm so far, `vision_naive`, and the name is the claim: it is the pixel analogue of
synthesize.py's `llm_naive`. The model reads the diagram and self-reports the bounding box it
read each element and flow from. There is no detector, so there is no closed vocabulary to pick
from, and no confabulation guard -- an element citing a blank patch of canvas is KEPT, and
verify_vision.py is left to catch it.

There is deliberately no `vision` (closed-vocabulary) arm yet. A closed vocabulary is a candidate
list produced deterministically BEFORE the model runs; for pixels that means contour/shape
detection (OpenCV), which this repo does not yet depend on. "Closed vocabulary without a
detector" is not a thing -- so image-in-with-nothing-pre-detected IS the naive arm, and shipping
it alone is honest rather than partial.

What the modality costs, measured rather than assumed (see WEEK12_REPORT.md): on a rendered
KidsTube diagram the structure comes back essentially intact -- every element, every type, every
flow id -- but the flow DESCRIPTIONS come back ~60% shorter, because a diagram's edge label
("DF1: register") never carried dfd.json's field enumeration ("parent registration (email,
password, name, govt ID, six-digit code)"). That gap is in the picture, not in the model, and it
is the thing to watch: generation/prompt.py feeds the flow description straight to the threat
elicitor, so a thinner description is less for it to reason about.
"""
from __future__ import annotations
from pathlib import Path

from adapters.schema import DFD_ELEMENTS_VISION_TOOL_SCHEMA, DFD_FLOWS_VISION_TOOL_SCHEMA
from retrieval.interaction_context import ELEMENT_TYPES

MODE_VISION_NAIVE = "vision_naive"

# A whole-DFD payload plus per-item bbox citations. Same budget as the source-side naive arm --
# open vocabularies are verbose, and a truncated tool call reads as a model failure rather than a
# budget one (see generation/llm_backend.AzureFoundryBackend).
VISION_MAX_TOKENS = 16000

_PREAMBLE = """\
You are deriving a Data Flow Diagram (DFD) for LINDDUN Pro privacy threat modeling by reading a
DIAGRAM IMAGE directly. The image is {w} x {h} pixels; the origin (0,0) is the TOP-LEFT. You cite
evidence as a pixel bounding box you read it from -- there is no pre-extracted list of shapes and
no id vocabulary; you locate the evidence yourself.

Standard DFD notation is used:
  rectangle          ExternalEntity  an actor outside the system
  ellipse            Process         a component that transforms, routes, or acts on data
  open-topped bar    DataStore       somewhere data comes to rest

Report every coordinate in the {w} x {h} pixel space stated above, NOT in any resized or
normalised space.
"""

_ELEMENTS_INSTRUCTIONS = """\
Emit every element drawn in the diagram.

Rules:
- citations are {x, y, w, h} boxes in pixel coordinates, plus the text you read there.
- Cite the ONE to THREE most decisive regions per element, the way an analyst footnotes -- not
  every place the thing is touched.
- The SHAPE determines the type: rectangle -> ExternalEntity, ellipse -> Process, open bar ->
  DataStore. Do not override the shape with your own judgement about what the thing "should" be.
- NAME each element exactly as the diagram labels it.
- Read only what is drawn. Do not add elements a system like this usually has but this diagram
  does not show.
- If a label is unclear or you are inferring beyond what is drawn, say so in uncertainty_note.

Respond using the emit_dfd_elements tool.\
"""

_FLOWS_INSTRUCTIONS = """\
These elements were accepted from your previous step:

{elements}

Emit every data flow (arrow) drawn between them.

Rules:
- source and destination MUST be ids from the ELEMENTS list above.
- Flows are DIRECTED -- follow the arrowhead, not the reading order.
- If an arrow carries a printed id (e.g. "DF1: register"), reuse that id exactly.
- description: what DATA moves. Use the arrow's printed label, and say only what the diagram
  shows -- do not embellish from what you know about systems like this.
- citations are {{x, y, w, h}} boxes plus the text you read there.
- Where arrows cross or labels crowd, say so in uncertainty_note rather than guessing silently.

Respond using the emit_dfd_flows tool.\
"""


def image_size(image_path: str | Path) -> tuple[int, int]:
    from PIL import Image
    with Image.open(image_path) as im:
        return im.size


def _elements_prompt(w: int, h: int) -> str:
    return _PREAMBLE.format(w=w, h=h) + "\n" + _ELEMENTS_INSTRUCTIONS


def _flows_prompt(w: int, h: int, elements: list[dict]) -> str:
    rendered = "\n".join(f"  {e['id']:5} {e['type']:14} {e['name']}" for e in elements)
    return (_PREAMBLE.format(w=w, h=h) + "\n"
            + _FLOWS_INSTRUCTIONS.format(elements=rendered))


def _clean_citations(raw: object) -> list[dict]:
    """Keep well-formed boxes as canonical {bbox: [x,y,w,h]} provenance. Malformed ones are
    dropped so the DFD stays schema-valid, but the ITEM is never dropped for citing badly -- that
    absent guard is what this arm measures."""
    out = []
    for c in raw or []:
        if not isinstance(c, dict):
            continue
        if not all(isinstance(c.get(k), int) for k in ("x", "y", "w", "h")):
            continue
        entry = {"bbox": [c["x"], c["y"], c["w"], c["h"]]}
        if isinstance(c.get("label_text"), str) and c["label_text"]:
            entry["label_text"] = c["label_text"]
        out.append(entry)
    return out


def _accept_elements(raw: list[dict]) -> tuple[list[dict], list[str]]:
    """Structural well-formedness only -- id/type/name present, ids unique. No citation check.

    The mirror of synthesize.py::_accept_elements_naive, and absent for the same reason: nothing
    here drops an element for citing a nonexistent region, so whether the model invents one is a
    measurement rather than something the adapter quietly prevents.
    """
    kept, rejected = [], []
    seen: set[str] = set()
    for e in raw:
        eid = e.get("id")
        if not eid or e.get("type") not in ELEMENT_TYPES or not e.get("name"):
            rejected.append(f"{eid or '<no id>'}: malformed (id/type/name)")
            continue
        if eid in seen:
            rejected.append(f"{eid}: duplicate id")
            continue
        seen.add(eid)
        el = {"id": eid, "type": e["type"], "name": e["name"],
              "provenance": _clean_citations(e.get("citations"))}
        for opt in ("rationale", "confidence", "uncertainty_note"):
            if e.get(opt):
                el[opt] = e[opt]
        kept.append(el)
    return kept, rejected


def _accept_flows(raw: list[dict], element_ids: set[str]) -> tuple[list[dict], list[str]]:
    """Graph well-formedness only. Endpoints must be emitted elements (a flow to a nonexistent
    element is malformed in any vocabulary); citations are NOT checked for landing on anything."""
    kept, rejected = [], []
    seen: set[str] = set()
    for f in raw:
        fid = f.get("id")
        if not fid or fid in seen:
            rejected.append(f"{fid or '<no id>'}: missing or duplicate id")
            continue
        if f.get("source") not in element_ids or f.get("destination") not in element_ids:
            rejected.append(f"{fid}: endpoint not an emitted element "
                            f"({f.get('source')} -> {f.get('destination')})")
            continue
        seen.add(fid)
        fl = {"id": fid, "source": f["source"], "destination": f["destination"],
              "description": f.get("description") or f"{f['source']} -> {f['destination']}",
              "provenance": _clean_citations(f.get("citations"))}
        for opt in ("confidence", "uncertainty_note"):
            if f.get(opt):
                fl[opt] = f[opt]
        kept.append(fl)
    return kept, rejected


def synthesize_vision_naive(image_path: str | Path, provider: str | None = None,
                            verbose: bool = True, scenario_name: str = "") -> dict:
    """Two calls -- elements, then flows -- over a DIAGRAM IMAGE, citing open pixel boxes.

    The two-call seam, the element-type list, and the naming/granularity guidance are held
    identical to the source-side arms on purpose, so a difference in the numbers is attributable
    to the modality and not to prompt drift.
    """
    from generation.llm_backend import ImageInput, get_llm_backend

    path = Path(image_path)
    backend = get_llm_backend(provider)
    image = ImageInput.from_path(path)
    w, h = image_size(path)

    raw_elements = backend.call_tool(_elements_prompt(w, h), DFD_ELEMENTS_VISION_TOOL_SCHEMA,
                                     max_tokens=VISION_MAX_TOKENS, image=image).get("elements", [])
    elements, el_rejected = _accept_elements(raw_elements)
    if not elements:
        raise RuntimeError("the model emitted no well-formed elements; refusing to write an empty "
                           "DFD." + (f" Rejections: {el_rejected}" if el_rejected else ""))

    raw_flows = backend.call_tool(_flows_prompt(w, h, elements), DFD_FLOWS_VISION_TOOL_SCHEMA,
                                  max_tokens=VISION_MAX_TOKENS, image=image).get("flows", [])
    flows, fl_rejected = _accept_flows(raw_flows, {e["id"] for e in elements})

    if verbose:
        print(f"  elements: {len(elements)} accepted, {len(el_rejected)} rejected "
              f"(well-formedness only -- no citation guard)")
        for r in el_rejected:
            print(f"    rejected: {r}")
        print(f"  flows:    {len(flows)} accepted, {len(fl_rejected)} rejected")
        for r in fl_rejected:
            print(f"    rejected: {r}")

    return {
        "_meta": {"scenario": f"{scenario_name or 'unnamed system'} (derived from image, "
                              f"{MODE_VISION_NAIVE})",
                  "adapter_mode": MODE_VISION_NAIVE,
                  "backend": backend.name,
                  "image_size": [w, h],
                  "rejected_elements": el_rejected,
                  "rejected_flows": fl_rejected},
        "elements": elements,
        "flows": flows,
    }
