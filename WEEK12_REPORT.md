# Week 12 — DFD image as a third pipeline input

Weeks 10–11 gave the pipeline a second input: source code, via `adapters/`. This week adds a
third — a **DFD diagram image** — on the same principle and through the same seam:

```
hand-authored dfd.json ─────────────────────> pipeline
source code ──> code facts ──> dfd.json ─────> pipeline
DFD image ─────────────────> dfd.json ───────> pipeline      (new)
```

Everything downstream is unchanged. `adapters/emit.py` still refuses to write anywhere but a
`*_derived` scenario, and `cli.py generate --scenario kidstube_image_derived` needs no
special-casing, because every command was already `--scenario`-parameterised.

## What was built

**`adapters/vision.py` — the `vision_naive` arm.** The pixel analogue of `synthesize_llm_naive`:
the model reads the diagram and self-reports the bounding box it read each element and flow from.
Two calls, elements then flows, with the element-type list and the naming/granularity guidance
held identical to the source-side arms so the modality is the only variable.

**There is deliberately no closed-vocabulary `vision` arm yet, and that is a finding, not a
shortfall.** A closed vocabulary is a candidate list produced deterministically *before* the model
runs — for source that is `extract.py`; for pixels it would be contour/shape detection. "Closed
vocabulary without a detector" is not a coherent thing, so image-in-with-nothing-pre-detected
*is* the naive arm. Shipping it alone is honest; adding a `vision` arm means adding OpenCV.

**`adapters/verify_vision.py` — Pass 3 for pixels.** Zero LLM calls, same rule as `verify_dfd.py`:
a verifier that asks a model whether the model was right is not a verifier. Two checks —
`citations_resolvable` (the box is inside the image) and `region_has_content` (something is
actually drawn in it). The second is weak on purpose: it proves the box landed on ink, not that
the ink is the right element. A real type check needs shape detection.

**`bbox` as a third citation vocabulary** in `adapters/schema.py`. `_validate_provenance` now
enforces exactly one of `fact_id` / `file`+`line` / `bbox` per entry — never two, never none.

**Image support in `generation/llm_backend.py`,** as an `ImageInput` parameter on `call_tool`
across all three backends (Anthropic's `source` block, OpenAI/Azure's `image_url` data URL). With
`image=None` the message content stays a bare string, so the text-only path over the wire is
byte-identical to what it was before — every existing generation run depends on that, and a test
pins it.

**CLI:** `cli.py derive-image --image PATH` and `cli.py verify-image [--calibrate]`.

## The run — `vision_naive` on the KidsTube DFD image

Azure `gpt-5.4`, two live calls, on `knowledge_base/scenarios/kidstube/dfd.png` (2081×1724).
Output committed as `knowledge_base/scenarios/kidstube_image_derived/`.

The image is a render *of* `kidstube/dfd.json`, so that JSON is exact ground truth and a perfect
adapter is the identity — the same discipline as the M0 gate, and it needs no new gold standard.

**Structure comes back essentially intact:**

| | gold | derived |
|---|---:|---:|
| elements | 12 | 12 |
| element names matched | — | 12/12 |
| element types correct | — | 12/12 |
| flow ids matched | 17 | 17/17 |
| flow endpoints correct | — | 14/17 |

Every element name read exactly, every shape→type call right, and the printed `DF1…DF17` ids
reused rather than renumbered. The three endpoint errors (DF3, DF4, DF5) are all in one crowded
region where the Parent User and Child User arrows cross and four labels stack; in each case the
model substituted `Child Profile Management` for a user endpoint. **The failures are where the
rendering is ambiguous, not random.**

**Descriptions come back ~60% thinner** — mean 38 chars gold vs 15 derived:

```
DF1  gold     parent registration (email, password, name, govt ID, six-digit code)
     derived  register
DF6  gold     child profile creation (name, DOB, gender, govt ID)
     derived  create child profile
```

The model reported the printed labels faithfully and did not embellish. **The loss is the
diagram's, not the model's** — `scripts/render_dfd.py` says outright that edge labels are short
human labels and the full descriptions live in `dfd.json`. This matters downstream because
`generation/prompt.py` feeds the flow description straight to the threat elicitor, so a thinner
description is less for it to reason about. It is the image-side analogue of M4's recall cost and
has not yet been measured end to end.

## The citation finding — M3's shape, one modality over

63 self-reported boxes:

| check | rate |
|---|---:|
| `citations_resolvable` (box inside the image) | **1.00** |
| `region_has_content` at stated coordinates | **0.41** (per box: 0.54) |
| `region_has_content` after a global ×2.2 rescale | **0.97** (per box: 0.98) |

The misses were not scattered — they were **one global scaling**. The model reported coordinates
in its own ~946×784 canvas despite being told the image is 2081×1724; a single factor, 2.20,
recovers essentially everything (flat 0.97–0.98 across 2.18–2.30, so a real optimum rather than a
fitting artifact). The citations are **real but expressed in an undeclared coordinate system** —
structurally the same result as M3's "real source line, rarely the exact construct line":

| | `llm_naive` (source) | `vision_naive` (image) |
|---|---:|---:|
| points at something real | 1.00 | 1.00 |
| lands on the exact stated address | 0.27 | 0.54 |
| lands after tolerance applied | ~0.66 (span) | 0.98 (rescale) |

**Where it differs, and why it still argues for a closed vocabulary.** The source arm's error is
unstructured — every citation off by its own amount. The vision arm's is a single global affine
factor, so it is fully recoverable in principle. But recovering it required knowing where the ink
actually is, i.e. scanning against the pixels. In production that calibration needs a
deterministic detector — precisely the thing a closed vocabulary would have made unnecessary. So
the argument survives in a sharper form: not *"vision citations can't be trusted"* but *"they must
be calibrated, and calibration needs the detector you were trying to skip."*

`verify-image` prints both rates in either mode, so whichever way it is run the gap is visible.
Uncalibrated is the default: that is what an open-vocabulary citation is worth as emitted.

One box fails even after calibration — DF3's, which is also one of the three flows whose endpoints
the model got wrong. The two error modes coincide on the same congested region.

## Threats on the image-derived DFD, grounded (the M4-equivalent)

`cli.py generate --scenario kidstube_image_derived` — 118 threats over 17 flows, then `cli.py
eval` against the gold standard.

**The gold transfers with no re-anchoring, and that is itself a result.** Matching is flow-anchored
(`[DF1]`..`[DF17]` embedded in `interaction`), and the image adapter reused the flow ids printed on
the diagram, so **41/41 gold threats anchor**. `kidstube_derived` needed
`scripts/build_kidstube_derived_gold.py` to translate ids through the alignment map and still lost
14 threats (2 planned-feature ceiling + 6 adapter-miss flows). Here the gold is copied verbatim,
the denominator is the same 41 the hand DFD is scored on, and no anchorable-subset restriction
applies. `structurally_unreachable = 0`, `unresolved_location = 0`.

| Type | hand TP/FP/FN | hand P/R | image TP/FP/FN | image P/R |
|---|---|---|---|---|
| L Linking | 5/10/1 | 0.33 / 0.83 | 3/11/3 | 0.21 / 0.50 |
| I Identifying | 4/12/1 | 0.25 / 0.80 | 4/11/1 | 0.27 / 0.80 |
| Nr Non-repudiation | 2/8/0 | 0.20 / 1.00 | 2/9/0 | 0.18 / 1.00 |
| D Detecting | 1/8/1 | 0.11 / 0.50 | 0/10/2 | 0.00 / 0.00 |
| Dd Data Disclosure | 11/16/4 | 0.41 / 0.73 | 11/16/4 | 0.41 / 0.73 |
| U Unawareness | 4/16/0 | 0.20 / 1.00 | 4/17/0 | 0.19 / 1.00 |
| Nc Non-compliance | 5/16/2 | 0.24 / 0.71 | 5/15/2 | 0.25 / 0.71 |
| **ALL** | **32/86/9** | **0.27 / 0.78** | **29/89/12** | **0.25 / 0.71** |

Both runs generated exactly 118 threats. Recall falls **0.78 → 0.71**; precision is flat within
noise (0.27 → 0.25, both automated lower bounds). Citation correctness is **1.00 on every axis**
— `node_valid`, `type_applicable`, `location_valid` — identical to the hand baseline, so the
image-derived DFD is a fully valid anchor target.

**Deriving the DFD from a picture costs far less recall than deriving it from code.** On M4's
27-threat subset, so all three sit on one denominator (the hand figure reproduces M4's published
0.70 exactly, which validates the subset reconstruction):

| DFD | recall (27 subset) | recall (all 41) |
|---|---:|---:|
| hand-authored | 0.70 | 0.78 |
| **image-derived** | **0.67** | **0.71** |
| source-derived (`facts_only`) | 0.52 | n/a — 14 threats unanchorable |

The image adapter gives up **0.03**; the source adapter gives up **0.18**. Two reasons, and they
compound: the diagram already encodes the analyst's element granularity and naming, so no
abstraction has to be re-invented from routes and collections; and the analyst *drew the planned
features*, so DF13/DF14 (AI Recommendation Engine, Third-Party Advertisers) are present — the
derivability ceiling that is structural for code does not exist for a picture.

The one category that collapses is **Detecting (1 TP → 0)**, on a 2-threat base, so n is too small
to read as a finding.

## Tests

**439 offline, all passing** (test_kb 77, test_generation 227, test_adapter 135, up from 107). The
new adapter tests cover the absent confabulation guard, `bbox` as a third vocabulary, the
verifier's freedom from any model or network, scale calibration surfacing rather than hiding the
frame mismatch, the text-only backend path staying a bare string, and an offline prompt-build
guard (the Week 11 lesson: a literal `{x, y, w, h}` is a `str.format` `KeyError` that only fires
after the first call has been billed).

Two pre-existing assertions were updated to the new `_validate_provenance` wording. The behaviour
is unchanged — both cases are still rejected; there are now three vocabularies to name.

## Open items / caveats

1. **n=1, one image, best case.** A clean matplotlib render — uniform strokes, no overlapping
   shapes, machine-consistent notation. Scoring well on it is a *ceiling* measurement and is not
   evidence about a Visio export or a photographed whiteboard. It must not be written up as field
   validation.
2. **The ×2.2 factor is not a constant.** Vision encoders resize to a token budget, so it will
   vary with input dimensions. Per-image calibration, never a hardcoded number.
3. **The original KidsTube HW2 diagram is the fixture worth having.** `kidstube/dfd.json` traces
   back to it (image → `system_description.md` → `dfd.json`, Week 3), and the repo's `dfd.png` is
   a Week 8 *re-render*, not that original. The HW2 diagram is a real artifact from a real tool
   whose ground-truth transcription already exists — a genuine field test at no extra labelling
   cost, if the file can be recovered.
4. **The thinner descriptions cost recall, but less than expected** — 0.78 → 0.71 on all 41. Only
   `grounded` has been run; `rag` and `ungrounded` on the image-derived DFD are unrun, so the
   grounding-order check (grounded > ungrounded > rag, which held on both the hand and
   source-derived DFDs) is untested here.
5. **`OpenAIBackend.call_tool` accepts `max_tokens` and never sends it.** Pre-existing, untouched
   here because newer models reject `max_tokens` in favour of `max_completion_tokens` (the lesson
   already documented in `AzureFoundryBackend`). It matters for the planned multi-model runs: on
   that backend a long payload will truncate with no budget error.

## Still pending with advisor (carried from Weeks 1–11)

Target paper/workshop venue; IP/publication scope. Family Location and Smart Home gold standards
still need independent review before their numbers are cited as comparable to KidsTube.
`ABSTRACT.md` remains untracked and still claims six scenarios where four exist, and still
presents genomic as a held-out **LINDDUN** generalisation test though only PANOPTIC genomic
results exist. Manual FP adjudication has still never been run: the 86-entry worklist at
`storage/adjudication/kidstube_grounded.json` has been sitting unlabelled since 16 July, so no
`precision_corrected` exists anywhere.

## Next

Run both adapters across several models — image and source code, same KidsTube system — to see
whether the citation-frame behaviour and the structure/description split are properties of the
modality or of one model.
