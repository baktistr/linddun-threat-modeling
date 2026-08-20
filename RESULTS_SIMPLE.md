# Results — plain summary

A short version of the Results section of *Evaluating Privacy Threat Modelling with LLMs*.
Full detail, tables and caveats are in `PE Research Project.md`.

## The headline

**Deterministic grounding produced 1,546 threats across five systems and not one had a fake
citation.** Citation validity 1.00, standard deviation 0.00, in all 15 grounded runs.

The two comparison modes did not manage that: RAG 0.87–0.98, ungrounded 0.82–0.84.

## 1. The three modes

Averages over 5 scenarios, 3 runs each.

| Mode | Citation validity | Recall | F1 |
|---|---:|---:|---:|
| grounded | **1.00** | **0.92** | 0.34 |
| rag | 0.93 | 0.69 | 0.36 |
| ungrounded | 0.83 | 0.76 | 0.34 |

Comparing scenario by scenario (n=5, paired):

| Comparison | Difference | p | Won on |
|---|---:|---:|---|
| citation, grounded vs ungrounded | +0.170 | <0.00001 | 5 of 5 |
| citation, grounded vs rag | +0.068 | 0.020 | 5 of 5 |
| citation, rag vs ungrounded | +0.102 | 0.006 | 5 of 5 |
| recall, grounded vs ungrounded | +0.158 | 0.011 | 5 of 5 |
| recall, grounded vs rag | +0.230 | 0.00003 | 5 of 5 |
| F1, grounded vs ungrounded | +0.000 | 1.000 | 2 of 5 |

Three takeaways.

1. **Grounding wins on citations, and the mechanism is why.** RAG reads the same knowledge base
   and still loses. A lookup gives the model the complete list of legal nodes. A search never
   tells it what the complete list is.
2. **Grounding also wins on recall.** +0.16 over ungrounded, +0.23 over RAG. Best on all five
   scenarios.
3. **F1 tells you nothing here.** The difference is literally +0.000. Grounded finds more real
   threats but also proposes more candidates, and the two cancel exactly. Anyone reporting F1 as
   the headline would report "no difference" and miss both real effects.

## 2. Distribution of invalid citations, and a prompt-level confound

The bad citations are not spread around. They are all the same mistake, in the same two places,
and part of the cause turned out to be our own prompt.

**They are all one kind of failure.** Across the ten rag and ungrounded conditions — five
scenarios, two modes — the "does this node exist" check is the only one that ever fails. The other two — is this threat type allowed here,
does this DFD location exist — are 1.00 every time. So the model gets the type right and the
place right, and invents the node id.

**And nearly all of them are the same two node ids.** Of 113 bad citations, **91% are just two
invented nodes**: `D.1.1` (83 times) and `L.1.2` (20 times).

**Why those two.** Both look like they ought to exist. The Detecting tree has only three nodes and
no children at all, so nothing called `D.1.1` exists. `L.1` has exactly one child, so `L.1.2`
looks like the obvious next one, and it does not exist either. Every invented node in every run is
a believable child of a real node. The model is finishing a pattern, not making things up at
random — and the two places it goes wrong are the two places the real trees stop earlier than
their own pattern suggests.

This is also why grounding removes the problem entirely. The lookup hands the model each tree's
real shape, so there is no gap left to fill in.

**Then we found we were causing part of it.** We went back and rebuilt the exact rag prompts to
see what the model had actually been shown. The retrieved passages contained a Detecting node id
in **0 of 63 flows**, and any node id at all in only 17 of 63. So the one deep node id the model
reliably saw was **our own example**: our rag prompt said the answer should be a node id, "for
example `Dd.1.1`". That is a real, legal id in the Data Disclosure tree. The ungrounded prompt had
no example at all.

That is an accident of how we wrote the prompt, not something retrieval does. So we deleted that
one string and changed nothing else:

| Scenario | Before | After | Change |
|---|---:|---:|---:|
| KidsTube | 0.86 | 0.99 | +0.13 |
| Smart Home | 0.84 | 0.93 | +0.08 |
| Family Location | 0.86 | 0.94 | +0.08 |
| School Grades | 0.81 | 0.94 | +0.13 |
| Wearable Fitness | 0.80 | 0.89 | +0.08 |

Better on 5 of 5, mean +0.10. Citations to non-existent deep Detecting nodes fell from **94% to
29%**.

The lesson generalises: the model copied the *depth* of our example into trees that are not that
deep. **An example id in a prompt is an experimental variable, not decoration.**

## 3. Model choice matters far more than input format

KidsTube, same pipeline, only the model and the input changed. "DFD file" is the JSON a person
wrote; "diagram image" is a PNG the model had to read and convert into that JSON first.

| Model | From the DFD file | From a diagram image |
|---|---:|---:|
| gpt-5.4 | 0.78 | 0.76 |
| gpt-4o-mini | 0.68 | 0.66 |
| grok-4.3 | 0.56 | 0.59 |

- Changing the **model** moves recall by **0.22**.
- Changing the **input** moves it by **0.03 or less** — inside normal run-to-run noise.

So model choice matters roughly four to seven times more than whether you hand over a clean DFD
or a picture of one.

Also: how many threats a model produces is a fixed habit, not a response to the input. gpt-5.4
gave 137 and 135 threats from two different inputs; grok-4.3 gave 58 and 61. High volume buys
recall and costs precision. Low volume does the reverse.

## 4. Cost and citation behaviour of the input adapters

When a DFD file has to be built from something else, two separate things can go wrong: the DFD
can be wrong, and the citation saying where it came from can be wrong.

### Source code to DFD file

Three ways of building it, from most controlled to least.

| Arm | How the DFD is built | Citation is valid |
|---|---|---:|
| `facts_only` | built from the extracted code facts, no LLM | **1.00** |
| `llm` | model composes it, but may only cite fact ids from a fixed list | **1.00** |
| `llm_naive` | model composes it and writes its own `file:line` | **0.25** |

**This is where citation validity collapses: 1.00 down to 0.25.** And the reason is precise. The
open `file:line` citations always name a real file and a real line — the model never invented a
path or ran off the end of a file. They just are not the *right* line: only 27% land on the exact
line the extractor pins the construct to.

So they are real but not checkable. Close to the right code, rarely on it. To accept them you
would need fuzzy line matching, which puts back exactly the guesswork a fixed list removes. That
is the argument for a closed vocabulary in one number.

### Diagram image to DFD file

**The structure survives almost perfectly.** All 12 elements found, every name read exactly, every
shape typed correctly, all 17 flow ids reused instead of renumbered, and 14 of 17 flow endpoints
right. The 3 wrong ones sit in the same crowded corner where two arrows cross and four labels
stack. It fails where the drawing is ambiguous, not at random.

**The descriptions are what is lost.** 38 characters on average in the hand-written JSON, 15 in
the version read from the picture:

```
DF1   from JSON     "parent registration (email, password, name, govt ID, six-digit code)"
      from picture  "register"
```

That is the diagram's fault, not the model's — an edge label was never meant to hold that detail,
and the model copied it faithfully. But it matters, because the flow description is the text the
threat model actually reasons over.

**The pixel citations repeat the source-code finding in a different form.** All 63 boxes were
inside the image, but only about half landed on ink. One rescale by ×2.2 fixed nearly all of it:
the model had been working in its own ~946×784 canvas while the image was 2081×1724. The boxes
were right, just in a coordinate system nobody declared.

**That fix does not generalise.** On two diagrams exported from PILLAR's editor — dark theme,
trust-boundary shapes our schema has no type for, `DF_0`-style ids — the best single rescale only
reached 0.58–0.93, and the right scale factor changed with image size. So on a real drawing, some
pixel citations are simply wrong, and no one correction recovers them. Fixing that would need the
detector a closed vocabulary was supposed to make unnecessary — and even that would not be enough.

### Two more results from those third-party diagrams

**The citation checks hold on systems we never tuned for.** Five of six runs scored 1.00 on all
three checks. The exception, 0.97, was one threat citing `L.1.2` — the same invented node from
section 2, now appearing even in grounded mode. Together with a second case, a threat typed `Uc`
(not one of the seven LINDDUN types), that is two fabricated identifiers in total. Both came from
the smallest model, both were caught by the checker with no model involved, and the `Uc` one is
the more telling: **the output schema already declared that field as a list of the seven valid
types, and the provider let it through anyway.** Prevention did not work; checking afterwards did.

**And one failure nothing catches.** Both diagrams label a data store `ML Moldel` — a typo in
their export. gpt-5.4 copied it faithfully both times; gpt-4o-mini quietly fixed it to `ML Model`
both times. A model that "fixes" the label has edited the thing it claims to be transcribing, and
we cannot detect it: the pixel box still points at the right place, so every check passes. The
citation is right and the content is wrong. Catching this needs OCR over the cited box. Note the
direction — the change is always toward what looks more sensible, which is exactly where nobody
would think to look.

## 5. DFD alone versus DFD with source code

Two experiments, pointing opposite ways.

**Building the DFD from code costs a lot.** Recall falls 0.70 → 0.52, measured on the same 27 gold
threats so the comparison is fair. The cause is not bad code reading. Code describes the system at
its own level of detail, so many gold threats have no matching flow to attach to. Citation
validity stayed at 1.00 — the code-built DFD is a perfectly good thing to cite, it is just a
different map of the same system.

**Building it from a picture costs much less.** On those same 27 threats: hand-written 0.70, from
a picture 0.67, from code 0.52. Two reasons. The drawing already uses the analyst's names and
level of detail, so nothing has to be re-invented. And the analyst drew the planned features that
exist nowhere in the code.

**Adding code detail to a DFD you already trust helps.** Not replacing it — adding to it.

| Condition | Flows enriched | Description length | Recall | Citation |
|---|---:|---|---:|---:|
| Analyst DFD (baseline, n=3) | — | 38 chars | 0.80 | 1.00 |
| Analyst DFD + code | 14/17 | 38 → 215 chars | **0.85** | 1.00 |
| Image-derived DFD (baseline, n=1) | — | 15 chars | 0.76 | 1.00 |
| Image-derived DFD + code | 15/17 | 15 → 139 chars | 0.73 | 1.00 |

Recall goes 0.80 → 0.85, which is two more gold threats found, with precision, F1 and citation
validity all unchanged. Three rules keep it honest: structure can never change, descriptions can
only get longer, and every addition must cite a code fact that is checked afterwards.

Two caveats. It is a single run, so it is promising rather than settled. And the same treatment on
the picture-derived DFD gave 0.76 → 0.73, which is nothing outside noise.

Why it should work at all: **the two adapters fail in opposite directions.** The image adapter
reads a drawing and keeps the structure — every element, every flow id, nearly every endpoint —
but loses the data detail, because an edge label is short. The source-code adapter keeps the data
detail — field names, credentials, upload paths — but loses the structure, because code is
organised the developer's way rather than the analyst's. Taking the structure from one and the
detail from the other is the idea being tested here. It worked once, on the analyst-written DFD.
It did nothing on the picture-derived one.

### Which arms actually travel to another codebase

This goes the opposite way to what you would guess, and it is worth being blunt about.

`facts_only` and `llm` both work from **facts**, and facts exist only because a parser recognised
Express routes and Mongoose models in `.js` files. Point either arm at a TypeScript, Django or
Rails project and there are no facts. For `llm` that is worse than it sounds: anything citing no
fact is dropped, so the output is not a poor DFD, it is an **empty** one.

`llm_naive` reads the raw source instead, so it is the only arm that runs anywhere at all.

**So the arm that generalises is the arm whose citations are 0.25 valid, and the two arms at 1.00
are locked to whatever the parser understands.** Extending the fixed-menu idea to a new stack
means writing a new parser, not writing a new prompt.

Two further limits on that parser, measured rather than assumed. It has only ever been run on one
repository. And two of its rules are tuned to that application's own naming — a guard function
called `requireRole`, and fields called `userType` or `role`. Remove those and the same code on a
similar Express app yields 11 elements instead of 14 and 15 flows instead of 27: it loses **all
three external entities and every actor flow**, which for privacy threat modelling is the half
that matters most.

## 6. Comparison with PILLAR

| | PILLAR | Ours |
|---|---:|---:|
| Model | gpt-4o-mini | gpt-4o-mini |
| Input | `dfd.png` | `dfd.png` |
| Findings | 105 | 77 |
| Precision / Recall / F1 | 0.21 / 0.54 / 0.30 | **0.35 / 0.66 / 0.46** |
| Node ids that resolve | 0.82 | **1.00** |
| Citations checked afterwards | no | yes |

**This is the closest to a fair test the project has.** Both systems were given the same picture —
`dfd.png` — and both ran the same model, gpt-4o-mini. Nothing about capability or input favours
either side.

**Both then misread the picture, in different ways.** The drawing has 12 elements and 16 distinct
arrows. PILLAR found 10 of the 16 and added 4 arrows that are not drawn. Our adapter copied all 17
printed flow labels but put the endpoints in the right place for only 8 of them, and missed one
element completely. On getting the arrows right, **PILLAR actually did better than we did.**

**So why do we score higher on threats?** Because of how matching works, not because we understood
the diagram better. The answer key is anchored to the flow labels `DF1`…`DF17`. Our adapter copies
those labels off the diagram, so our threats land on the right label even when the arrow underneath
points at the wrong box. PILLAR does not copy the labels, so its findings have to be matched by
shape instead — and its 4 invented arrows can never match, while 11 gold threats sit on flows it
never recovered. That caps its precision at 0.73 and its recall at 0.73.

Those caps fall on PILLAR alone. Not because we rigged the test, but because **the matcher rewards
copying labels**, which our adapter does and PILLAR does not. That is a property of our adapter,
not of our threat finding.

**The citation half is the real comparison.** We split PILLAR's 315 node citations rather than
lumping them, because most of its failures are not hallucinations:

- **0.68** match our knowledge base exactly.
- **0.14** match once you ignore capitalisation (`DD.1.1` vs `Dd.1.1`) — a convention, not a
  mistake.
- **0.18** are not identifiers at all: empty strings, or prose like "Not applicable" sitting in an
  id field.
- **0.00** are unresolvable.

An earlier version of this comparison said 12% of PILLAR's citations were deeper than our
knowledge base went. Replacing our curated 51-node subset with the official 65-node trees took
that to zero — so that gap was our coverage problem, not theirs.

So the honest claim is about architecture, not scores: PILLAR emits ids that mostly resolve but
need case-folding and sometimes contain prose, **and it ships them unchecked**. Ours come from a
fixed list and are re-derived after generation.

## 7. Transfer to a second framework

To see whether any of this is specific to LINDDUN, we pointed the same pipeline at a different
taxonomy — MITRE PANOPTIC — on the NIST genomic scenario, swapping the mapping-table lookup for a
PANOPTIC crosswalk. F1 is 0.08–0.19.

That number is low by design, not by failure: it requires an exact sub-activity id match against
roughly a hundred candidates. A coarser category-level version is the obvious next step.

What matters is that **the architecture transferred unchanged**: the deterministic lookup, the
citation vocabulary, and the checker all worked against a taxonomy they were never designed for.

## What we cannot claim

- **Precision is a floor everywhere.** Unmatched threats are counted wrong by default. The manual
  review that would fix this has not been done.
- **The gold standards are ours.** Both authors wrote them; no outside expert has reviewed them.
- **Most conditions are single runs.** Only the main ablation is repeated. Differences under
  about 0.05 recall are noise and are not interpreted.
- **The model comparison is one system.** All of it is KidsTube.
- **The clean image result is a best case.** Our diagram was generated from the same file it was
  scored against. Real third-party diagrams did worse.
- **The source-code adapter is one parser, one repository.** It reads `.js` only, recognises
  Express and Mongoose specifically, and two of its rules are keyed to KidsTube's own naming. It
  has never been run on a second codebase, and it fails quietly rather than loudly.
- **No one has used this for real.** We measured whether citations are correct, never whether an
  analyst works faster or trusts the output more.
