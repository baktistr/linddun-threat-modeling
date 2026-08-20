# Methodology — plain summary

A short version of the Methodology section of *Evaluating Privacy Threat Modelling with LLMs*.
Full detail is in `PE Research Project.md`.

## The problem in one line

An LLM can suggest privacy threats. The analyst cannot tell which suggestions follow the
methodology and which are invented. We make every suggestion carry two citations, then check
both ourselves.

## A word on what "DFD" means here

The pipeline never works on a picture. It works on a **DFD file**: a JSON document listing the
elements, the flows between them, and a text description of each flow. That file is what the
model is shown, one flow at a time.

A drawing of the same system is a **diagram image** — a PNG. It is one of the things a user might
have, but it has to be converted into a DFD file first. Throughout this document, *DFD file*
means the JSON and *diagram image* means the picture.

## What the system does

Three steps.

1. **Take a system model in.** A DFD file, a source repository, or a diagram image. All three end
   up as the same DFD file.
2. **Ask the model, one flow at a time.** For each flow in the DFD file, one LLM call: which
   LINDDUN threats apply here? Every threat it returns must cite a threat-tree node and a DFD
   location.
3. **Check the citations ourselves.** No LLM involved. We look up whether the cited node and
   location actually exist.

Rule that holds the design together: **no step trusts the step before it.**

## The knowledge base

Two files do the real work. The **threat trees** are the official LINDDUN trees, version v241203:
65 nodes and 128 worked examples across the seven types. The **mapping table** is Table 4.1 of the
LINDDUN Pro Tutorial: five valid interaction types, and which threats apply to each.

## The three modes (this is the experiment)

All three ask the same question, with the same model and the same output schema. Only the
information given to the model beforehand changes.

**Grounded — what we propose.** Before the prompt is written, the system looks up the flow's two
endpoint types in the mapping table. The lookup returns the threat types that apply here, plus
the id, title and description of every tree node worth considering. All of it goes into the
prompt as a plain list, and the model is told to pick only from that list. Nothing is searched,
so a wrong node cannot come back. If the two endpoint types are not one of the five valid
combinations, the model is never called for that flow at all — the same rule the scorer uses to
mark a gold threat unreachable.

**RAG — the comparison.** Real retrieval. The flow is turned into a search query, and the system
pulls the top five passages from the same knowledge base the lookup reads. Keeping it to that one
source means only the mechanism changes, not the knowledge available. The passages are offered as
guidance rather than as a list to choose from, because a search cannot promise the right node was
found. There is no skip rule here: every flow gets a call.

**Ungrounded — the baseline.** The model gets the flow description and nothing else. Whatever it
knows about LINDDUN comes from its training.

The difference that matters is one word. Grounded is a **lookup**, so it cannot return the wrong
node. RAG is a **search**, so it can miss the right one entirely. Running both is how we tell
those apart.

## The check after generation

Three tests per threat, all of them plain file lookups. Does the cited tree node exist under the
cited threat type? Is that threat type allowed at this kind of interaction? Does the cited DFD
location exist? A threat passes only if all three pass.

We do not ask a model to grade the model. A checker that asks the model whether it was right is
not a checker.

## Getting a DFD file in

There are three ways in, and two of them need converting.

An **analyst-authored DFD file** needs no work at all. It is already the JSON the pipeline wants,
so it enters unchanged, and it cites nothing, because a person wrote it.

**Source code** goes through an extractor that pulls out code facts, and the DFD file is built
from those. Every element and flow cites a fact id, and each id is re-parsed from the source to
confirm it.

A **diagram image** is read by a vision model, which writes out the DFD file. Every element and
flow cites the pixel box it was read from, and each box is re-checked against the image. Note
what is lost here: a diagram's edge labels are short, so the flow descriptions come back far
thinner than the ones a person types into the JSON.

There is also an optional **enrichment** step: keep a DFD file whose structure you trust, and add
data details from code. It may only lengthen descriptions. It may never change structure.

## From source code to a DFD file, step by step

Code does not come with a DFD. Something has to decide that `/api/auth` is a Process, that the
`users` collection is a Data Store, and that a flow runs between them. The real question is **who
decides, and can anyone check them afterwards.**

### Step 1: read the code into "facts"

A parser walks every `.js` file and writes down what it sees. One construct, one record. It does
not interpret anything.

Line 12 of `backend/routes/auth.js` says roughly:

```js
router.post('/register', imageUpload.single('profileImage'), async (req, res) => {
```

The parser writes down one fact:

```
[F8d4ae4f3] express_route  backend/routes/auth.js:12
    method='POST'  router_path='/register'  middleware=["imageUpload.single('profileImage')"]
```

Notice what the fact does **not** say. It does not say "this is the registration service", or
"this handles children's data". It says only what is literally on that line. Interpreting it is
the next step's job, and keeping the two apart is what makes checking possible later.

KidsTube gives **492 facts from 36 files**. Run it again on the same code and you get the same 492,
in the same order — it is a parser plus a list of patterns, with no LLM anywhere. That is all
"deterministic" means here.

The id `F8d4ae4f3` is a short hash of the fact's own content: kind, file, line and fields. It is
deliberately not a counter, so adding a new kind of fact later does not renumber everything and
silently break citations already written down.

### Step 2: turn the facts into a DFD — three ways

**Arm 1, `facts_only`: rules only, no LLM.** One rule per kind of fact. Each mounted router
becomes a Process. Each collection, folder or browser storage area becomes a Data Store. Each role
named in a permission check becomes an External Entity. A write to a collection becomes a
Process → Data Store flow; a read becomes the reverse.

On KidsTube this gives 14 elements and 27 flows, identical every run. But the names are whatever
the code calls things — the Process is called `/api/auth`, not "Authentication Service". It cannot
merge fifteen similar routes into one box, and it cannot decide that something is not worth
drawing at all. Those are exactly the judgements a human analyst makes.

This arm exists to be the bar. If the LLM cannot beat plain rules, it has not earned its place.

**Arm 2, `llm`: the model decides, but from a fixed menu.** The model is given the 492 facts —
not the source — and writes the DFD: better names, sensible grouping, sensible level of detail.
The catch is that every element and flow must cite fact ids **from the list it was handed**.

If it cites an id that is not on the list, that element is thrown away. Not flagged — thrown away.

Here is why that matters. The model knows KidsTube is a children's video site, and it wants to add
an "AI Recommendation Engine" and "Third-Party Advertisers", because sites like this usually have
them. KidsTube's written plans do mention them. But no code implements them, so no fact mentions
them, so nothing can cite them, so they are dropped. **"Do not make things up" stops being an
instruction in the prompt and becomes something the code enforces.**

**Arm 3, `llm_naive`: the model decides and writes its own citations.** Same job, but it reads the
raw source and invents its own `file:line` references. No menu, no filter. This is the control
condition: it shows what the fixed menu was actually buying.

### One example, all the way through

```
Child.js line 133    mongoose.model('ChildProfile', childProfileSchema)
        ↓            parser rule
fact F1b828376       a model named 'ChildProfile' is registered here
        ↓            Mongoose pluralises model names; the extractor re-runs that rule
fact Fc12aadaf       collection name is 'childprofiles'          ← marked "derived"
        ↓            facts_only rule: one Data Store per collection
element DS1          "MongoDB childprofiles collection"
        ↓            read and write facts on routes under three mounts
flows                DS1 → P1, DS1 → P2, P2 → DS1, DS1 → P3
```

One thing in that chain is different from the rest. The word `childprofiles` **appears nowhere in
KidsTube's source code**. It exists only because Mongoose turns model names into collection names,
and the extractor copies that rule. Still deterministic, but it is computed rather than read, so
the checker can re-run the rule and cannot point at a line proving it. 103 of the 492 facts are
like this, and every one is labelled "computed by rule, not present in any source line". It is the
one honest gap in the "we check everything" story, so we mark it rather than hide it.

### What the three arms scored

Citations valid: `facts_only` 1.00, `llm` 1.00, `llm_naive` 0.25.

The first two cannot really lose, because anything uncitable never reaches the output. The number
that carries information is the last one. And its failure is specific: the naive arm's citations
always name a real file and a real line — it never invented a path — but they are the **right**
line only 27% of the time.

That is the whole argument for the fixed menu, in one number. Left free, the model points near the
right code instead of at it, and "near" is not something a checker can accept without guessing.

### What this adapter does and does not read

It reads `.js` files, and recognises Express routes and mounts, Mongoose models and queries, file
uploads, and browser storage. It is a Node/Express/Mongoose adapter. TypeScript, Django, Rails or
Spring produce nothing at all. Two of its rules are tuned even more narrowly than that, to
KidsTube's own naming: it looks for a guard function called `requireRole` and for fields called
`userType` or `role`, and those are what produce the parent, child and admin entities.

The parts meant to generalise are the schema, the fixed-menu citation rule, and the practice of
reporting the ceiling. Not the JavaScript patterns.

## What we tested on

Six systems, given as elements, flows and gold threats: KidsTube (12, 17, 41), Smart Home
(7, 8, 18), Family Location (8, 13, 20), School Grades (10, 15, 20), Wearable Fitness
(7, 10, 20), and Genomic (32, 39, 99).

The five LINDDUN catalogs were written by hand by both authors, against the official trees. None
was produced by the system being tested. Genomic comes from a published NIST report and is scored
under MITRE PANOPTIC instead.

## How the runs were done

- **Models:** gpt-5.4, gpt-4o-mini, grok-4.3 — one Azure endpoint, three deployments.
- **Output:** forced tool call. No free text is ever parsed.
- **Temperature:** 0. Note this reduces randomness but does not remove it — three identical
  calls agreed on 8 of 10 cited nodes.
- **Repeats:** the main ablation is 3 runs per cell. 5 scenarios x 3 modes x 3 runs = 45 runs,
  567 calls. Everything else is a single run and is labelled as such.

## How we scored

A generated threat matches a gold threat when **the threat type is the same and both point at the
same DFD flow**.

- **Citation validity** — share of threats passing all three checks. Does not use the gold
  standard at all.
- **Recall** — share of gold threats found.
- **Precision** — share of generated threats that matched.

One caveat that applies everywhere: **precision is a floor, not a real number.** Our gold
standards are curated lists, not complete ones. A genuinely good threat that the list never
mentioned is still counted as wrong. Sorting real mistakes from uncatalogued-but-valid threats is
a human job, and we have not done it yet, so no corrected precision is reported.

## Reproducibility

Figures are generated from the stored run files by a script, not typed in. Every run records the
code commit it came from. 521 offline tests run with no network and no API key.
