# Week 13 — BM25 for the RAG arm, and what a fair retrieval baseline is worth

**Project:** AI-Assisted Privacy Threat Modeling — LINDDUN Pro, LLM-Grounded and Verified
**Week:** 13
**Author:** Bakti Satria Adhityatama

## Goal for Week 13

Make the RAG arm use **Okapi BM25**, and then find out whether that changes anything.

The motivation is a reviewer-facing one. The report's central claim is that deterministic
grounding beats retrieval on citation validity (1.00 against 0.87–0.98). The obvious objection is
that the retrieval arm was handicapped: it ran TF-IDF cosine, a week-1 placeholder chosen because
it needed no model downloads, and "your baseline was weak" is the cheapest way to dismiss an
ablation. BM25 is what a reader means by *lexical retrieval baseline*, so the arm should be it.

That framing decides the week's shape. Swapping the backend is the small part; the part that
matters is measuring whether the swap moves any result, because only a measurement licenses the
sentence "the comparison does not depend on the retriever."

## What was found first: BM25 existed, but nothing used it

`Bm25Backend` was already written in `retrieval/embeddings.py`, and it is genuine Okapi BM25, not
an approximation — validated this week against an independently written textbook per-query
implementation over all 475 corpus chunks: **max deviation 9e-7 (float32 noise), identical top-20
rankings** on six probe queries. Saturating TF, Lucene IDF (which decays to ~0 for corpus-wide
terms instead of going negative), explicit `b` length normalization, presence-only query side.

The arm did not use it. Two layers pinned TF-IDF:

1. `config.EMBEDDING_BACKEND` defaulted to `"tfidf"`.
2. **`.env` line 2 set `EMBEDDING_BACKEND=tfidf`** — the actual culprit, and the one that would
   have survived changing the config default alone.

So `Retriever.load()` in `generation/generate.py` returned a TF-IDF retriever on every `rag` and
`panoptic_rag` run ever made. A backend can be implemented, tested, and indexed, and still not be
the thing the experiment ran. That is the week's transferable lesson, and it is why the sweep
script now asserts the retriever it got rather than trusting the argument it passed.

## What was built

**Default flipped to `bm25`** in `config.py`, `.env`, and `.env.example`, with the consequence
written into the config docstring rather than left implicit: every threat set through
`RESULTS_2026-08-08.md` used TF-IDF, so those rag-arm artifacts came from a different retriever
than the code now serves. The grounded and ungrounded arms never touch the index and are
unaffected.

**`retrieval_backend` override on `generate_for_scenario()`**, mirroring the existing
`model`/`dfd_path` pattern. The codebase already warns that mutating config mid-process leaks into
whatever runs next; for a retrieval backend that means a later run silently scoring against the
wrong index. Passing it per call lets one process run both conditions cleanly. Default `None`
keeps the configured backend, so no existing caller changes.

**A run-log line naming the retriever** in the rag branch. A saved rag artifact is a bare JSON
list with no `_meta`, so which retriever produced it was previously unrecoverable.

**`scripts/run_rag_backend_sweep.py`** — deliberately *not* an extension of
`run_ablation_repeats.py`. That script owns `storage/ablation_repeats.json`, the 45 runs behind
Table 3 and Figure 2, and writes `repeats/{scenario}_{mode}_run{n}.json`. Routing this experiment
through it would have overwritten the published TF-IDF rag runs in place. The new script has its
own state, output directory, and report, is resumable across interruption, and writes state after
every cell.

**The index confound, found and removed.** `index.pkl` held 425 chunks while `index_bm25.pkl` held
475. The `linddun` corpus the rag arm actually retrieves from is *identical* in both (94 chunks) —
the gap is entirely `scenarios` — but corpus size feeds IDF and average document length, so it
still perturbs the scoring of linddun chunks. TF-IDF was rebuilt over the current 475-chunk corpus
so the backend is the only variable. The 425-chunk artifact is preserved at
`storage/index/index.pkl.bak-425chunks`; it is not reproducible from the current corpus and
`storage/index/` is gitignored, so that copy is the only record of it.

## The sweep — 5 scenarios × {tfidf, bm25} × 3 runs

gpt-5.4 via Azure, temperature 0 (deployment confirmed it honoured the pin), k=5,
`exclude_kinds=["gold_threat"]`, both indexes over the same 475 chunks. 30 cells, 378 generation
calls, **0 failures**, ~1h25m.

| scenario | backend | n_gen | P | R | F1 | citation |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| kidstube | tfidf | 86 (3) | 0.29 | 0.61 (0.02) | 0.39 | 0.96 (0.02) |
| kidstube | bm25 | 90 (3) | 0.27 | 0.60 (0.05) | 0.38 | 0.97 (0.02) |
| smart_home | tfidf | 46 (2) | 0.24 | 0.61 (0.06) | 0.34 | 0.94 (0.01) |
| smart_home | bm25 | 48 (1) | 0.31 | **0.81 (0.03)** | 0.44 | **1.00 (0.00)** |
| family_location | tfidf | 68 (2) | 0.24 | 0.82 (0.03) | 0.37 | 0.97 (0.00) |
| family_location | bm25 | 76 (2) | 0.23 | 0.87 (0.06) | 0.36 | 0.97 (0.02) |
| school_grades | tfidf | 76 (2) | 0.20 | 0.75 (0.09) | 0.31 | 0.95 (0.03) |
| school_grades | bm25 | 80 (2) | 0.19 | 0.78 (0.03) | 0.31 | 0.95 (0.05) |
| wearable_fitness | tfidf | 50 (2) | 0.31 | 0.77 (0.03) | 0.44 | 0.93 (0.01) |
| wearable_fitness | bm25 | 51 (1) | 0.30 | 0.77 (0.03) | 0.43 | 0.91 (0.01) |

Paired across the five scenarios, each scenario one block (the same unit of inference the
grounding ablation uses):

| metric | bm25 − tfidf | t | p | favours bm25 |
| :--- | ---: | ---: | ---: | :--- |
| recall | +0.055 | 1.47 | 0.216 | 3/5 |
| citation validity | +0.011 | 0.81 | 0.461 | 3/5 |
| F1 | +0.012 | 0.54 | 0.616 | 1/5 |
| **n_generated** | **+4.00** | 3.70 | **0.021** | **5/5** |

## The result — a null, with one documented exception

**The retrieval algorithm is not what is wrong with the RAG arm.** No quality measure separates
the backends. The only significant effect is volume: BM25 elicits about four more candidate
threats per scenario, on five of five, and precision moves against it enough that F1 favours BM25
in just 1 of 5. BM25 makes the arm more *productive*, not more *accurate*.

This was predictable before a single call was made, and was predicted. Measured up front: the two
backends return the same top-5 for **12 of 63 flows, mean Jaccard 0.88**, and the share of
retrieved context that is a threat-tree node is **6.0% (tfidf) against 4.4% (bm25)** — both near
zero. Under either scorer the context is dominated by mapping-table rows. Neither can fix a
context that rarely contains a citable node, so there was no mechanism by which a large gain could
appear. Recording that prior in the script's docstring *before* running is what makes the null
result informative rather than merely disappointing.

**smart_home is a real exception and should not be smoothed over.** +0.200 recall and +0.063
citation, with three BM25 runs at citation 1.000 (sd 0.000) against three TF-IDF runs at 0.937
(sd 0.006) — clean, non-overlapping separation, not noise, and it survived a fresh TF-IDF control
run at the current commit and rebuilt index. But it is one block in five: **excluding it, recall
falls to +0.019 (p=0.25) and citation to −0.002 (p=0.81).** It is also the smallest scenario — 8
flows, 18 gold threats, one threat = 0.056 recall — which is where a couple of better retrievals
travel furthest. One block driving a mean that the other four contradict is a finding about
heterogeneity, not an effect.

**What this buys the report.** The grounded-vs-RAG gap cannot be attributed to a weak lexical
baseline: upgrading TF-IDF to the standard retriever moves citation validity by +0.011 (p=0.46),
while the grounded arm's advantage over RAG is 0.068. The objection is now answered with a
measurement instead of an assurance.

## Documentation corrected

The write-up described retrieval as "dense semantic retrieval" and "hybrid dense-cosine" in four
places. That was **already wrong under TF-IDF** — TF-IDF cosine is sparse lexical, not dense
semantic — and would have been plainly wrong under BM25. Corrected in `PE Research Project.md`,
`PE Research Project v2.md` (the current draft), `PIPELINE.md`, and `README.md`, and the Robertson
& Zaragoza BM25 reference added to `REFERENCES.md` now that the paper names Okapi BM25.

## Tests

`tests/test_kb.py` gained a BM25 unit block (IDF ordering and non-negativity, TF saturation,
`b`-controlled length normalization, presence-only query side, end-to-end retrieval quality at the
same bar as the configured backend) and an index-integrity block asserting every persisted index
embeds its own chunk list with matching row count. Full suite: **541 passed, 0 failed**
(202 adapter + 242 generation + 97 KB).

## Open items / caveats

- **The report's RAG row no longer matches the code.** The rag numbers in `PE Research Project
  v2.md` come from TF-IDF runs against the 425-chunk index. The Week 13 TF-IDF column is the fresh
  control at the current corpus and commit; if the paper should describe the code as it now
  stands, those are the numbers to use. Deciding this is a paper-level call, not made this week.
- **v2 has no section for this experiment.** The backend sweep is stated inline in the methodology
  (§ retrieval corpus) rather than given its own results section. If it deserves one, Section 8 is
  where it goes.
- **The real RAG problem is unchanged and unaddressed.** Retrieved context is ~95% mapping-table
  rows and methodology prose under both backends; gold-node recall@5 was measured at 3%/0% in Week
  12's probe. The promising variant remains retrieving tree nodes and mapping rows into *separate*
  prompt slots rather than swapping one for the other — the tree-nodes-only probe traded ~0.20
  recall for at most +0.07 citation and is not shippable as a default.
- **`sbert` is still untested as an arm.** Both backends compared this week are lexical, so
  neither addresses vocabulary mismatch between scenario prose and LINDDUN's formal wording. That
  is the hypothesis a dense encoder would actually test, and the null result here makes it the
  more interesting remaining question.
- The 425-chunk TF-IDF index exists only as an untracked `.bak` file.

## Next

Decide the paper-level question above, then either add Section 8 or fold the sweep into the
existing methodology paragraph. If the RAG arm is to be improved rather than merely made fair, the
separate-prompt-slots variant is the next experiment, and it is a prompt-construction change, not
a retrieval one — which is the conclusion this week's null result points at.
