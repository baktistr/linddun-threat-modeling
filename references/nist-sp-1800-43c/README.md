# NIST SP 1800-43C — source materials

Source documents for the **genomic** evaluation scenario
(`knowledge_base/scenarios/genomic/`). Kept here for provenance and as the audit
trail behind the genomic gold standard. These files are **not** part of the RAG
corpus — `references/` is outside the ingestion path (`config.CORPORA`), so nothing
here is chunked or indexed.

## What's here

| Path | Contents |
|------|----------|
| `nist-sp-1800-43c-draft.pdf` | The report (56 pp). The body walks through the *core example*; Appendices A–B are included, C–G are referenced as external links on the last page. |
| `appendix/appendixA–G.rst`, `index.rst` | reStructuredText source of the external appendices (from NIST's GitHub repo). The substantive appendices (E system description, F dataflow analysis, G validation/prioritization) are mostly `.. figure::` directives — the data lives in the figures below. |
| `appendix/media/Appendix-Figure*.png` | The appendix figures (25 PNGs). These are the raster tables that hold the **complete example** (~99 threats); there is no machine-readable version anywhere NIST published. |

## How this maps to the gold standard

The genomic gold standard (`knowledge_base/scenarios/genomic/gold_standard_threats.json`)
was transcribed (vision OCR) primarily from:

- **`Appendix-Figure20.png`** — Threat Validations and Ranking Attributes (node, scenario, PANOPTIC actions, LINDDUN analysis text, impacted PEOs, feasibility, difficulty).
- **`Appendix-Figure24.png`** — Ranked Threats (the ranking value per threat).

`Appendix-Figure11.png` (Integrated and Sorted Dataflow Analysis) holds the per-threat
DFD source/destination/context; it was read for structure but not transcribed at high
confidence. The raw transcription is committed at `scripts/data/genomic_complete_raw.json`,
and `scripts/build_genomic_gold.py` regenerates the gold JSON from it.

> The figures are from a **DRAFT** (public comment period Aug–Sep 2025). Treat
> transcribed details as transcription-confidence and verify against these figures
> before relying on a single row.

## Provenance & license

- **Report:** NIST SP 1800-43C (DRAFT, August 2025), *Genomic Data Threat Modeling: Privacy — An Implementation for Genomic Data Sequencing and Analysis*, National Cybersecurity Center of Excellence (NCCoE), NIST.
- **Project page:** <https://www.nccoe.nist.gov/projects/cybersecurity-and-privacy-genomic-data>
- **PDF:** <https://www.nccoe.nist.gov/sites/default/files/2025-08/nist-sp-1800-43c-draft.pdf>
- **Appendix source (figures + rst):** <https://github.com/usnistgov/nccoe-genomic-data-threat-modeling> (rendered: <https://pages.nist.gov/nccoe-genomic-data-threat-modeling/>)
- **License:** Works of the U.S. federal government are not subject to copyright in the United States (17 U.S.C. §105). NIST publications are in the public domain; attribution is appropriate.
