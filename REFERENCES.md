# References & Bibliography

Working bibliography for this project (AI-assisted, grounded LINDDUN Pro privacy threat modeling). Grouped by how each cluster relates to the work. arXiv entries are preprints; links are to the source of record.

## A. LINDDUN methodology — the foundation encoded in the knowledge base

- Deng, M., Wuyts, K., Scandariato, R., Preneel, B., Joosen, W. (2011). *A privacy threat analysis framework: supporting the elicitation and fulfillment of privacy requirements.* Requirements Engineering 16(1). — the original LINDDUN paper.
- Wuyts, K., Sion, L., Joosen, W. (2020). *LINDDUN GO: A Lightweight Approach to Privacy Threat Modeling.* IWPE @ IEEE EuroS&PW. <https://sion.info/assets/pdf/publications/WuytsIWPE2020.pdf>
- DistriNet, KU Leuven (2023). *LINDDUN PRO Privacy Threat Modeling Tutorial v0.1.* <https://linddun.org/publications/> — source of `threat_trees.json` and the mapping table.
- *Robust and reusable LINDDUN privacy threat knowledge* (2025). Computers & Security. <https://www.sciencedirect.com/science/article/abs/pii/S0167404825001087> — structured, reusable threat-tree knowledge.
- *Empirical evaluation of a privacy-focused threat modeling methodology.* Journal of Systems and Software. <https://www.sciencedirect.com/science/article/abs/pii/S016412121400137X>

## B. LLM-assisted privacy threat modeling — closest prior art

- *PILLAR: an AI-Powered Privacy Threat Modeling Tool* (FBK). LINDDUN + LLMs; automates DFD generation, threat categorization, and prioritization, including LINDDUN GO. <https://arxiv.org/abs/2410.08755> · code: <https://github.com/stfbk/PILLAR>
- *Benchmarking the effectiveness of multi-agent LLMs in collaborative privacy threat modeling with LINDDUN GO* (2026). Journal of Information Security and Applications. <https://www.sciencedirect.com/science/article/abs/pii/S2214212626001195>
- *PriMod4AI: Lifecycle-Aware Privacy Threat Modeling for AI Systems using LLM.* Unifies structured privacy knowledge with retrieval-augmented (RAG) LLM reasoning. <https://arxiv.org/abs/2602.04927>
- *A LINDDUN-based Privacy Threat Modeling Framework for GenAI.* <https://arxiv.org/abs/2603.06051>

## C. LLM-assisted security threat modeling (STRIDE; adjacent method)

- *ThreatModeling-LLM: Automating Threat Modeling using Large Language Models.* <https://arxiv.org/abs/2411.17058>
- *LLMs' Suitability for Network Security: A Case Study of STRIDE Threat Modeling.* <https://arxiv.org/abs/2505.04101>
- *Usefulness of data flow diagrams and large language models for security threat validation: a registered report.* <https://arxiv.org/abs/2408.07537> — relevant to evaluation design.
- *STRIDE-GPT* — GPT-based STRIDE threat-modeling tool. <https://github.com/mrwadams/stride-gpt>

## D. DFD extraction / synthesis from source code — the input front-end

- *Automatic extraction of security-rich dataflow diagrams for microservice applications written in Java* (Code2DFD). Journal of Systems and Software. <https://arxiv.org/abs/2304.12769>
- *Automatically Extracting Threats from Extended Data Flow Diagrams.* ESSoS. <https://www.researchgate.net/publication/308925595>
- Sion, L., et al. (2018). *Solution-aware data flow diagrams for security threat modeling.* ACM SAC. <https://dl.acm.org/doi/10.1145/3167132.3167285>

## E. Threat-modeling foundations

- Shostack, A. (2014). *Threat Modeling: Designing for Security.* Wiley. — STRIDE + DFD canon, LINDDUN's lineage.

## F. NIST privacy engineering & the genomic case (second scenario + its provenance)

- NIST (2025). *SP 1800-43C (DRAFT) — Genomic Data Threat Modeling: Privacy.* NCCoE. <https://www.nccoe.nist.gov/sites/default/files/2025-08/nist-sp-1800-43c-draft.pdf> — source of the genomic gold standard (bundled in `references/nist-sp-1800-43c/`).
- NIST. *CSWP 35 — Cybersecurity Threat Modeling the Genomic Data Sequencing Workflow.* <https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.35.ipd.pdf> — security companion to the privacy document.
- NIST (2017). *NISTIR 8062 — An Introduction to Privacy Engineering and Risk Management.* <https://nvlpubs.nist.gov/nistpubs/ir/2017/NIST.IR.8062.pdf> — defines the Privacy Engineering Objectives (predictability, manageability, disassociability).
- NIST (2020). *Privacy Framework v1.0.* <https://www.nist.gov/privacy-framework>
- NIST. *Privacy Risk Assessment Methodology (PRAM).* <https://github.com/usnistgov/PrivacyEngCollabSpace/tree/master/tools/risk-assessment/NIST-Privacy-Risk-Assessment-Methodology-PRAM>
- NIST. *IR 8467 — Genomic Data Cybersecurity and Privacy Frameworks Community Profile.* <https://csrc.nist.gov/pubs/ir/8467/2pd>
- MITRE. *PANOPTIC — Pattern and Action Nomenclature of Privacy Threats in Context.* — privacy attack taxonomy paired with LINDDUN in SP 1800-43C.

## G. Retrieval-augmented generation & grounding (architecture basis)

- Lewis, P., et al. (2020). *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks.* NeurIPS. <https://arxiv.org/abs/2005.11401>
- Karpukhin, V., et al. (2020). *Dense Passage Retrieval for Open-Domain Question Answering.* EMNLP. <https://arxiv.org/abs/2004.04906> — dense side of hybrid retrieval.

## H. Primary regulatory sources (in / needed for the knowledge base)

In the knowledge base (KidsTube):
- COPPA — 16 CFR Part 312. <https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312>
- GDPR — Regulation (EU) 2016/679. <https://eur-lex.europa.eu/eli/reg/2016/679/oj>
- CCPA/CPRA — Cal. Civ. Code §1798.100 et seq. <https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=3.&part=4.&lawCode=CIV&title=1.81.5>

Needed for genomic grounding (currently absent from `regulations.md`):
- HIPAA Privacy Rule — 45 CFR Parts 160 & 164.
- Genetic Information Nondiscrimination Act (GINA), 2008.
- Common Rule — 45 CFR 46.
- Clinical Laboratory Improvement Amendments (CLIA).

## Notes on positioning

PILLAR (B), the multi-agent LINDDUN GO benchmark (B), and PriMod4AI (B) are the nearest prior art — LINDDUN + LLMs. This project's intended differentiation: grounded per-node retrieval over the full LINDDUN Pro trees, an authoritative NIST-derived gold standard, and **code → DFD** as a supported input (the gap least addressed by the above).
