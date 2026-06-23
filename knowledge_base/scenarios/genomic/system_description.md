# Genomic Sequencing (NIST SP 1800-43C complete example) — System Description

> Second evaluation scenario, complementing KidsTube. Source: NIST SP 1800-43C (DRAFT, August 2025), *Genomic Data Threat Modeling: Privacy — An Implementation for Genomic Data Sequencing and Analysis*, NCCoE. <https://www.nccoe.nist.gov/projects/cybersecurity-and-privacy-genomic-data>. The report PDF and the appendix figures/sources are bundled in the repo at [`references/nist-sp-1800-43c/`](../../../references/nist-sp-1800-43c/). Unlike KidsTube, this scenario is **authoritative**: NIST performs its own LINDDUN + PANOPTIC analysis and validates each threat against the NIST Privacy Engineering Objectives (PEOs). The gold standard covers the **complete example** (~99 itemized threats across the clinical and research pipelines plus their shared backbone). The PDF body only walks through the small *core example* (the shared subset); the complete analysis is published only as figures in the external HTML appendices and was transcribed from there.

## Overview

A genomic sequencing service receives biological samples, sequences the DNA, runs bioinformatics analysis, and delivers context-relevant results. The service supports two pipelines that share a common backbone: a **clinical** pipeline (sequence a patient's DNA, deliver clinical results to patient and physician) and a **research** pipeline (sequence donor DNA, deliver research insights to trusted/invited data recipients and publishing locations). The **core example** is the shared portion common to both pipelines — sample intake, wet-lab sequencing, cataloging/pseudonymization, compute-cluster analysis, and delivery staging — operated end-to-end by a single managing party, the sequencing service. The **complete example** additionally models the clinical-specific and research-specific dataflows; threats from all three are combined in the gold standard (each tagged `in_core_example`).

The defining privacy property of this domain: genomic data is *inherently identifying and immutable*, pertains to relatives as well as the data subject, and can reveal disease susceptibility — so complete disassociability cannot be guaranteed even after pseudonymization.

## Privacy framing

- **Privacy Engineering Objectives (PEOs):** predictability, manageability, disassociability (NIST IR 8062 / Privacy Framework). A validated threat must undermine at least one.
- **Data subjects:** the *direct data subject* (patient / research donor) and, indirectly, their genetic relatives.
- **Primary threat actor in the core example:** an honest-but-curious pipeline insider with physical or digital access (e.g., a receiving clerk, lab technician), able to correlate study context with samples/data — plus the software supply chain behind bioinformatics tooling.
- **Regulatory environment (governance layer, not per-dataflow):** HIPAA Privacy Rule / PHI, Genetic Information Nondiscrimination Act (GINA), Clinical Laboratory Improvement Amendments (CLIA), College of American Pathologists (CAP), GDPR, state laws (CCPA, Alabama HB21 Genetic Data), NIH requirements, and the Common Rule (45 CFR 46: IRB oversight, informed consent, protections for vulnerable groups).

## Key Personal Data Assets

- **Biological sample:** the physical specimen (e.g., blood, saliva, tissue) — bodily-privacy asset.
- **Sample metadata:** test/research request forms, chain-of-custody records, demographics, and the LIMS-assigned pseudonymized ID.
- **Sequence data:** raw and processed digital genomic sequence — inherently identifying and immutable.
- **Context-relevant research/clinical data:** analysis output derived from the sequence (e.g., disease susceptibility, treatment-personalization insight).
- **Linkage context:** the association between a sample/data batch and the study or disease it belongs to, often inferable from co-timing.

## Data Action Types (NIST PRAM / Privacy Framework)

Collection · Generation/Transformation · Disclosure/Transfer · Retention/Logging · Disposal. The core-example DFD exercises Generation/Transformation, Disclosure/Transfer, and Retention/Logging.

## DFD Elements

Component IDs use the NIST convention: the **`S`** prefix marks the *shared* dataflow (the core example); `-PH` / `-A` suffixes are NIST sub-case tags. Numbering follows the complete-example diagram and is therefore not fully sequential. A single managing party (the sequencing service) is responsible for all elements.

### External Entities / Actors
- S1-PH Receiving Clerk — intakes the physical sample and hands it off for sequencing
- S2-A Lab Technician — prepares and transforms the sample into digital data in the wet lab
- S17 Third-party bioinformatics tools / software — externally developed analysis tooling used along the pipeline

### Processes
- S3-PH Wet Lab — prepares samples and sequences DNA into digital data
- S5-A Compute Nodes — run bioinformatics analysis, transforming sequence data into context-relevant research/clinical data

### Data Stores
- S4-PH LIMS (Laboratory Information Management System) — catalogs the sample and issues a pseudonymized tracking ID
- S6-A Cluster Filesystem — stores digital sequence data and analysis output
- S11-PH Physical Sample Storage — freezers retaining leftover physical sample material
- S13-A Data Delivery DMZ — demilitarized zone where results are staged for delivery to the recipient

### Trust / Management Notes
- All elements are managed by the sequencing service (single responsible party in the core example).
- The Data Delivery DMZ (S13-A) is the delivery boundary at which results leave the service.

### Dataflow Segments (core example, NIST Figure 4 / Table 12)
Each segment is a source → flow → destination triad with its data action(s).
- DF1 S1-PH→S2-A: transfer physical sample to lab tech for sequencing
- DF2 S2-A→S3-PH: transfer physical sample to wet lab for sequencing
- DF3 S3-PH→S11-PH: retain leftover physical sample in freezers
- DF4 S3-PH→S4-PH: generate + retain pseudonymized sample ID (sample metadata) in LIMS
- DF5 S4-PH→S3-PH: return the pseudonymized ID to the wet lab for use on the sample
- DF6 S3-PH→S6-A: transfer + retain digital sequence data on the cluster filesystem
- DF7 S6-A→S5-A: transfer sequence data to compute nodes for analysis
- DF8 S5-A→S6-A: transform sequence data into context-relevant research data (returned to filesystem); analysis uses third-party tools (S17)
- DF9 S6-A→S13-A: transfer generated context-relevant research data to the data delivery DMZ for delivery

## Additional components in the complete example

The complete example (clinical + research pipelines) introduces further actors and components that appear as sources/destinations of the ~99 threats. Per-threat DFD source/destination are documented in NIST Figure 11 (Appendix F) and are not transcribed at high confidence here; the gold standard records the NIST PANOPTIC scenario id (`scenario_id`) per threat instead. Notable additional elements:

- **Clinical actors/components:** Patient (data subject), Clinician, Genetic Physician, Genetic Counselor, Bioinformaticist/Bioinformatician, Clinical Result Generation App, Internal/External EMR, 3rd Party Portal, 3rd Party Previous Enrollment Entity.
- **Research actors/components:** NCCoE Researcher, DNA Store, Digital Sample Data Store, NCCoE-hosted/-trusted/-invited Data Recipient, Trusted Research Data Recipient, NCCoE-Managed and Externally-Managed Publishing Locations.
- **Lab/device lifecycle:** Physical Sample Management Technician, Device Acquisition/Decommissioning Specialist, used flow cells, privacy-relevant wet-lab devices.

These broaden the LINDDUN coverage to all 7 types — e.g. Identifying (re-identification of research-data groups), Non-repudiation (authenticated in-person result delivery), Detecting (inferring a patient's health from contact with a genetic counselor), Data Disclosure (over-generation/retention, supply-chain), Unawareness/Unintervenability (consent gaps, family members who cannot consent, no withdrawal), and Non-compliance (improper retention/disposal).
