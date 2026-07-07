"""Builds the genomic scenario's complete dfd.json and adds per-threat DFD location fields
(dfd_source_id/dfd_destination_id/...) to gold_standard_threats.json.

Source: NIST SP 1800-43C DRAFT, Appendix F, Figure 11 ("Task 4: Assess System Design") --
references/nist-sp-1800-43c/appendix/media/Appendix-Figure11.png. This table gives an explicit
Source/Destination/Dataflow-Type/Data-Action/Context row for every one of the 99 threats, row-
aligned 1:1 with gold_standard_threats.json's `id` (verified below by cross-checking the LINDDUN
node column against each threat's existing `nist_node`).

This corrects a mistake in the initial Week 3 dfd.json: that version only covered the 9-flow
"shared pipeline" (Figure 7) and treated the other 89 threats' locations as untranscribable. They
are not -- Figure 11 gives them explicitly. The element/flow inventory here also draws on
Appendix E Figures 4-7 (the four DFDs: shared, clinical, research-physical, research-digital) for
element names/types.

Run: PYTHONPATH=. python3 scripts/build_genomic_dfd.py
"""
from __future__ import annotations
import json

import config

# Row = (id, nist_node, source_name, source_id, dataflow_type, action1, action2, dest_name, dest_id, context)
# Transcribed by vision-reading Appendix-Figure11.png in ~10-row bands for legibility.
ROWS = [
    (1, "L.2.1.2", "Wet Lab", "S3-PH", "Physical Sample", "Transfer", "Retention", "Physical Sample Storage", "S11-PH", "Send the physical sample to be stored in the appropriate freezers"),
    (2, "L.2.1.2", "LIMS", "S4-PH", "Sample Metadata", "Transfer", "", "Wet Lab", "S3-PH", "Send back to the wet lab the de-identified ID to be used for the sample"),
    (3, "L.2.1.2", "Wet Lab", "S3-PH", "Sequence Data", "Transfer", "Retention", "Cluster Filesystem", "S6-A", "Send the digital raw sequence data to be stored"),
    (4, "L.2.1.2", "Cluster Filesystem", "S6-A", "Sequence Data", "Transfer", "", "Compute Nodes", "S5-A", "Send digital raw sequence data to Compute Nodes to operate on the data to transform it into objective-specific data"),
    (5, "L.2.1.2", "Cluster Filesystem", "S6-A", "Context-relevant Research Data", "Transfer", "", "Data Delivery DMZ", "S13-A", "Send the generated context-relevant research data to the data delivery DMZ for making it available for delivery"),
    (6, "L.2.1.2", "NCCoE Researcher", "R1-A", "Physical Sample Request", "Transfer", "", "DNA Store", "R2-RP", "NCCoE Researcher submits the physical sample request to obtain the physical sample from the DNA Store that will be sent to the sequencing lab"),
    (7, "L.2.1.2", "DNA Store", "R2-RP", "Physical Sample", "Collection", "", "NCCoE Researcher", "R1-A", "NCCoE Researcher retrieves the physical sample referenced by the physical sample request from the DNA Store"),
    (8, "L.2.1.2", "NCCoE Researcher", "R1-A", "Physical Sample", "Transfer", "", "Receiving Clerk", "S1-PH", "NCCoE Researcher sends the physical sample to the sequencing lab that will generate context-relevant research data"),
    (9, "L.2.1.2", "Clinician", "C2-A", "Physical Sample Request", "Transfer", "", "Patient", "C1-A", "Clinician provides patient with the test request form to obtain the physical sample that will be sent to the sequencing lab"),
    (10, "L.2.1.2", "Patient", "C1-A", "Physical Sample", "Collection", "", "Clinician", "C2-A", "Clinician retrieves the physical sample referenced by the physical sample request"),
    (11, "L.2.1.2", "Clinician", "C2-A", "Physical Sample", "Transfer", "", "Receiving Clerk", "S1-PH", "Clinician sends the physical sample to the sequencing lab that will generate context-relevant research data"),
    (12, "L.2.1.2", "NCCoE Researcher", "R1-A", "Digital Sample Data Request", "Transfer", "", "Digital Sample Data Store", "R4-RD", "NCCoE Researcher submits the digital sample request to obtain the digital sample data from the Digital Sample Data Store that will be sent to the sequencing lab"),
    (13, "L.2.1.2", "Digital Sample Data Store", "R4-RD", "Digital Sample Data", "Collection", "", "NCCoE Researcher", "R1-A", "NCCoE Researcher retrieves the digital sample data referenced by the digital sample data request from the Digital Sample Data Store"),
    (14, "L.2.2.1", "Receiving Clerk", "S1-PH", "Physical Sample", "Transfer", "", "Lab Technician", "S2-A", "Send the physical sample to the lab technician working on the relevant research project"),
    (15, "L.2.2.1", "Lab Technician", "S2-A", "Physical Sample", "Transfer", "", "Wet Lab", "S3-PH", "Send the physical sample to the wet lab to be sequenced"),
    (16, "L.2.2.2", "Genetic Counselor", "C4-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Counselor meets with the Patient and reviews the test results with them, providing recommendations, next steps, and a copy of the results"),
    (17, "L.2.2.2", "Genetic Physician", "C5-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Physician provides patient with their results and professional recommendations"),
    (18, "I.1.1", "DNA Store", "R2-RP", "Physical Sample", "Collection", "", "NCCoE Researcher", "R1-A", "NCCoE Researcher retrieves the physical sample referenced by the physical sample request from the DNA Store"),
    (19, "I.1.1", "NCCoE Researcher", "R1-A", "Physical Sample", "Transfer", "", "Receiving Clerk", "S1-PH", "NCCoE Researcher sends the physical sample to the sequencing lab that will generate context-relevant research data"),
    (20, "I.1.1", "Patient", "C1-A", "Physical Sample", "Collection", "", "Clinician", "C2-A", "Clinician retrieves the physical sample referenced by the physical sample request"),
    (21, "I.1.1", "Clinician", "C2-A", "Physical Sample", "Transfer", "", "Receiving Clerk", "S1-PH", "Clinician sends the physical sample to the sequencing lab that will generate context-relevant research data"),
    (22, "I.1.1", "Cluster Filesystem", "S6-A", "Context-relevant Research Data", "Transfer", "", "Clinical Result Generation App", "C3-A", "Cluster Filesystem sends the context-relevant research data to the Clinical Result Generation App to create a final clinical report"),
    (23, "I.1.1", "Genetic Counselor", "C4-A", "Patient Re-identification Request", "Transfer", "", "3rd Party Previous Enrollment Entity", "C8-A", "Genetic Counselor provides the results to the 3rd Party Previous Enrollment Entity to update their records for any studies the Patient is involved in"),
    (24, "I.1.1", "Digital Sample Data Store", "R4-RD", "Digital Sample Data", "Collection", "", "NCCoE Researcher", "R1-A", "NCCoE Researcher retrieves the digital sample data referenced by the digital sample data request from the Digital Sample Data Store"),
    (25, "I.1.2", "Bioinformaticist", "C6-A", "Sequence Data", "Retention", "", "Cluster Filesystem", "S6-A", "Bioinformaticist reviews the sequence data and ensures there were no undetected sequencing issues."),
    (26, "I.2.1.1", "Wet Lab", "S3-PH", "Sample Metadata", "Generation", "Retention", "LIMS", "S4-PH", "Generate the de-identified ID to be used for the sample"),
    (27, "I.2.1.1", "Bioinformaticist", "C6-A", "Sequence Data", "Retention", "", "Cluster Filesystem", "S6-A", "Bioinformaticist reviews the sequence data and ensures there were no undetected sequencing issues."),
    (28, "I.2.3", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "NCCoE-trusted Data Recipient", "R3-A", "Make the context-relevant research data available for the NCCoE-trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (29, "I.2.3", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "Trusted Research Data Recipient", "C7-CR", "Make the context-relevant research data available for the Trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (30, "I.2.3", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "Transfer", "NCCoE-Managed Publishing Location", "R5-A", "Make the context-relevant research data available for researchers and trusted interested parties with access to the NCCoE-Managed Publishing Location to retrieve"),
    (31, "I.2.3", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "", "Externally-Managed Publishing Location", "R6-A", "Make the context-relevant research data available for researchers and interested parties to retrieve from the Externally-Managed Publishing Location"),
    (32, "Nr.1.1", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "NCCoE-trusted Data Recipient", "R3-A", "Make the context-relevant research data available for the NCCoE-trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (33, "Nr.1.1", "Genetic Counselor", "C4-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Counselor meets with the Patient and reviews the test results with them, providing recommendations, next steps, and a copy of the results"),
    (34, "Nr.1.1", "Genetic Physician", "C5-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Physician provides patient with their results and professional recommendations"),
    (35, "Nr.1.1", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "Trusted Research Data Recipient", "C7-CR", "Make the context-relevant research data available for the Trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (36, "Nr.1.1", "Genetic Counselor", "C4-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Counselor meets with the Patient and reviews the test results with them, providing recommendations, next steps, and a copy of the results"),
    (37, "Nr.1.1", "Genetic Physician", "C5-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Physician provides patient with their results and professional recommendations"),
    (38, "Nr.1.1", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "Transfer", "NCCoE-Managed Publishing Location", "R5-A", "Make the context-relevant research data available for researchers and trusted interested parties with access to the NCCoE-Managed Publishing Location to retrieve"),
    (39, "Nr.1.1", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "", "Externally-Managed Publishing Location", "R6-A", "Make the context-relevant research data available for researchers and interested parties to retrieve from the Externally-Managed Publishing Location"),
    (40, "Nr.2", "Genetic Counselor", "C4-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Counselor meets with the Patient and reviews the test results with them, providing recommendations, next steps, and a copy of the results"),
    (41, "Nr.2", "Genetic Physician", "C5-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Physician provides patient with their results and professional recommendations"),
    (42, "D.1", "Genetic Counselor", "C4-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Counselor meets with the Patient and reviews the test results with them, providing recommendations, next steps, and a copy of the results"),
    (43, "D.1", "Genetic Physician", "C5-A", "Interpreted Clinical Results and Professional Recommendations", "Disclosure", "", "Patient", "C1-A", "Genetic Physician provides patient with their results and professional recommendations"),
    (44, "D.1", "3rd Party Previous Enrollment Entity", "C8-A", "Outreach Attempt", "Disclosure", "", "Patient", "C1-A", "3rd Party Previous Enrollment Entity informs Patient that a new record has been added to their file"),
    (45, "D.2", "Bioinformaticist", "C6-A", "Tool Selection and Job Queue", "Generation", "Transfer", "Compute Nodes", "S5-A", "Bioinformaticist decides which tools to use on the sequence data and queues new jobs on the Compute Nodes."),
    (46, "D.2", "Cluster Filesystem", "S6-A", "Context-relevant Research Data", "Transfer", "", "Clinical Result Generation App", "C3-A", "Cluster Filesystem sends the context-relevant research data to the Clinical Result Generation App to create a final clinical report"),
    (47, "D.2", "Bioinformaticist", "C6-A", "Final Clinical Report", "Transfer", "", "Clinical Result Generation App", "C3-A", "Bioinformaticist pulls the final clinical report from the Clinical Result Generation App"),
    (48, "D.2", "Genetic Physician", "C5-A", "Context-relevant Research Data", "Transfer", "Disclosure", "External EMR", "C11-CT", "Genetic Physician logs the professional recommendations and clinical next steps in the External EMR"),
    (49, "D.2", "Genetic Physician", "C5-A", "Context-relevant Research Data", "Transfer", "Disclosure", "Internal EMR", "C10-A", "Genetic Physician logs the professional recommendations and clinical next steps in the Internal EMR"),
    (50, "DD.2.1", "Bioinformaticist", "C6-A", "Sequence Data", "Retention", "", "Cluster Filesystem", "S6-A", "Bioinformaticist reviews the sequence data and ensures there were no undetected sequencing issues."),
    (51, "DD.3.1", "Bioinformaticist", "C6-A", "Tool Selection and Job Queue", "Generation", "Transfer", "Compute Nodes", "S5-A", "Bioinformaticist decides which tools to use on the sequence data and queues new jobs on the Compute Nodes."),
    (52, "DD.3.4", "Physical Sample Management Technician", "S7-PH", "Physical Sample", "Transfer", "", "Physical Sample Storage", "S11-PH", "Retrieve the remainder of the physical sample once contextual retention requirements have been met"),
    (53, "DD.3.4", "Physical Sample Management Technician", "S7-PH", "Physical Sample", "Disposal", "", "Sample Disposal Item", "S12-PH", "Dispose of the remainder of the physical sample once contextual retention requirements have been met"),
    (54, "DD.3.4", "Physical Sample Management Technician", "S7-PH", "Physical Sample Remnants", "Disposal", "", "Used Flow Cell", "S3.2-PH", "Flow cells used during the sequencing process should be cleaned according to best practices to eliminate any portion of the physical sample that may remain after a sequencing run to avoid unintentional data leakage/disclosure when the flow cell is reused for another sequencing run."),
    (55, "DD.4.1.2", "Compute Nodes", "S5-A", "Sequence Data, Context-relevant Research Data", "Transformation", "", "Cluster Filesystem", "S6-A", "Operate on the raw sequence data to create context-relevant research data"),
    (56, "DD.4.2", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "NCCoE-trusted Data Recipient", "R3-A", "Make the context-relevant research data available for the NCCoE-trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (57, "DD.4.2", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "Transfer", "NCCoE-Managed Publishing Location", "R5-A", "Make the context-relevant research data available for researchers and trusted interested parties with access to the NCCoE-Managed Publishing Location to retrieve"),
    (58, "DD.4.2", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "", "Externally-Managed Publishing Location", "R6-A", "Make the context-relevant research data available for researchers and interested parties to retrieve from the Externally-Managed Publishing Location"),
    (59, "U.1.1", "NCCoE Researcher", "R1-A", "Physical Sample Request", "Transfer", "", "DNA Store", "R2-RP", "NCCoE Researcher submits the physical sample request to obtain the physical sample from the DNA Store that will be sent to the sequencing lab"),
    (60, "U.1.1", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "NCCoE-trusted Data Recipient", "R3-A", "Make the context-relevant research data available for the NCCoE-trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (61, "U.1.1", "Clinician", "C2-A", "Physical Sample Request", "Transfer", "", "Patient", "C1-A", "Clinician provides patient with the test request form to obtain the physical sample that will be sent to the sequencing lab"),
    (62, "U.1.1", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "Trusted Research Data Recipient", "C7-CR", "Make the context-relevant research data available for the Trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (63, "U.1.1", "NCCoE Researcher", "R1-A", "Physical Sample Request", "Transfer", "", "DNA Store", "R2-RP", "NCCoE Researcher submits the physical sample request to obtain the physical sample from the DNA Store that will be sent to the sequencing lab"),
    (64, "U.1.1", "Clinician", "C2-A", "Physical Sample Request", "Transfer", "", "Patient", "C1-A", "Clinician provides patient with the test request form to obtain the physical sample that will be sent to the sequencing lab"),
    (65, "U.1.1", "Compute Nodes", "S5-A", "Sequence Data, Context-relevant Research Data", "Transformation", "", "Cluster Filesystem", "S6-A", "Operate on the raw sequence data to create context-relevant research data"),
    (66, "U.1.1", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "NCCoE-trusted Data Recipient", "R3-A", "Make the context-relevant research data available for the NCCoE-trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (67, "U.1.1", "Bioinformaticist", "C6-A", "Tool Selection and Job Queue", "Generation", "Transfer", "Compute Nodes", "S5-A", "Bioinformaticist decides which tools to use on the sequence data and queues new jobs on the Compute Nodes."),
    (68, "U.1.1", "Cluster Filesystem", "S6-A", "Context-relevant Research Data", "Transfer", "", "Clinical Result Generation App", "C3-A", "Cluster Filesystem sends the context-relevant research data to the Clinical Result Generation App to create a final clinical report"),
    (69, "U.1.1", "Bioinformaticist", "C6-A", "Final Clinical Report", "Transfer", "", "Clinical Result Generation App", "C3-A", "Bioinformaticist pulls the final clinical report from the Clinical Result Generation App"),
    (70, "U.1.1", "Bioinformaticist", "C6-A", "Final Clinical Report", "Transfer", "", "3rd Party Portal", "C9-A", "Bioinformaticist uploads the final clinical report onto the 3rd Party Portal"),
    (71, "U.1.1", "3rd Party Portal", "C9-A", "Final Clinical Report", "Collection", "", "Genetic Counselor", "C4-A", "Genetic Counselor downloads the final clinical report from the 3rd Party Portal"),
    (72, "U.1.1", "Genetic Counselor", "C4-A", "Context-relevant Research Data", "Disclosure", "", "Clinician", "C2-A", "Genetic Counselor makes the context-relevant clinical data available for the Clinician to retrieve with additional input and analysis"),
    (73, "U.1.1", "Genetic Physician", "C5-A", "Context-relevant Research Data", "Transfer", "Disclosure", "External EMR", "C11-CT", "Genetic Physician logs the professional recommendations and clinical next steps in the External EMR"),
    (74, "U.1.1", "Genetic Physician", "C5-A", "Context-relevant Research Data", "Transfer", "Disclosure", "Internal EMR", "C10-A", "Genetic Physician logs the professional recommendations and clinical next steps in the Internal EMR"),
    (75, "U.1.1", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "Trusted Research Data Recipient", "C7-CR", "Make the context-relevant research data available for the Trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (76, "U.1.1", "NCCoE Researcher", "R1-A", "Digital Sample Data Request", "Transfer", "", "Digital Sample Data Store", "R4-RD", "NCCoE Researcher submits the digital sample request to obtain the digital sample data from the Digital Sample Data Store that will be sent to the sequencing lab"),
    (77, "U.1.1", "NCCoE Researcher", "R1-A", "Digital Sample Data Request", "Transfer", "", "Digital Sample Data Store", "R4-RD", "NCCoE Researcher submits the digital sample request to obtain the digital sample data from the Digital Sample Data Store that will be sent to the sequencing lab"),
    (78, "U.1.1", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "Transfer", "NCCoE-Managed Publishing Location", "R5-A", "Make the context-relevant research data available for researchers and trusted interested parties with access to the NCCoE-Managed Publishing Location to retrieve"),
    (79, "U.1.1", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "", "Externally-Managed Publishing Location", "R6-A", "Make the context-relevant research data available for researchers and interested parties to retrieve from the Externally-Managed Publishing Location"),
    (80, "U.1.2", "NCCoE Researcher", "R1-A", "Physical Sample Request", "Transfer", "", "DNA Store", "R2-RP", "NCCoE Researcher submits the physical sample request to obtain the physical sample from the DNA Store that will be sent to the sequencing lab"),
    (81, "U.1.2", "Clinician", "C2-A", "Physical Sample Request", "Transfer", "", "Patient", "C1-A", "Clinician provides patient with the test request form to obtain the physical sample that will be sent to the sequencing lab"),
    (82, "U.1.2", "NCCoE Researcher", "R1-A", "Digital Sample Data Request", "Transfer", "", "Digital Sample Data Store", "R4-RD", "NCCoE Researcher submits the digital sample request to obtain the digital sample data from the Digital Sample Data Store that will be sent to the sequencing lab"),
    (83, "U.2.1", "Bioinformaticist", "C6-A", "Tool Selection and Job Queue", "Generation", "Transfer", "Compute Nodes", "S5-A", "Bioinformaticist decides which tools to use on the sequence data and queues new jobs on the Compute Nodes."),
    (84, "U.2.2", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "NCCoE-trusted Data Recipient", "R3-A", "Make the context-relevant research data available for the NCCoE-trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (85, "U.2.2", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "Trusted Research Data Recipient", "C7-CR", "Make the context-relevant research data available for the Trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (86, "U.2.2", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "Transfer", "NCCoE-Managed Publishing Location", "R5-A", "Make the context-relevant research data available for researchers and trusted interested parties with access to the NCCoE-Managed Publishing Location to retrieve"),
    (87, "U.2.3", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "NCCoE-trusted Data Recipient", "R3-A", "Make the context-relevant research data available for the NCCoE-trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (88, "U.2.3", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "Trusted Research Data Recipient", "C7-CR", "Make the context-relevant research data available for the Trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (89, "U.2.3", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "Transfer", "NCCoE-Managed Publishing Location", "R5-A", "Make the context-relevant research data available for researchers and trusted interested parties with access to the NCCoE-Managed Publishing Location to retrieve"),
    (90, "U.2.3", "NCCoE-trusted Data Recipient", "R3-A", "Context-relevant Research Data", "Disclosure", "", "Externally-Managed Publishing Location", "R6-A", "Make the context-relevant research data available for researchers and interested parties to retrieve from the Externally-Managed Publishing Location"),
    (91, "Nc.2", "Physical Sample Management Technician", "S7-PH", "Physical Sample", "Transfer", "", "Physical Sample Storage", "S11-PH", "Retrieve the remainder of the physical sample once contextual retention requirements have been met"),
    (92, "Nc.2", "Physical Sample Management Technician", "S7-PH", "Physical Sample", "Disposal", "", "Sample Disposal Item", "S12-PH", "Dispose of the remainder of the physical sample once contextual retention requirements have been met"),
    (93, "Nc.2", "Physical Sample Management Technician", "S7-PH", "Physical Sample Remnants", "Disposal", "", "Used Flow Cell", "S3.2-PH", "Flow cells used during the sequencing process should be cleaned according to best practices to eliminate any portion of the physical sample that may remain after a sequencing run to avoid unintentional data leakage/disclosure when the flow cell is reused for another sequencing run."),
    (94, "Nc.2", "Bioinformaticist", "C6-A", "Sequence Data", "Retention", "", "Cluster Filesystem", "S6-A", "Bioinformaticist reviews the sequence data and ensures there were no undetected sequencing issues."),
    (95, "Nc.2", "Data Delivery DMZ", "S13-A", "Context-relevant Research Data", "Disclosure", "", "Trusted Research Data Recipient", "C7-CR", "Make the context-relevant research data available for the Trusted Data Recipient to retrieve from the Data Delivery DMZ"),
    (96, "Nc.4", "Physical Sample Management Technician", "S7-PH", "Physical Sample", "Disposal", "", "Sample Disposal Item", "S12-PH", "Dispose of the remainder of the physical sample once contextual retention requirements have been met"),
    (97, "Nc.4", "Device Decommissioning Specialist", "S9-PH", "Digital Data", "Disposal", "", "Privacy-Relevant Wet Lab Devices", "S3.1-PH", "Devices used to process genomic data should be decommissioned according to privacy best practices to avoid unintentional data leakage/disclosure when the device(s) are resold"),
    (98, "Nc.4", "Device Acquisition Specialist", "S10-PH", "Digital Data", "Collection", "", "Privacy-Relevant Wet Lab Devices", "S3.1-PH", "Devices used to process genomic data should be acquired from the manufacturer or should be acquired after being refurbished according to privacy best practices to avoid unintentional data leakage/disclosure when the device(s) are purchased"),
    (99, "Nc.4", "Physical Sample Management Technician", "S7-PH", "Physical Sample Remnants", "Disposal", "", "Used Flow Cell", "S3.2-PH", "Flow cells used during the sequencing process should be cleaned according to best practices to eliminate any portion of the physical sample that may remain after a sequencing run to avoid unintentional data leakage/disclosure when the flow cell is reused for another sequencing run."),
]

# Element inventory (id -> (name, dfd_type, role)), from Appendix E Figures 4 (clinical), 5
# (research physical), 6 (research digital), 7 (shared), cross-checked against Figure 11's own
# Source/Destination element labels.
#
# `role` is NOT part of NIST's own diagram -- it's an interpretive annotation we add on top,
# distinguishing ExternalEntity elements who are internal staff performing part of the org's
# workflow (role="internal_staff") from elements genuinely outside the organization
# (role="external_party"). NIST's SP 1800-43C follows the broader PANOPTIC convention, which
# types every human actor as ExternalEntity regardless of employment; strict LINDDUN Pro Table
# 4.1 semantics define ExternalEntity as "outside the system" specifically so that a Process can
# mediate any DataStore/EE exchange (mapping_table.json's `_meta` note). `role` drives
# `effective_type()` in retrieval/interaction_context.py, used only for mapping-table lookups --
# `type` below is left untouched as a faithful transcription of NIST's figure. See
# WEEK4_REPORT.md for the rationale and quantified impact (recovers 53/80 previously-unreachable
# genomic gold threats); flagged for advisor sign-off before treating the resulting reachability
# numbers as final.
ELEMENTS = {
    # Shared pipeline (Figure 7)
    "S1-PH": ("Receiving Clerk", "ExternalEntity", "internal_staff"),
    "S2-A": ("Lab Technician", "ExternalEntity", "internal_staff"),
    "S3-PH": ("Wet Lab", "Process", None),
    "S3.1-PH": ("Privacy-Relevant Wet Lab Devices", "DataStore", None),
    "S3.2-PH": ("Used Flow Cell", "DataStore", None),
    "S4-PH": ("LIMS", "DataStore", None),
    "S5-A": ("Compute Nodes", "Process", None),
    "S6-A": ("Cluster Filesystem", "DataStore", None),
    "S7-PH": ("Physical Sample Management Technician", "ExternalEntity", "internal_staff"),
    "S8-A": ("Digital Data Management Technician", "ExternalEntity", "internal_staff"),
    "S9-PH": ("Device Decommissioning Specialist", "ExternalEntity", "internal_staff"),
    "S10-PH": ("Device Acquisition Specialist", "ExternalEntity", "internal_staff"),
    "S11-PH": ("Physical Sample Storage", "DataStore", None),
    "S12-PH": ("Sample Disposal Item", "DataStore", None),
    "S13-A": ("Data Delivery DMZ", "DataStore", None),
    # Clinical pipeline (Figure 4)
    "C1-A": ("Patient", "ExternalEntity", "external_party"),
    "C2-A": ("Clinician", "ExternalEntity", "internal_staff"),
    "C3-A": ("Clinical Result Generation App", "Process", None),
    "C4-A": ("Genetic Counselor", "ExternalEntity", "internal_staff"),
    "C5-A": ("Genetic Physician", "ExternalEntity", "internal_staff"),
    "C6-A": ("Bioinformaticist", "ExternalEntity", "internal_staff"),
    "C7-CR": ("Trusted Research Data Recipient", "ExternalEntity", "external_party"),
    "C8-A": ("3rd Party Previous Enrollment Entity", "ExternalEntity", "external_party"),
    "C9-A": ("3rd Party Portal", "DataStore", None),
    "C10-A": ("Internal EMR", "DataStore", None),
    "C11-CT": ("External EMR", "DataStore", None),
    # Research pipeline, physical + digital (Figures 5, 6)
    "R1-A": ("NCCoE Researcher", "ExternalEntity", "internal_staff"),
    "R2-RP": ("DNA Store", "DataStore", None),
    "R3-A": ("NCCoE-trusted Data Recipient", "ExternalEntity", "external_party"),
    "R4-RD": ("Digital Sample Data Store", "DataStore", None),
    "R5-A": ("NCCoE-Managed Publishing Location", "DataStore", None),
    "R6-A": ("Externally-Managed Publishing Location", "DataStore", None),
}


def build_raw_json() -> list[dict]:
    return [
        {
            "row": r[0], "nist_node": r[1],
            "source_name": r[2], "source_id": r[3],
            "dataflow_type": r[4], "data_action_1": r[5], "data_action_2": r[6],
            "destination_name": r[7], "destination_id": r[8],
            "context": r[9],
        }
        for r in ROWS
    ]


def _normalize_node(node: str) -> str:
    """DD vs Dd is a typographic difference between Figure 11 (all-caps 'DD' abbreviation) and
    the gold standard's stored nist_node (mixed-case 'Dd'); not a real mismatch."""
    return node[:2].capitalize() + node[2:] if node[:2].upper() == "DD" else node


# Figure 11's "No." column mostly equals gold's `id` 1:1 (verified: 88/99 rows match by node,
# and every one of the ~90 non-clustered rows also matches gold's `description` text on spot
# checks against Appendix-Figure20.png, which shares Figure 11's row order). The exception is a
# locally-repeated "sample/data not de-identified" cluster (rows/ids ~18-27), where Figure 11 (an
# exhaustive per-dataflow-segment walk) enumerates MORE granular instances than gold's final,
# curated, cross-validated catalog (built from Appendix G Figures 20/24, and per WEEK2_REPORT.md
# already hand-corrected once in this exact region: "rows #23/#24 had swapped feasibility; #27's
# description was recovered from the source"). Resolved here by exact `description` text matching
# against gold (not row position); ambiguous/unresolved ids are flagged rather than guessed.
GOLD_ID_ROW_OVERRIDE = {
    18: 19,   # gold desc "before being received" -- matches row19 (Researcher->Receiving Clerk)
    19: 21,   # gold desc "before being received" -- matches row21 (Clinician->Receiving Clerk)
    20: None,  # unresolved: no 3rd distinct Figure 11 row for this description among candidates
    21: 22,   # gold desc uniquely matches row22 (Cluster Filesystem->Clinical Result Generation App)
    22: 23,   # gold desc uniquely matches row23 (Genetic Counselor->3rd Party Previous Enrollment)
    23: None,  # unresolved: no Figure 11 row found for "within the data delivery DMZ" (I.1.1)
    24: 25,   # gold desc uniquely matches row25 (Bioinformaticist->Cluster Filesystem, I.1.2)
    25: 26,   # gold desc uniquely matches row26 (Wet Lab->LIMS, "full de-identification difficult")
    26: 27,   # gold desc uniquely matches row27 (Bioinformaticist->Cluster Filesystem, "date of birth")
    27: 27,   # duplicate of gold id26's description/node -- shares row27's location (best effort)
}
LOW_CONFIDENCE_GOLD_IDS = {18, 19, 26, 27}   # assigned, but via ambiguous/duplicate content match
UNRESOLVED_GOLD_IDS = {20, 23}               # no Figure 11 row confidently corresponds


def row_for_gold_id(gold_id: int) -> int | None:
    if gold_id in GOLD_ID_ROW_OVERRIDE:
        return GOLD_ID_ROW_OVERRIDE[gold_id]
    return gold_id  # default: row N == gold id N


def verify_against_existing_gold(raw: list[dict]) -> list[str]:
    """Cross-check: for each gold id's resolved Figure-11 row, the LINDDUN node must match
    gold_standard_threats.json's nist_node for that id (case-normalized for the DD/Dd typographic
    difference)."""
    gold = json.loads((config.KB_DIR / "scenarios/genomic/gold_standard_threats.json").read_text())
    by_row = {r["row"]: r for r in raw}
    mismatches = []
    for t in gold["threats"]:
        gold_id = t["id"]
        row_num = row_for_gold_id(gold_id)
        if row_num is None:
            continue  # intentionally unresolved, not an error
        row = by_row.get(row_num)
        if row is None:
            mismatches.append(f"id {gold_id}: no Figure 11 row {row_num}")
            continue
        if _normalize_node(row["nist_node"]) != _normalize_node(t["nist_node"]):
            mismatches.append(f"id {gold_id} (row {row_num}): nist_node mismatch "
                               f"(gold={t['nist_node']!r} vs figure11={row['nist_node']!r})")
        for eid in (row["source_id"], row["destination_id"]):
            if eid not in ELEMENTS:
                mismatches.append(f"id {gold_id}: element id {eid!r} not in ELEMENTS inventory")
    return mismatches


def merge_into_gold(raw: list[dict]) -> dict:
    """Add dfd_source_id/dfd_destination_id/... fields to gold_standard_threats.json, keeping
    every existing field untouched."""
    path = config.KB_DIR / "scenarios/genomic/gold_standard_threats.json"
    gold = json.loads(path.read_text())
    by_row = {r["row"]: r for r in raw}

    for t in gold["threats"]:
        row_num = row_for_gold_id(t["id"])
        row = by_row.get(row_num) if row_num is not None else None
        if row is None:
            t["dfd_source_id"] = None
            t["dfd_destination_id"] = None
            t["dfd_dataflow_type"] = None
            t["dfd_context"] = None
            t["dfd_location_confidence"] = "unresolved"
        else:
            t["dfd_source_id"] = row["source_id"]
            t["dfd_destination_id"] = row["destination_id"]
            t["dfd_dataflow_type"] = row["dataflow_type"]
            t["dfd_context"] = row["context"]
            t["dfd_location_confidence"] = ("low" if t["id"] in LOW_CONFIDENCE_GOLD_IDS else "high")

    dfd_location_note = \
        " + Week 3: dfd_source_id/dfd_destination_id added from Appendix F Figure 11 " \
        "('Task 4: Assess System Design'), cross-checked against nist_node; " \
        f"{len(UNRESOLVED_GOLD_IDS)} ids ({sorted(UNRESOLVED_GOLD_IDS)}) left unresolved " \
        f"(dfd_location_confidence=unresolved), {len(LOW_CONFIDENCE_GOLD_IDS)} ids " \
        f"({sorted(LOW_CONFIDENCE_GOLD_IDS)}) resolved via ambiguous/duplicate content-match " \
        "(dfd_location_confidence=low) -- see scripts/build_genomic_dfd.py."
    base_revision = gold["_meta"].get("revision", "").split(dfd_location_note)[0]
    gold["_meta"]["revision"] = base_revision + dfd_location_note
    return gold


def build_dfd_json(raw: list[dict]) -> dict:
    elements = [
        {"id": eid, "name": name, "type": etype, **({"role": role} if role else {})}
        for eid, (name, etype, role) in ELEMENTS.items()
    ]
    flows = []
    seen = set()
    for row in raw:
        key = (row["source_id"], row["destination_id"])
        if key in seen:
            continue
        seen.add(key)
        flows.append({
            "id": f"GF{len(flows) + 1}",
            "source": row["source_id"],
            "destination": row["destination_id"],
            "description": f"{row['dataflow_type']}: {row['context']}",
        })
    return {
        "_meta": {
            "scenario": "Genomic Sequencing (NIST SP 1800-43C) -- complete example",
            "source": "Appendix E Figures 4-7 (elements) + Appendix F Figure 11 'Task 4: Assess "
                       "System Design' (flows), references/nist-sp-1800-43c/appendix/media/. "
                       "Figure 11 was vision-transcribed row-by-row and cross-checked against "
                       "gold_standard_threats.json's existing nist_node per row (see "
                       "scripts/build_genomic_dfd.py:verify_against_existing_gold).",
            "purpose": "Structured DFD (elements + flows) covering the full complete example "
                       "(shared + clinical + research pipelines), superseding the Week 3 version "
                       "that only covered the 9-flow shared-pipeline subset.",
            "flow_count": len(flows),
            "element_count": len(elements),
            "known_gap": "mapping_table.json (LINDDUN Pro Table 4.1, sourced from the official "
                         "tutorial) only covers 5 interaction pairs, all routed through a Process "
                         "(Process<->Process/DataStore/ExternalEntity). NIST's diagrams routinely "
                         "show entities and stores talking DIRECTLY to each other with no Process "
                         "in between, which the tutorial's table doesn't model at all. Of the 97 "
                         "gold threats with a resolved DFD location, only 17 sit on one of the 5 "
                         "valid pairs by raw `type` alone; the other 80 break down as "
                         "ExternalEntity->DataStore (39), ExternalEntity->ExternalEntity (23), "
                         "DataStore->ExternalEntity (17), and DataStore->DataStore (1). Week 4: "
                         "each ExternalEntity element now also carries a `role` "
                         "(internal_staff/external_party) -- an interpretive annotation, not part "
                         "of NIST's own diagram -- and `effective_type()` "
                         "(retrieval/interaction_context.py) treats internal_staff EEs (lab "
                         "technicians, clinicians, genetic counselors/physicians, "
                         "bioinformaticists, researchers) as Process for mapping-table lookups "
                         "only, since they perform data transformation as part of the org's "
                         "workflow rather than sitting genuinely outside it (only Patient, "
                         "3rd Party Previous Enrollment Entity, and the two Trusted/-trusted Data "
                         "Recipient roles keep role=external_party). This recovers 53 of the 80 "
                         "previously-unreachable threats (17/99 -> 70/99 reachable); the remaining "
                         "27 are all genuinely cross-organization exchanges (Data Delivery DMZ <-> "
                         "external data recipients/publishing locations, 3rd Party Previous "
                         "Enrollment Entity <-> Patient) that stay unreachable under LINDDUN Pro's "
                         "own Process-mediation rule. `type` is left untouched as a faithful "
                         "transcription of NIST's figure -- this is a per-project reinterpretation "
                         "layered on top, flagged for advisor sign-off before the 70/99 number is "
                         "treated as final. See WEEK3_REPORT.md (original finding) and "
                         "WEEK4_REPORT.md (this change).",
        },
        "elements": elements,
        "flows": flows,
    }


def main():
    raw = build_raw_json()
    assert len(raw) == 99, f"expected 99 rows, got {len(raw)}"

    raw_path = config.ROOT / "scripts" / "data" / "genomic_figure11_raw.json"
    raw_path.write_text(json.dumps(raw, indent=2))
    print(f"Wrote {raw_path} ({len(raw)} rows)")

    mismatches = verify_against_existing_gold(raw)
    if mismatches:
        print(f"\n{len(mismatches)} MISMATCHES:")
        for m in mismatches:
            print(f"  {m}")
    else:
        print("All 99 rows verified against existing gold_standard_threats.json nist_node values.")

    dfd = build_dfd_json(raw)
    dfd_path = config.KB_DIR / "scenarios" / "genomic" / "dfd.json"
    dfd_path.write_text(json.dumps(dfd, indent=2))
    print(f"Wrote {dfd_path} ({dfd['_meta']['element_count']} elements, {dfd['_meta']['flow_count']} unique flows)")

    gold = merge_into_gold(raw)
    gold_path = config.KB_DIR / "scenarios/genomic/gold_standard_threats.json"
    gold_path.write_text(json.dumps(gold, indent=2))
    n_high = sum(1 for t in gold["threats"] if t.get("dfd_location_confidence") == "high")
    n_low = sum(1 for t in gold["threats"] if t.get("dfd_location_confidence") == "low")
    n_unresolved = sum(1 for t in gold["threats"] if t.get("dfd_location_confidence") == "unresolved")
    print(f"Wrote {gold_path}: dfd_source_id/dfd_destination_id added "
          f"({n_high} high-confidence, {n_low} low-confidence, {n_unresolved} unresolved)")

    return raw, mismatches


if __name__ == "__main__":
    main()
