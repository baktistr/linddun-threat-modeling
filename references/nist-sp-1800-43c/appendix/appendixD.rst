Appendix D: Methodology Overview
================================

This appendix summarizes the methodology presented in the body of the paper for easy reference. Note that while this methodology is presented sequentially, it is often iterative in practice.

*Question 1: What are we working on?*

1. Define the target of the threat modeling by identifying system boundaries. Note that the target may constitute a system of systems. Also identify the relevant Mission Objectives from the NIST *Genomic Data Profile.*

2. Identify the different use cases.

3. Complete PRAM Worksheet 1 to capture organizational objectives and privacy governance.

4. Document system context.

   a. In adapted PRAM Worksheet 2, complete System Privacy Capabilities related to the NIST Privacy Engineering Objectives (PEOs) for each use case. Include the security objectives if cybersecurity threat modeling is not being performed separately.

   b. Create a PANOPTIC Contextual Domains mapping for the system using the PANOPTIC mapping template.

   c. Complete Contextual Factors in Worksheet 2, leveraging responses in Worksheet 1 and the PANOPTIC Contextual Domains mapping.

5. Create dataflow diagrams (DFDs) for the different use cases (including a shared DFD if there is a high degree of commonality across the pipelines of the different use cases).

   a. Associate each component with a managing entity and each discrete dataflow with descriptive data actions.

   b. Organize the diagrams using PRAM data actions as swim lanes: collection, generation/transformation, retention/logging, disclosure/transfer, disposal.

   c. Create indices of components and any distinguishing sub-cases and label DFD sources and destinations accordingly.

*Question 2: What could go wrong?*

6.  Using the Assess System Design sheet in Worksheet 2, document each DFD segment --- source, flow, destination --- including data actions and relevant context. If preferred, use a separate sheet for each DFD.

7.  Identify potential LINDDUN threats for each dataflow segment entry using the LINDDUN threat trees. Ensure that all identified threats are defined from the perspective of the data subject. Create duplicate entries to accommodate multiple threats.

8.  Combine the LINDDUN analyses of the individual DFDs (if applicable) and group the entries by sorting on the LINDDUN threat designation.

9.  Create a PANOPTIC Privacy Activities mapping for each use case using the PANOPTIC mapping template. In doing so, identify relevant or potentially relevant threat actions that could form a privacy attack on one or more data subjects and define scenarios for specific sets of threat actions that could constitute attacks.

10. Validate all threats:

    a. Leveraging the PANOPTIC – LINDDUN mapping, confirm that there is at least one entry in the combined LINDDUN analysis table related to each PANOPTIC attack. Eliminate from further consideration attacks without a corresponding LINDDUN threat. Eliminate from further consideration LINDDUN threats unrelated to any PANOPTIC attack.

    b. For each remaining threat, confirm that it threatens one or more PEO. Eliminate from further consideration any threats that would not undermine at least one PEO.

*Question 3: What are we going to do about it?*

11. Prioritize threats

    a. Assign categorical values for feasibility and difficulty to each validated threat.

    b. Adjust the attack feasibility-difficulty matrix values and/or LINDDUN threat weights if necessary.

    c. Rank order the threats by sorting on computed prioritization values (multiplying the feasibility-difficulty value by the LINDDUN threat weight). List threats from highest to lowest value.

12. Determine threat responses --- eliminate, disrupt, transfer, or accept --- starting from the highest priority threat and moving down the list.

13. If opting to disrupt a threat:

    a. Identify one or more critical threat actions of the PANOPTIC attack.

    b. Find the NIST Privacy Framework Subcategories associated with each critical threat action. Rank order the Subcategories based on the priorities associated with the selected Mission Objectives in the *Genomic Data Profile.*

    c. In order of Subcategory priority, use the NIST PF – SP 800-53r5 crosswalk to review controls that are relevant for each Subcategory. Select those controls that most directly address the threat action(s).

    d. Note that selected controls are likely to disrupt other, similar attacks.

