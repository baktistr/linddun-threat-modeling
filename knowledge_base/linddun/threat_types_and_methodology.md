# LINDDUN Privacy Threat Types

> Source: LINDDUN PRO Privacy Threat Modeling Tutorial v0.1 (April 2023), DistriNet, KU Leuven.
> https://downloads.linddun.org/tutorials/pro/v0/tutorial.pdf

LINDDUN is an acronym for seven privacy threat types: **L**inking, **I**dentifying, **N**on-repudiation, **D**etecting, **D**ata Disclosure, **U**nawareness, **N**on-compliance.

## L — Linking

Linking refers to any act of associating different data elements to each other (including meta-data) in such a way that it leads to undesirable privacy implications — i.e. when the combination of related data items reveals additional information about a data subject or group. By matching data items based on recurring attributes, a user profile (or group profile) can be built. Linking typically relies on a recurring identifier, a combination of attributes (quasi-identifiers), or a profile that allows data to be singled out. Many systems require linking to meet functional requirements (e.g. session tracking); Linking analysis looks at situations where this ability to tie things together is problematic or undesirable.

## I — Identifying

Personal data is by definition related to a data subject. Identifying threats express situations in which the identity of the data subject can be learned through leaks, can be deduced, or inferred when this is unwanted and to be prevented.

## Nr — Non-repudiation

Non-repudiation threats represent outcomes in which an individual is unable to deny certain claims about their involvement in the system, or any claim pertaining to themselves, as a consequence of data collected/shared or an action taken. Non-repudiation threats involve evidence with two dimensions: (i) the strength of that evidence with regard to the claim, and (ii) the strength of the attributability to an individual. Note: in privacy, non-repudiation is often a *threat* (the inability to deny), the opposite of its role as a security goal.

## D — Detecting

Assessment of Detecting threats involves becoming aware of data-subject involvement, membership, or participation in the system by observing the existence of relevant information, through (i) observed communication, (ii) observed application side-effects (e.g. temporary files in the file system), or (iii) system responses that may give away the existence of these elements (via deliberate probing or accidental leakage). Detecting threats do NOT require access to the data itself — observing existence, side-effects, or communication flows can be enough to deduce relevant information.

## Dd — Data Disclosure

A data disclosure is the transfer of personal data across a boundary — collection by the system or transfer to a known or unknown third party. The minimality principle is key: only collect, process, store, and share strictly required personal data. Data Disclosure threats represent cases in which either the explicit (intended/designed) or the implicit (unintended/consequential) disclosure of personal data is considered avoidable. Explicit disclosures happen intentionally and by design; implicit disclosures are indirect (through meta-data or derived from other disclosed data).

## U — Unawareness and Unintervenability

Unawareness focuses on the lack of support offered to involved or affected individuals. It assesses privacy harm caused by insufficiently informing, involving, or empowering the data subject. Three potential lacks of system support: (i) not properly informing data subjects about data collection and processing (lack of transparency), (ii) insufficiently making users aware of potential privacy harm or impact (lack of user feedback), and (iii) not providing data subjects with controls or means to influence how their data is handled (lack of intervenability).

## Nc — Non-compliance

Non-compliance is the lack of adherence to legislation, regulation, standards, and best practices, leading to incomplete management of risk. As a LINDDUN threat type it focuses on the intersection between privacy threats identified in the other types and the link to broader risk notions (legal risk, cybersecurity risk, organizational risk). Documenting a Non-compliance threat involves evaluating compliance problems that derive from the applicable Linking, Identifying, Non-repudiation, Data Disclosure, and Unawareness threats.

---

# Interaction-Based Threat Elicitation

LINDDUN Pro uses **interaction-based** elicitation. You iterate over every interaction (every combination of source — dataflow — destination) in the DFD. For each data flow, consider whether there is a privacy threat at the **source**, at the **data flow** itself, or at the **destination**.

## Position interpretations

**Source (S).** The threat arises at the element that shares or communicates data, where the sharing itself can cause a privacy threat. This is an action-effect threat — the source was triggered to initiate communication (e.g. a browser retransmitting cookies or linkable identifiers to each recipient).

**Data Flow (fl).** The threat arises at the data flow, i.e. when data (both meta-data and content) is in transit. These threats are data-centric (e.g. meta-data about source and destination used to link flows, or to identify the parties involved).

**Destination (D).** The threat arises at the element that receives the data, where the data can be processed or stored in a way that causes a privacy threat (e.g. insecure storage or insufficient minimization upon storing). These threats are action-based — the receipt of data and what the recipient does with it triggers the threat.

## How to use the mapping table

For every interaction, look it up in the mapping table to check which LINDDUN threat types you need to consider at which positions. Two iteration strategies:

- **Starting from the threat types:** pick a threat type (e.g. Linking), walk all interactions, then move to the next type. Keeps you focused on one tree at a time; requires multiple passes over the model.
- **Starting from the model:** pick an interaction, review all seven threat types for it, then move to the next interaction. Single pass over the model; requires switching between threat trees frequently.

## Valid vs invalid interactions

The mapping table covers these valid interactions: Process→Process, Process→DataStore, Process→ExternalEntity, DataStore→Process, ExternalEntity→Process. Invalid combinations (DataStore-flow-DataStore, ExternalEntity-flow-ExternalEntity) are excluded — data stores don't exchange data without a process, and external entities don't have modeled flows between each other.
