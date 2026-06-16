# Privacy Regulation Reference for LINDDUN Threat Mapping

> Provisions most relevant to privacy threat modeling, summarized for retrieval. Each entry cites the official source. Summaries are paraphrased; consult the official text for legal use.

---

## COPPA — Children's Online Privacy Protection Rule (16 CFR Part 312)

Source: eCFR Title 16, Part 312. https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312

### § 312.3 — General requirements
Operators of websites/online services directed to children under 13 (or with actual knowledge they collect data from children under 13) must: provide notice of data practices; obtain verifiable parental consent before collection/use/disclosure; give parents a means to review and refuse further use of collected data; not condition participation on excessive data collection; and maintain reasonable security.

### § 312.4 — Notice
Operators must post a clear privacy notice describing what information is collected from children, how it is used, and disclosure practices. Direct notice to parents is required before collection.
**LINDDUN relevance:** Unawareness (U) — lack of transparency about data collection. A platform that does not notify children/parents of tracking maps here.

### § 312.5 — Verifiable parental consent
Operators must obtain verifiable parental consent before any collection, use, or disclosure of a child's personal information. The consent method must be reasonably calculated, in light of available technology, to ensure the person giving consent is the child's parent. Non-exhaustive approved methods include: signed consent form, credit/debit card transaction with notification, toll-free number staffed by trained personnel, video conference, government-ID check against databases, and knowledge-based authentication. Parents must be able to consent to collection/use without consenting to third-party disclosure.
**LINDDUN relevance:** Non-compliance (Nc). A weak mechanism (e.g. a self-chosen six-digit code with no identity verification) does not meet § 312.5.

### § 312.6 — Right to review and delete
Operators must provide parents a reasonable means to review the personal information collected from their child and to refuse further use/maintenance (deletion).
**LINDDUN relevance:** Unawareness/unintervenability (U) — lack of controls. If deletion is claimed but not technically enforced, also Non-compliance (Nc).

### § 312.7 — Prohibition against conditioning participation (data minimization)
An operator may not condition a child's participation in a game, prize offering, or other activity on the child disclosing more personal information than is reasonably necessary to participate. The FTC treats this as an outright prohibition on collecting more than reasonably necessary — even with consent.
**LINDDUN relevance:** Data Disclosure (Dd.1, Dd.2) — unnecessary data types and excessive volume. Collecting exact DOB, gender, or government ID from children when an age range would suffice maps here.

### § 312.8 — Confidentiality, security, and integrity
Operators must establish and maintain reasonable procedures to protect the confidentiality, security, and integrity of children's personal information, and take reasonable steps to release data only to parties able to maintain its security.
**LINDDUN relevance:** Data Disclosure (Dd.4) and Non-compliance (Nc) — insecure storage (e.g. unencrypted government ID images, unauthenticated databases) violates this.

### § 312.10 — Data retention and deletion
Personal information may be retained only as long as reasonably necessary to fulfill the purpose for which it was collected, then must be deleted using reasonable measures to prevent unauthorized access.
**LINDDUN relevance:** Data Disclosure (Dd.3.4) — duration/retention. Indefinite retention of behavioral logs maps here.

### Penalty note
COPPA civil penalties are inflation-adjusted; as of the 2025 adjustment the maximum is $53,088 per violation (FTC). High-volume children's services can accumulate substantial exposure.

---

## GDPR — General Data Protection Regulation (EU 2016/679)

Source: Regulation (EU) 2016/679. https://eur-lex.europa.eu/eli/reg/2016/679/oj

### Art. 5(1)(c) — Data minimisation
Personal data must be adequate, relevant, and limited to what is necessary for the purposes for which it is processed.
**LINDDUN relevance:** Data Disclosure (Dd.1, Dd.2).

### Art. 5(1)(e) — Storage limitation
Personal data must be kept in identifiable form no longer than necessary for the processing purposes.
**LINDDUN relevance:** Data Disclosure (Dd.3.4 retention).

### Art. 5(1)(f) — Integrity and confidentiality
Personal data must be processed with appropriate security, including protection against unauthorised processing and accidental loss, using technical/organisational measures.
**LINDDUN relevance:** Data Disclosure (Dd.4), Detecting (D).

### Art. 6 — Lawfulness of processing
Processing requires a lawful basis (consent, contract, legal obligation, vital interests, public task, or legitimate interests).
**LINDDUN relevance:** Non-compliance (Nc).

### Art. 9 — Special categories
Processing of special-category data (health, biometric, etc.) is prohibited absent specific conditions.
**LINDDUN relevance:** Data Disclosure (Dd.1.1 sensitivity).

### Art. 12–14 — Transparency and information
Data subjects must be informed, in clear language, about what data is collected, why, by whom, and their rights.
**LINDDUN relevance:** Unawareness (U) — transparency.

### Art. 15–22 — Data subject rights
Rights of access, rectification, erasure ("right to be forgotten", Art. 17), restriction, portability, and objection.
**LINDDUN relevance:** Unawareness/unintervenability (U) — controls.

### Art. 25 — Data protection by design and by default
Controllers must implement technical/organisational measures (e.g. pseudonymisation) to embed data-protection principles and minimise data by default.
**LINDDUN relevance:** cross-cutting — Linking (L, via pseudonymisation), Data Disclosure (Dd).

### Art. 32 — Security of processing
Appropriate security measures including, where appropriate, pseudonymisation and encryption.
**LINDDUN relevance:** Data Disclosure (Dd.4), Detecting (D).

---

## CCPA / CPRA — California Consumer Privacy Act (as amended)

Source: California Civil Code §§ 1798.100 et seq. https://oag.ca.gov/privacy/ccpa

### § 1798.100 — Collection and data minimisation
A business's collection, use, retention, and sharing of personal information must be reasonably necessary and proportionate to the purposes for which it was collected.
**LINDDUN relevance:** Data Disclosure (Dd.1, Dd.2).

### § 1798.105 — Right to delete
Consumers may request deletion of personal information collected from them, subject to exceptions.
**LINDDUN relevance:** Unawareness/unintervenability (U).

### § 1798.110 / .115 — Right to know
Consumers may request the categories and specific pieces of personal information collected, sources, purposes, and third parties with whom it is shared.
**LINDDUN relevance:** Unawareness (U) — transparency; Data Disclosure (Dd.4) — involved parties.

### § 1798.120 — Right to opt out of sale/sharing
Consumers may direct a business not to sell or share their personal information. Special protections apply to consumers under 16 (opt-in required).
**LINDDUN relevance:** Data Disclosure (Dd.4 involved parties), Non-compliance (Nc).

### § 1798.140 — Sensitive personal information (CPRA)
Defines sensitive personal information (government IDs, precise geolocation, etc.) with additional use-limitation rights.
**LINDDUN relevance:** Data Disclosure (Dd.1.1 sensitivity).
