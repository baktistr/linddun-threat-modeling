# Telehealth Remote Monitoring (demo scenario)

A remote patient-monitoring system: a patient's wearable feeds vitals into a monitoring
platform backed by an EHR database; clinical staff (nurse, attending physician) interact with
that data directly; a genetic testing lab courier delivers sequencing results; a clinical
decision-support app screens for risk flags; and an external insurance auditor periodically
pulls records for billing review.

This is a hand-authored dummy scenario, deliberately structured like the genomic (NIST)
scenario's internal/external pattern but at demo scale. It has no `gold_standard_threats.json`
-- it's for showing (a) grounded generation with the new HIPAA/GINA/Common Rule citations, and
(b) the `effective_type` reclassification live, not for precision/recall scoring.

## Actors and their `role` (Week 4 annotation, not part of any "real" source diagram)
- **Patient** (`external_party`) -- genuinely outside the organization.
- **Nurse**, **Attending Physician**, **Genetic Testing Lab Courier** (`internal_staff`) --
  organizational staff performing part of the care/testing workflow, typed `ExternalEntity` like
  every human actor in this DFD style, but treated as `Process` for mapping-table reachability
  via `retrieval/interaction_context.py`'s `effective_type()`.
- **External Insurance Auditor** (`external_party`) -- a genuinely external third party; the one
  flow into it (DF9) stays unreachable under LINDDUN Pro's Process-mediation rule regardless of
  the `effective_type` fix, same as genomic's remaining 27 stuck threats.

## Demo script
1. Run `python cli.py generate --scenario telehealth_demo` as-is: DF3, DF4, DF5 generate threats
   (reachable via `effective_type`); DF9 is skipped (genuinely external, stays unreachable).
2. To show the *before* state, temporarily delete the `"role": "internal_staff"` fields from
   `dfd.json` and rerun -- DF3/DF4/DF5 now get skipped too, reproducing the original 17/99-style
   ceiling at this demo's scale.
3. Regulatory citations on `DF2`/`DF3`/`DF8` (EHR access) and `DF5`/`DF6` (genetic results) are
   the ones most likely to cite the newly-added HIPAA/GINA/Common Rule provisions in
   `knowledge_base/regulations/regulations.md`.
