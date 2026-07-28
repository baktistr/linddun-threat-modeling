#!/usr/bin/env python3
"""Generate the Family Location Sharing App gold-standard threat catalog as structured JSON.

Provenance (important, unlike KidsTube/Genomic): this scenario and its gold standard are
hand-authored for this repo (Week 8) from a short product description supplied in-session, not
transcribed from an external human-authored homework assignment (KidsTube) or an authoritative
third-party report (Genomic/NIST). Every threat below was drafted with LINDDUN Pro's actual
threat trees open (knowledge_base/linddun/threat_trees.json) and every tree_node is a real,
existing node id, but this catalog has not been independently reviewed the way KidsTube's HW2
source or Genomic's NIST publication have been. Treat any evaluation numbers derived from it as a
weaker evidentiary signal than the other two scenarios until a human expert reviews it -- flag
this explicitly in any paper that cites results from this scenario.

Design choices mirroring the existing scenarios:
- All DFD flows are Process-mediated (see dfd.json's _meta), so there is no genomic-style
  mapping-table gap -- every flow is structurally reachable.
- Matching uses dfd_source_id/dfd_destination_id (like Genomic), not an embedded [DFn] tag in an
  "interaction" string (that convention is KidsTube-specific -- see eval/match.py's
  flow_anchored = scenario == "kidstube" check).
- Per the scenario brief, some threats deliberately mirror KidsTube's categories (insecure
  credential storage, indefinite retention) since both are child-data apps; others are specific
  to continuous location tracking (excessive collection frequency/granularity, third-party
  ad/analytics sharing without the child's own consent, incomplete retention disclosure).
"""
import json
from collections import Counter
from pathlib import Path

# Each threat is a dict. Required keys: id, dfd_source_id, dfd_destination_id, originator_id,
# tree_node, threat_type, title, description, assumptions, severity, likelihood.
THREATS = [
    {"id": 1, "dfd_source_id": "EE2", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "L.1.1", "threat_type": "L",
     "title": "Persistent device identifier links all location pings to the same child indefinitely",
     "description": "A persistent device or session identifier attached to every GPS ping lets anyone with access to the raw feed link the child's entire movement history together, even across app reinstalls or account renames.",
     "assumptions": "The location-ingestion identifier is not rotated or pseudonymized per session.",
     "severity": "Med", "likelihood": "High"},

    {"id": 2, "dfd_source_id": "EE2", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "Dd.2.2", "threat_type": "Dd",
     "title": "High-frequency continuous GPS pings collect far more granular data than a geofence check needs",
     "description": "The child's device transmits precise coordinates continuously (e.g. every few seconds), producing a detailed movement diary, when the stated purpose -- arrival/departure alerts -- only requires knowing zone-boundary crossings.",
     "assumptions": "Ping frequency is fixed and continuous rather than adaptive to proximity to a zone boundary.",
     "severity": "Med", "likelihood": "High"},

    {"id": 3, "dfd_source_id": "P1", "dfd_destination_id": "P2", "originator_id": "P2",
     "tree_node": "L.2.2.1", "threat_type": "L",
     "title": "Aggregated location pings enable detailed behavioral profiling of the child's routine",
     "description": "Combining the child's location pings over time reveals a detailed behavioral profile -- school schedule, extracurricular activities, friends' addresses -- well beyond the geofencing engine's immediate operational need.",
     "assumptions": "Historical pings are retained and accessible to the profiling/engine layer, not just the current ping.",
     "severity": "High", "likelihood": "Med"},

    {"id": 4, "dfd_source_id": "P1", "dfd_destination_id": "P2", "originator_id": "P2",
     "tree_node": "D.1", "threat_type": "D",
     "node_remap_note": "Cited D.1.1 until 2026-07-28. That node was invented by this project's Week 1 RECONSTRUCTION of the LINDDUN trees and does not exist in the official trees (v241203, bundled at references/linddun-trees/). Retargeted to the official D.1 (Observed communications); threat content unchanged.", "title": "Unencrypted internal traffic reveals zone-crossing timing via network observation alone",
     "description": "An adversary monitoring network traffic between the backend and the Geofencing Engine can detect exactly when the child enters or leaves a tracked zone purely from traffic timing/volume, without ever decrypting the payload.",
     "assumptions": "No evidence that internal service-to-service traffic is encrypted or padded to obscure event timing.",
     "severity": "Med", "likelihood": "Low"},

    {"id": 5, "dfd_source_id": "P1", "dfd_destination_id": "DS2", "originator_id": "DS2",
     "tree_node": "Dd.1.1", "threat_type": "Dd",
     "title": "Highly sensitive fields stored under the same policy as low-sensitivity account data",
     "description": "The Family Account Store retains the child's school name, home address, and friends'/hosts' addresses in the same table and under the same access-control and retention policy as low-sensitivity account metadata like display name or app theme preference.",
     "assumptions": "No field-level sensitivity classification or differential access control exists in the account store schema.",
     "severity": "High", "likelihood": "Med"},

    {"id": 6, "dfd_source_id": "DS1", "dfd_destination_id": "P1", "originator_id": "DS1",
     "tree_node": "Dd.4.2", "threat_type": "Dd",
     "title": "Location-store access credentials reused/unencrypted, exposing the full movement trail if compromised",
     "description": "Similar to KidsTube's JWT-in-localStorage pattern, the backend's credentials for the Location History Store are shared across environments and not rotated; if leaked, they expose a child's entire historical movement trail, not just a single session's data.",
     "assumptions": "The datastore credential is reused across staging and production, per common practice in comparably small teams.",
     "severity": "High", "likelihood": "Med"},

    {"id": 7, "dfd_source_id": "P1", "dfd_destination_id": "EE3", "originator_id": "P1",
     "tree_node": "Dd.4.1.2", "threat_type": "Dd",
     "title": "Parent can add a secondary guardian viewer without the child's knowledge or consent",
     "description": "The primary parent can grant a secondary guardian ongoing access to the child's live location at any time, dynamically expanding who can observe the child, with no notification to or consent from the child themselves.",
     "assumptions": "The invite/grant flow requires only the parent's confirmation, not any child-facing acknowledgment.",
     "severity": "Med", "likelihood": "High"},

    {"id": 8, "dfd_source_id": "P1", "dfd_destination_id": "EE3", "originator_id": "EE3",
     "tree_node": "I.1.1", "threat_type": "I",
     "title": "Secondary guardian receives the child's full name and live coordinates with no pseudonymization option",
     "description": "Location data shared with a secondary guardian includes the child's full name tied to live coordinates, with no option to share a coarser or pseudonymized view (e.g. \"at school\" instead of exact address) for lower-trust or extended-family viewers.",
     "assumptions": "The guardian-sharing feature has a single access tier (full detail) with no granularity control.",
     "severity": "Med", "likelihood": "High"},

    {"id": 9, "dfd_source_id": "DS1", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "I.1.2", "threat_type": "I",
     "title": "Reused parent login credentials directly re-identify the child's full movement history if compromised",
     "description": "If the parent's login credentials -- commonly reused across family apps -- are compromised, an attacker gains direct, fully identified access to the child's complete movement history under the parent's own authenticated session, no further inference needed.",
     "assumptions": "No additional authentication factor is required to view historical location data beyond the standard account login.",
     "severity": "High", "likelihood": "Med"},

    {"id": 10, "dfd_source_id": "P1", "dfd_destination_id": "EE4", "originator_id": "EE4",
     "tree_node": "L.2.2.2", "threat_type": "L",
     "title": "\"De-identified\" analytics shared with the ad partner can be re-linked into family-group profiles",
     "description": "Aggregated usage/engagement analytics sent to the advertising partner, though described as de-identified, can be combined with the partner's other data sources (device or ad identifiers, timing patterns) to reconstruct cross-app behavioral profiles of the family group.",
     "assumptions": "The analytics payload includes device- or session-level identifiers rather than only fully aggregated, k-anonymized statistics.",
     "severity": "Med", "likelihood": "Med"},

    {"id": 11, "dfd_source_id": "P1", "dfd_destination_id": "EE4", "originator_id": "P1",
     "tree_node": "Nc.1.2", "threat_type": "Nc",
     "node_remap_note": "Cited Nc.1.3 until 2026-07-28. That node was invented by this project's Week 1 RECONSTRUCTION of the LINDDUN trees and does not exist in the official trees (v241203, bundled at references/linddun-trees/). Retargeted to the official Nc.1.2 (Generic regulatory noncompliance); threat content unchanged.", "title": "Analytics sharing with an advertising partner is enabled by default with no explicit consent screen",
     "description": "Sharing usage analytics with a third-party advertising partner is on by default; the parent is never shown an explicit, purpose-specific consent screen before this sharing begins, and the child -- the actual data subject -- has no consent mechanism at all.",
     "assumptions": "The privacy policy discloses third-party sharing in general terms but the app has no dedicated consent toggle shown during onboarding.",
     "severity": "High", "likelihood": "High"},

    {"id": 12, "dfd_source_id": "P1", "dfd_destination_id": "EE4", "originator_id": "EE4",
     "tree_node": "Dd.3.2", "threat_type": "Dd",
     "title": "No technical or contractual control over the ad partner's further propagation of shared data",
     "description": "Once usage/engagement analytics reach the advertising partner, the app has no enforced technical or contractual control preventing that partner from further propagating or reselling the data to downstream ad-tech intermediaries.",
     "assumptions": "Any data-sharing agreement with the analytics partner is not technically enforced (e.g. no data-use audit or deletion-on-request mechanism).",
     "severity": "Med", "likelihood": "Med"},

    {"id": 13, "dfd_source_id": "EE1", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "U.1.1", "threat_type": "U",
     "title": "The child, the actual data subject, is never shown any notice that their location is being collected",
     "description": "Only the parent goes through onboarding and consent; the child -- whose location is the data being continuously collected -- is never shown any age-appropriate notice that this collection and sharing is happening at all.",
     "assumptions": "The child's device runs a lightweight tracking client with no user-facing onboarding or notice screen.",
     "severity": "High", "likelihood": "High"},

    {"id": 14, "dfd_source_id": "DS1", "dfd_destination_id": "P1", "originator_id": "DS1",
     "tree_node": "Dd.3.4", "threat_type": "Dd",
     "title": "Location history is retained indefinitely with no automatic deletion or lifecycle policy",
     "description": "The Location History Store accumulates GPS pings indefinitely with no automatic deletion, anonymization, or archival policy, meaning years of a child's precise movement history persist by default.",
     "assumptions": "No retention/lifecycle job or documented deletion policy was found for the Location History Store.",
     "severity": "Med", "likelihood": "High"},

    {"id": 15, "dfd_source_id": "EE1", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "Nr.1.1", "threat_type": "Nr",
     "title": "Every parental action is permanently logged and attributable, creating unintended surveillance evidence",
     "description": "Every parental action -- viewing the child's location, adding a guardian, changing geofence zones -- is logged with the parent's identity and retained indefinitely, creating a permanent, attributable record that could later be used as evidence of surveillance patterns in contexts like a custody dispute.",
     "assumptions": "Audit logs of parental actions have no retention limit and are not access-restricted beyond normal account authentication.",
     "severity": "Low", "likelihood": "Med"},

    {"id": 16, "dfd_source_id": "EE2", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "Nr.1.2", "threat_type": "Nr",
     "title": "A child's SOS/check-in message is permanently attributed with no ability to retract it",
     "description": "Once the child sends a manual SOS or check-in message with their location, it is permanently stored and attributed to them with no mechanism to retract or anonymize a message sent by accident or in a moment of distress.",
     "assumptions": "The check-in feature has no delete/undo affordance after submission.",
     "severity": "Low", "likelihood": "Low"},

    {"id": 17, "dfd_source_id": "EE2", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "U.2.1", "threat_type": "U",
     "title": "The child has no control to pause location sharing; only the parent can toggle tracking",
     "description": "The child has no in-app control to pause or temporarily disable location sharing (e.g. during a sensitive personal moment) -- only the parent can toggle tracking on or off, leaving the data subject with zero intervenability over their own data collection.",
     "assumptions": "The tracking on/off setting exists only in the parent-facing app, not the child's device client.",
     "severity": "Med", "likelihood": "High"},

    {"id": 18, "dfd_source_id": "P1", "dfd_destination_id": "DS1", "originator_id": "DS1",
     "tree_node": "Dd.2.1", "threat_type": "Dd",
     "title": "Full continuous GPS traces are stored instead of the coarser zone-crossing events actually needed",
     "description": "The system stores full continuous GPS traces (latitude, longitude, altitude, speed) rather than the coarser \"entered/exited zone X\" events that the geofencing feature actually requires, retaining substantially more granular data than the stated purpose needs.",
     "assumptions": "The Geofencing Engine could operate on zone-crossing events derived at ingestion time rather than requiring the raw trace to be persisted afterward.",
     "severity": "Med", "likelihood": "High"},

    {"id": 19, "dfd_source_id": "EE1", "dfd_destination_id": "P1", "originator_id": "P1",
     "tree_node": "Nc.1.2", "threat_type": "Nc",
     "title": "Collecting a minor's precise real-time location has no documented child-specific safeguard or DPIA",
     "description": "Collecting and continuously sharing a minor's precise real-time location has no documented data protection impact assessment or child-specific safeguard (e.g. verified parental consent, data minimization review), violating data-protection principles that apply specifically to children's location data.",
     "assumptions": "No DPIA or child-specific privacy-by-design documentation was found for the location-collection feature.",
     "severity": "High", "likelihood": "Med"},

    {"id": 20, "dfd_source_id": "P2", "dfd_destination_id": "EE1", "originator_id": "EE1",
     "tree_node": "D.2", "threat_type": "D",
     "title": "Notification metadata alone reveals which zone the child entered, without accessing raw coordinates",
     "description": "Someone with access to push-notification metadata or logs (e.g. a shared family phone, or a compromised notification-service integration) can infer which geofenced zone the child entered based on which alert template fired, without ever accessing the raw coordinate data.",
     "assumptions": "Notification templates are zone-specific (e.g. \"arrived at school\" vs. a generic alert) rather than uniformly worded.",
     "severity": "Low", "likelihood": "Med"},
]

OUT_PATH = Path(__file__).resolve().parent.parent / "knowledge_base" / "scenarios" / "family_location" / "gold_standard_threats.json"


def build() -> dict:
    types = Counter(t["threat_type"] for t in THREATS)
    return {
        "_meta": {
            "scenario": "Family Location Sharing App",
            "source": "Hand-authored for this repo (Week 8), grounded in real LINDDUN Pro threat-tree "
                       "nodes -- NOT transcribed from an external human-authored assignment or an "
                       "authoritative third-party report. Weaker evidentiary status than KidsTube "
                       "(human HW2) or Genomic (NIST SP 1800-43C) until independently reviewed.",
            "count": len(THREATS),
            "type_distribution": dict(sorted(types.items())),
            "field_notes": "dfd_source_id/dfd_destination_id anchor each threat to a real dfd.json flow "
                           "(location-based matching, same convention as Genomic -- see "
                           "eval/match.py's flow_anchored = scenario == 'kidstube' check). All flows "
                           "are Process-mediated, so every threat is structurally reachable.",
        },
        "threats": THREATS,
    }


def main():
    out = build()
    OUT_PATH.write_text(json.dumps(out, indent=2) + "\n")
    print(f"Wrote {OUT_PATH} ({out['_meta']['count']} threats, types: {out['_meta']['type_distribution']})")


if __name__ == "__main__":
    main()
