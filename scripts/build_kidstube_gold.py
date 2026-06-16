#!/usr/bin/env python3
"""Generate the KidsTube gold-standard threat catalog (30 threats) as structured JSON.

Source: EPS S26 HW2 (Bakti Satria Adhityatama). This is the evaluation ground truth
against which AI-generated threats are compared in later weeks.
"""
import json
from pathlib import Path

THREATS = [
    (1,  "EE1-P1 [DF1]",        "EE1",        "L.1.1",  "L",  "Linking parent and child accounts via shared email identifier",
     "Parent email is a persistent unique identifier reused for child login and embedded in JWTs, linking all child activity to the parent's real-world identity.",
     "Email addresses are not hashed or pseudonymized anywhere in the system.", "Med", "High"),
    (2,  "EE1-P1 [DF1]",        "P1",         "Dd.1.1", "Dd", "Excessive collection of government ID during registration",
     "Government ID image (photo, legal name, ID number, address, DOB) is collected for age verification, far more than needed, and stored unencrypted with no access control or retention policy.",
     "Government ID image stored in plaintext on disk. No evidence of encryption at rest.", "High", "High"),
    (3,  "EE1-P1 [DF1]",        "DF1",        "I.1.1",  "I",  "Interception of identified parent data during registration transmission",
     "Registration sends full PII including government ID image over the network; if HTTPS is not enforced, a network adversary can directly identify the parent.",
     "Engineering documentation does not mention TLS/HTTPS configuration for the Node.js server.", "High", "Med"),
    (4,  "P1-DS1 [DF2]",        "DS1",        "Dd.3.1", "Dd", "Indefinite retention of parent account data without lifecycle management",
     "Parent records have timestamps but no automatic deletion, anonymization, or archival. Privacy policy claims 30-day erasure but no technical enforcement exists.",
     "No automated data lifecycle management found in the codebase.", "Med", "High"),
    (5,  "P1-DS4 [DF15]",       "DS4",        "Dd.4.1", "Dd", "Government ID images stored insecurely on shared file system",
     "ID images saved to backend/uploads/images/ with no encryption, no access control beyond OS permissions, co-located with video content. Shared SSH credentials allow multiple users to access all ID images.",
     "Images saved using multer to local directory. SSH credentials shared among multiple accounts.", "High", "High"),
    (6,  "P1-DS5 [DF16]",       "DS5",        "Dd.4.2", "Dd", "JWT token and user data exposed in browser localStorage",
     "JWT (user ID, userType) and full user data stored in localStorage, accessible to any same-origin JavaScript (XSS-vulnerable). Tokens valid 7 days, no rotation, persist on shared devices.",
     "Confirmed: JWT token stored in localStorage and valid for 7 days.", "High", "Med"),
    (7,  "EE2-P1 [DF4]",        "EE2",        "L.1.2",  "L",  "All child actions linked to parent account via shared credentials",
     "Children log in with the parent's email and password; every child action carries the parent's account ObjectId, inherently linking child behavior to the parent's real identity. Children have no independent credentials.",
     "Confirmed by engineering documentation child login flow.", "Med", "High"),
    (8,  "EE2-P1 [DF4]",        "DF4",        "I.1.2",  "I",  "Child identity revealed through parent credential reuse and weak six-digit code",
     "Child submits parent credentials over the network; any breach exposes all children's profiles. The six-digit code is static, user-chosen, and trivially guessable (test accounts use 123456).",
     "Test account codes are 123456. No complexity enforcement beyond exactly 6 digits.", "Med", "Med"),
    (9,  "EE1-P3 [DF6]",        "P3",         "Dd.1.2", "Dd", "Excessive child PII collected at profile creation",
     "Exact DOB, gender, and government ID are collected for each child — unnecessary for service delivery and most under-13s lack photo ID. Violates COPPA data minimization (§312.7).",
     "Confirmed by ChildProfile model schema.", "High", "High"),
    (10, "P3-DS2 [DF7/DF10]",   "DS2",        "L.2.1",  "L",  "Profiling children through aggregated behavioral data in DS2",
     "DS2 stores up to 50 search entries and 100 watch entries per child with exact queries, timestamps, per-second durations; combined with name, DOB, gender this builds a rich behavioral profile.",
     "Confirmed by ChildProfile schema and history tracking code.", "High", "High"),
    (11, "P3-DS2 [DF10]",       "DS2",        "Dd.2.1", "Dd", "Excessive volume of child behavioral data retained indefinitely",
     "DS2 retains up to 50 search + 100 watch entries per child. Documentation states logs are not deleted. The FIFO cap perpetually maintains maximum volume — not a deletion mechanism.",
     "Documentation explicitly states logs are not deleted. 50/100 caps are FIFO buffers.", "High", "High"),
    (12, "EE2-P2 [DF8]",        "P2",         "Nr.1.1", "Nr", "Non-repudiation of child actions via persistent attributed logging",
     "Every child action is logged with timestamps and the child's ObjectId across DS2/DS3, creating an irrefutable permanent record of a minor's online behavior the child cannot deny.",
     "Confirmed by ChildProfile and Video schemas.", "Med", "High"),
    (13, "EE2-P2 [DF8]",        "P2",         "U.1.1",  "U",  "Children unaware of data collection and parental surveillance",
     "P2/P3 silently record all activity. Documentation states children are not notified about search/watch history tracking. No child-facing notices or indicators.",
     "Directly stated in engineering documentation under Video Search and Watch History.", "High", "High"),
    (14, "P2-DS3 [DF9]",        "DS3",        "L.1.3",  "L",  "Video interactions permanently linkable to identified users via ObjectId",
     "Likes and comments store user ObjectId as foreign keys to DS1/DS2, permanently linking all content interactions to identified individuals and enabling long-term profiling.",
     "Confirmed by Video schema: likes[].user and comments[].user are ObjectId refs.", "Med", "High"),
    (15, "DS2-P4 [DF13]",       "P4",         "Dd.4.3", "Dd", "Planned sharing of children's browsing data with AI engine and third parties",
     "Planned feature would expose children's behavioral profiles to an AI engine and ad targeting. Documentation states browsing history is used to train AI models and shared with advertisers (not yet implemented).",
     "Feature documented but not yet implemented. Analyzed as a planned threat requiring preventive action.", "High", "Med"),
    (16, "P4-EE3 [DF14]",       "EE3",        "Nc.1.1", "Nc", "Planned third-party data sharing violates COPPA and contradicts privacy policy",
     "Advertisers would receive children's behavioral data without verifiable parental consent (COPPA §312.5). The privacy policy states KidsTube does not sell or rent children's data — directly contradicting the planned feature.",
     "Privacy policy (Section 6) and engineering documentation are in direct contradiction.", "High", "Med"),
    (17, "P1-DS1 [DF2]",        "DS1",        "Dd.4.4", "Dd", "MongoDB database accessible without authentication on shared server",
     "Connection uses mongodb://localhost:27017/kidstube with no TLS and no authentication; any process on the server can read/write all collections. SSH access uses shared accounts.",
     "Connection string confirmed in documentation. Shared SSH accounts documented.", "High", "High"),
    (18, "EE1-P3-DS2 [DF6->DF7]","DS2",       "Nc.1.2", "Nc", "Systematic violation of data minimization principle across the platform",
     "Excessive data (exact DOB, gender, child government ID, per-second watch tracking, 50/100 behavioral logs) collected and retained. Violates COPPA §312.7, GDPR Art. 5(1)(c), CCPA minimization.",
     "Based on analysis of all collected data fields vs. functional requirements.", "High", "High"),
    (19, "EE1-P3 [DF6]",        "P3",         "U.2.1",  "U",  "Limited intervenability: deletion claims contradict actual data persistence",
     "Privacy policy claims 30-day erasure with no enforcement; logs are not deleted; government ID images and comments referencing the child ObjectId may survive profile deletion.",
     "Assumed file system cleanup (DS4) and cross-collection cleanup (DS3) not triggered by API deletion.", "Med", "Med"),
    (20, "EE2-P2 [DF8]",        "DF8",        "D.1.1",  "D",  "Child search queries and actions observable on the network",
     "Child interactions are sent as HTTP API calls with JWT in the Authorization header. Without enforced HTTPS, exact search terms are visible to network observers; even with HTTPS, traffic patterns reveal behavior.",
     "No mention of HTTPS enforcement, HSTS headers, or TLS configuration in documentation.", "Med", "Med"),
    (21, "P1-EE1/EE2 [DF3/DF5]","P1",         "I.2.1",  "I",  "JWT tokens expose user type and identity in transit",
     "JWTs are signed but not encrypted; anyone intercepting a token can decode the base64 payload to learn the user's ObjectId and whether the request is from a parent or child.",
     "Standard JWT uses base64-encoded payloads readable without the signing secret.", "Med", "Med"),
    (22, "DS2-P3-EE1 [DF17]",   "P3",         "U.1.2",  "U",  "Covert parental surveillance of children without age-appropriate transparency",
     "Parents receive full search and watch history through Manage Children. Children are explicitly not informed; complete secrecy, especially near age 13, violates age-appropriate transparency principles.",
     "Directly confirmed by engineering documentation.", "High", "High"),
    (23, "EE1-P1 [DF1]",        "P1",         "I.2.2",  "I",  "Six-digit code provides inadequate verification of parental identity",
     "P1 validates only that the code is exactly 6 digits — no complexity, rotation, or lockout. All test accounts use 123456. A child could observe or guess the code and access parent controls.",
     "Test accounts use 123456. No rate limiting or lockout documented.", "Med", "High"),
    (24, "P2-DS3 [DF9]",        "DS3",        "Nr.1.2", "Nr", "Children's comments create irrevocable attributed speech records",
     "Comments are stored with the child's ObjectId, text, and timestamp. No DELETE endpoint exists, creating permanent attributable speech records for minors that persist even if harmful.",
     "Video API shows POST /api/videos/:id/comments but no DELETE endpoint for comments.", "Med", "Med"),
    (25, "P3-DS2 [DF7]",        "DS2",        "L.2.2",  "L",  "Cross-referencing child and parent data via shared naming prefix and foreign key",
     "Child profiles contain a direct parent ObjectId foreign key and documentation states children share the same prefixes as the parent, making family relationships trivially discoverable from DB access alone.",
     "Stated in engineering documentation and confirmed in ChildProfile schema.", "Med", "High"),
    (26, "P1-DS4 [DF15]",       "DS4",        "Dd.1.3", "Dd", "Government ID images co-located with streaming content on shared file system",
     "Government IDs are stored in the same backend/uploads/ directory structure as publicly served video content. Misconfigured static file serving could accidentally expose IDs.",
     "Both images and videos stored under backend/uploads/ per file structure documentation.", "High", "Med"),
    (27, "EE1-P2 [DF11]",       "P2",         "Dd.3.2", "Dd", "No automated content moderation before video exposure to children",
     "Videos default to isApproved:false but approval relies entirely on parent judgment. No automated content scanning or platform-level review; a negligent parent could approve inappropriate content.",
     "isApproved defaults to false; no automated screening pipeline documented.", "Med", "Med"),
    (28, "EE1-P1 [DF1]",        "P1",         "Nc.1.3", "Nc", "Inadequate COPPA verifiable parental consent mechanism",
     "Parent uploads government ID and chooses a six-digit code, but P1 never verifies the ID belongs to the registrant. None of the FTC-approved §312.5 consent methods are implemented.",
     "No third-party identity verification or FTC-approved consent method documented.", "High", "High"),
    (29, "P1/P2/P3-DS1/DS2/DS3 [DF2/DF7/DF9]","DS1/DS2/DS3","Dd.4.5","Dd","No encryption at rest or in transit for database containing children's PII",
     "MongoDB connections use no TLS and store all personal data (parent PII, child PII, behavioral data) without encryption at rest. Combined with no authentication (threat 17), all data is plaintext-readable.",
     "Connection string has no auth or TLS parameters. No mention of encryption features.", "High", "High"),
    (30, "P3-DS2 [DF10]",       "DS2",        "U.1.3",  "U",  "Per-second watch duration tracking creates undisclosed detailed behavioral profiles",
     "VideoPlayer.js reports exact seconds watched via setInterval; DS2 stores watchDuration per second with a completion flag. This granularity is undisclosed, unnecessary, and builds detailed temporal profiles of children.",
     "Confirmed by VideoPlayer.js using setInterval and trackWatchHistory(videoId, totalWatchTime, true).", "Med", "High"),
]

def main():
    catalog = {
        "_meta": {
            "scenario": "KidsTube",
            "source": "EPS S26 HW2 (Bakti Satria Adhityatama)",
            "role": "gold-standard baseline for evaluation",
            "threat_count": len(THREATS),
            "field_notes": "severity/likelihood are the HW2 qualitative ratings. originator_id is the DFD element where the threat is located (LINDDUN Pro Table 4.2-4.4 format). tree_node is the LINDDUN threat tree node id.",
        },
        "threats": [
            {
                "id": t[0],
                "interaction": t[1],
                "originator_id": t[2],
                "tree_node": t[3],
                "threat_type": t[4],
                "title": t[5],
                "description": t[6],
                "assumptions": t[7],
                "severity": t[8],
                "likelihood": t[9],
            }
            for t in THREATS
        ],
    }
    out = Path(__file__).parent.parent / "knowledge_base" / "scenarios" / "kidstube" / "gold_standard_threats.json"
    out.write_text(json.dumps(catalog, indent=2))
    print(f"Wrote {len(THREATS)} threats to {out}")
    # quick integrity checks
    ids = [t[0] for t in THREATS]
    assert ids == list(range(1, 31)), "threat ids must be 1..30 contiguous"
    types = {t[4] for t in THREATS}
    print(f"Threat types present: {sorted(types)}")
    from collections import Counter
    print("Per-type counts:", dict(Counter(t[4] for t in THREATS)))

if __name__ == "__main__":
    main()
