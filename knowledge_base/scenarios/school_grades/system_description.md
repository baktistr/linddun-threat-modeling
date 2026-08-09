# School Grades Management Portal

> Fifth evaluation scenario, alongside KidsTube, Genomic, Family Location Sharing, and Smart Home.
> Hand-authored for this repo (2026-08-08) from the author's own specification — one of the two
> scenarios the abstract previously listed as planned. Not transcribed from an external
> human-authored assignment or an authoritative third-party report — see
> [`gold_standard_threats.json`](gold_standard_threats.json)'s own `_meta` for the same provenance
> caveat as smart_home and family_location.

A K-12 school's grades portal. Students submit assignments and view their own grades; parents view
their own child's grades through a linked account; teachers review submissions and record grades
with written feedback; a school administrator manages accounts and parent-child links. The web
application and both databases run on a **third-party cloud hosting provider**, which also receives
nightly full backups. Minors' education records at a commercial third-party processor is the
privacy core of the scenario.

## Actors
- **Student** — the data subject, a minor; submits work, views own grades.
- **Parent** — views their own child's grades and feedback.
- **Teacher** — reviews submissions, records grades and feedback.
- **School Administrator** — creates, modifies, disables accounts; maintains parent-child links.
- **Cloud Hosting Provider** — third party hosting the app and databases, receiving backups.

## Components
- **Grades Portal Web App** (Process) — authentication, role routing, all user-facing views.
- **Assignment & Grading Service** (Process) — submission handling, grade recording, view assembly.
- **Assignment Store** (DataStore) — submitted work files.
- **Grade Records Database** (DataStore) — grades, feedback, grader identity, timestamps.
- **Account Directory** (DataStore) — accounts, roles, parent-child relationship links.

## Privacy-relevant properties
- Every record concerns a minor; grades and teacher feedback are sensitive beyond their face value.
- One persistent student identifier links submissions and grades across courses and years.
- The parent-child link makes household relationships part of the account data.
- The full plaintext database is technically readable by the hosting provider (no customer-held keys).
- Grade entries are permanently attributable to the recording teacher.
