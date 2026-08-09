# Wearable Fitness & Health Tracking App

> Sixth evaluation scenario, alongside KidsTube, Genomic, Family Location Sharing, Smart Home, and
> School Grades. Hand-authored for this repo (2026-08-08) from the author's own specification — the
> second of the two scenarios the abstract previously listed as planned. Not transcribed from an
> external human-authored assignment or an authoritative third-party report — see
> [`gold_standard_threats.json`](gold_standard_threats.json)'s own `_meta` for the same provenance
> caveat as smart_home and family_location.

A consumer wearable with GPS plus its companion mobile app. The user logs calorie intake, meals,
and weight; the device continuously streams heart rate, step, and position telemetry. A **health
analytics service** reads the accumulated logs across sessions to surface trends and to infer
health-condition indicators — eating-disorder or diabetes risk signals — and derives daily-routine
summaries from the location history. The full dataset and the analytics models are hosted at a
**third-party cloud provider**. Special-category health inference from lifestyle data, and
cross-session location linkability, are the privacy core of the scenario.

## Actors
- **User (wearer)** — the data subject; logs intake and weight, wears the device.
- **Cloud Hosting Provider** — third party hosting analytics, health logs, and location history.

## Components
- **Wearable Device** (Process) — continuous sensor capture: heart rate, steps, GPS.
- **Companion Mobile App** (Process) — manual entries, dashboards, sync endpoint.
- **Health Analytics Service** (Process) — cross-session analysis, condition inference, routine derivation.
- **Health Log Store** (DataStore) — calorie intake, meals, weight history, exercise sessions.
- **Location History Store** (DataStore) — timestamped GPS traces, retained across sessions.

## Privacy-relevant properties
- Condition inference creates special-category health data (GDPR Art. 9) from lifestyle logs.
- The GPS function allows location history to be queried across sessions, revealing daily routine.
- Nightly-rest GPS clusters are a quasi-identifier that re-identifies "de-identified" traces.
- Collection is continuous; the user-facing features need only per-workout and daily summaries.
- The host stores both health and location datasets, joinable through shared identifiers.
