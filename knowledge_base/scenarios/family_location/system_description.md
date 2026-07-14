# Family Location Sharing App

> Third evaluation scenario, alongside KidsTube and Genomic. Hand-authored for this repo
> (Week 8) from a short product description, not derived from an external homework assignment
> or an authoritative third-party report. See [`gold_standard_threats.json`](gold_standard_threats.json)'s
> own `_meta` for the provenance caveat this implies for anyone citing its numbers.

An app which shares the location of children with their parents, for situations such as their
children going on field trips, staying over at a friend's house, or walking home from school. A
parent can invite a secondary guardian (e.g. a grandparent) to also view the child's location, and
the app defines geofenced zones (home, school, a friend's address) that trigger arrival/departure
notifications. The free tier is funded in part by sharing aggregated usage analytics with a
third-party advertising/analytics partner.

## Actors
- **Parent** -- registers the account, owns the child's profile, defines geofence zones, views
  location history.
- **Child** -- carries the tracked device; has no account of their own and no controls over the
  system's behavior.
- **Secondary Guardian** -- an additional viewer invited by the parent (e.g. a grandparent or
  relative), can view the child's live location once added.
- **Advertising/Analytics Partner** -- third party receiving aggregated, "de-identified"
  usage/engagement analytics.

## Components
- **Mobile App Backend** (Process) -- central server handling accounts, location ingestion, and
  history retrieval.
- **Geofencing & Alert Engine** (Process) -- evaluates incoming location pings against configured
  zones and triggers notifications.
- **Location History Store** (DataStore) -- retains every GPS ping received from the child's
  device.
- **Family Account & Permissions Store** (DataStore) -- account records, child profile, geofence
  zone definitions, and guardian access permissions.

## Overlap with KidsTube, and scenario-specific risks

Per the scenario brief this repo was given: some threats here deliberately overlap with KidsTube's
gold standard in *category* (e.g. insecure credential/token storage enabling account takeover,
excessive/indefinite retention with no lifecycle policy), since both are consumer apps handling a
child's data on behalf of a parent who is not the data subject. Others are specific to this
system's location-tracking nature: continuous high-frequency GPS collection exceeding what a
coarse geofence check needs, third-party ad/analytics sharing without the data subject's (the
child's) own consent, and incomplete disclosure of how long location history is retained or with
whom it is shared.

All flows in `dfd.json` are Process-mediated (every interaction has a Process on at least one
side), so every flow is reachable under LINDDUN Pro's Table 4.1 with no `effective_type`
reclassification needed -- deliberately, mirroring the existing `smart_home` demo scenario's
discipline, so this scenario's structural reachability ceiling equals its full gold-standard size
(no genomic-style mapping-table gap).
