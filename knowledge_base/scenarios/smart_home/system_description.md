# Smart Home Security System

> Fourth evaluation scenario, alongside KidsTube, Genomic, and Family Location Sharing. Originally
> a hand-authored demo scenario with no gold standard (Week 4); upgraded to a scored evaluation
> scenario in Week 8. Like Family Location, this is hand-authored for this repo, not transcribed
> from an external human-authored assignment or an authoritative third-party report -- see
> [`gold_standard_threats.json`](gold_standard_threats.json)'s own `_meta` for the same provenance
> caveat.

A consumer smart-home platform: a homeowner installs cameras and door locks managed by a local
**Home Hub**, which syncs events and video to a cloud backend accessible from a mobile app. A
guest can be issued a temporary door-unlock code. Aggregated (non-identifying, in theory) usage
analytics are shared with a third-party analytics vendor to improve the product.

## Actors
- **Homeowner** -- registers the account, owns the devices.
- **Guest User** -- receives a temporary access code, no persistent account.
- **Cloud Analytics Vendor** -- third party receiving usage analytics.

## Components
- **Home Hub** (Process) -- local controller for cameras/door locks/sensors.
- **Mobile App Backend** (Process) -- cloud service backing the homeowner's mobile app.
- **Local Event Log** (DataStore) -- on-device log of sensor/door/lock events.
- **Cloud Video Storage** (DataStore) -- stores uploaded camera clips.

## Overlap with KidsTube, and scenario-specific risks

Per the scenario brief this repo was given: some threats here deliberately overlap with
KidsTube's gold standard in *category* (insecure credential/API-key storage enabling access to
the full video archive, indefinite retention with no lifecycle policy), since both hand off
sensitive data to a third party or persist it far longer than the stated purpose requires. Others
are specific to this system: continuous occupancy/motion profiling from aggregated sensor events,
targeted-advertising-flavored risk from the analytics vendor's downstream use of "aggregated"
usage data, and incomplete disclosure of exactly how long video/event data is retained or which
third parties receive it.

All flows in `dfd.json` are Process-mediated (every interaction has a Process on at least one
side), so every flow is reachable under LINDDUN Pro's Table 4.1 with no `effective_type`
reclassification needed -- deliberately, so this scenario's structural reachability ceiling
equals its full gold-standard size (no genomic-style mapping-table gap).
