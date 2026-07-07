# Smart Home Security System (demo scenario)

A consumer smart-home platform: a homeowner installs cameras and door sensors managed by a
local **Home Hub**, which syncs events and video to a cloud backend accessible from a mobile app.
A guest can be issued a temporary door-unlock code. Aggregated (non-identifying, in theory)
usage analytics are shared with a third-party analytics vendor to improve the product.

This is a hand-authored dummy scenario for demoing the generation pipeline on a system outside
the two tuned/held-out evaluation scenarios (KidsTube, genomic). It has no
`gold_standard_threats.json` -- it's for showing grounded threat generation + citations, not for
precision/recall scoring.

## Actors
- **Homeowner** -- registers the account, owns the devices.
- **Guest User** -- receives a temporary access code, no persistent account.
- **Cloud Analytics Vendor** -- third party receiving usage analytics.

## Components
- **Home Hub** (Process) -- local controller for cameras/sensors/locks.
- **Mobile App Backend** (Process) -- cloud service backing the homeowner's mobile app.
- **Local Event Log** (DataStore) -- on-device log of sensor/door events.
- **Cloud Video Storage** (DataStore) -- stores uploaded camera clips.

All flows in `dfd.json` are Process-mediated (every interaction has a Process on at least one
side), so every flow is reachable under LINDDUN Pro's Table 4.1 with no `effective_type`
reclassification needed -- deliberately, to keep this demo simple.
