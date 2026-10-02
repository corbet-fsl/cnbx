# cnbx — Inbox

Member-device composition over Contacts, Threads, Delivery and Waves.

## Scope

### Purpose

Every conversation of the member, one to one and in groups, by wiring `cwvs`, `ctcs`, `cthr` and `cdlv`.

### Owns

Wiring only, with typed results for wave, outcome, contact and conversation operations and no state of its own. Covers direct, group and room conversation and delivery-status operations, using `cwlt`, `cgrp` and `cdht`.

### Never

Reimplements contact rules, encryption, acknowledgements or group governance. Holds a forum connection, releases a wave before accepted accounting and a durable checkpoint, or exposes raw MLS or an accounting bypass.

### States

Derived Idle, WaitingForRelease, LiveConversation and ClosedOrOffline.

### Test obligations

Full reservation to release to Answer to unmetered direct chat with the real libraries, close and block cancelling live work, failed storage never exposing uncommitted first content, and one combined checkpoint. Native and Wasm behaviour with identical vectors, full line and branch coverage, real round trips without mocks of its own logic, injected delay, duplication, loss, cancellation, clock regression, corruption and storage conflicts, atomic publication with acknowledgement only after durable acceptance, per-community isolation, and bounded work without its own cryptography.

## Status

Stream A was committed first. Established-contact send/receive/ACK composition
and owner-derived views are implemented locally but unvalidated. First-contact,
room, live-session and record-network routes still await owner integration. No
full reservation-to-release-to-Answer/direct-chat acceptance. See
[contract](docs/CONTRACT.md) and [FSL license](LICENSE.md).
