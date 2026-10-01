# cnbx — Inbox

Member-device composition over Contacts, Threads, Delivery and Waves.

## Scope

Wire contact and outcome operations, direct/fork/room conversations, accepted
history and live/offline delivery status. Wallet owns balance/proof capability;
Groups supplies verified membership decisions from Board. Read state from the
owners and publish combined candidates through the same Vault checkpoint.

Never duplicate a relationship journal, MLS ratchet, accounting state, ACK or
group policy. No Forum connection, frontend privilege, raw MLS/balance-store
bypass or Wave release before accepted evidence and durable publication.
All product frontends use the cmsg door.

**States.** Derived Idle, WaitingForRelease, LiveConversation and ClosedOrOffline;
Inbox persists no independent domain state.

**Ports.** Typed owner views and candidate publication. Current established direct
send, receive and ACK paths compose Contacts, Threads, Delivery and Store; Waves,
Wallet, Groups and Records provide the remaining first-contact/group/offline ports.
A repeated message returns Delivery's durable receipt; a repeated ACK reports the
owner's existing acceptance without another history transition.

**Invariants and tests.** Full acceptance requires real reservation → release →
Answer → unmetered direct chat, close/block cancellation, failed-store refusal
before first content, and a combined owner checkpoint. Native and actual Wasm
vectors must use the real leaves. Synthetic test issuers establish only the
fixture's authority boundary, never production device attestation or accounting.

## Status

Stream A was committed first. Established-contact send/receive/ACK composition
and owner-derived views are implemented locally but unvalidated. First-contact,
room, live-session and record-network routes still await owner integration. No
full reservation-to-release-to-Answer/direct-chat acceptance. See
[contract](docs/CONTRACT.md) and [FSL license](LICENSE.md).
