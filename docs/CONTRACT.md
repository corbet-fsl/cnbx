# Inbox contract

Inbox wires the four owner libraries; it adds no domain state or protocol.
Idle, WaitingForRelease, LiveConversation and ClosedOrOffline are derived views.
No caller-supplied boolean, raw roster or decoded proof DTO grants authority.

Every successful mutation is the child's actual candidate/checkpoint operation.
Contacts/Threads/Delivery/Wallet outputs share the encrypted cwst transaction
before publication or ACK. Failed/uncertain storage returns refusal/reconcile,
never a fresh operation ID, blind retry or fabricated acceptance.

First-contact release needs real Waves/Wallet accepted reservations and atomic
local Wallet adoption. The MVP also requires the original record-epoch proof
and punishment paths; missing original evidence must refuse release.
Rooms need the Groups/Attend ordered proof capability. Transport
uses complete Mesh messages and existing Records. Missing owner ports remain
unavailable and are separate from facade test or compile success.

Current composition implements established-contact owner-derived views and
send/receive/receipt/ACK checkpoint forwarding. Pending and Receiving expose no
plaintext, ciphertext or receipts. Published exposes only the owners' committed
history and durable Delivery wire. It adds no state machine or transcript.
Waves, room and transport composition are still incomplete; a direct-owner grant
is not a replacement for Waves accepted release evidence.

## Direct session and member API

`Inbox::view(conversation, store)` loads only committed owner state.
`View::snapshot(peer)` returns the canonical serde/schemars `ConversationView`
with that peer's Contacts relation and the selected conversation's accepted
history. It grants no authority; the peer argument selects a relation, not an
MLS recipient. The door uses owner types directly for its generated schema.

The setup sequence stays inside Inbox: `View::key_package`,
`View::create_direct` and `View::join_direct` return opaque `Preparing`.
`Preparing::commit` delegates the actual Threads checkpoint and returns `Opened`;
only `Opened::events` exposes the committed package or invitation. Reload the
view after each checkpoint. Both preparation and publication use the current
owner authority. This is not a first-contact release or a way around Waves.

After `Published::outgoing` stores the envelope, reload the view and call
`View::retry(message, devices)` to obtain exactly those stored bytes after a
lost response or restart. The current Contacts and device checks still apply.
Send one complete `Wire::bytes()` message through Mesh. Feed a received reply
through `View::acknowledge` and commit its Pending result before reporting
recipient acceptance. A receiver sends `Published::receipt` only after its
combined history/Delivery checkpoint; a duplicate returns the retained receipt.
No transport completion, retry or receipt is an accounting Answer.

## Consent-driven group preparation

`Inbox::group(id, store)` loads the actual canonical Groups and Threads records.
`GroupConversation::{revision,snapshot}` projects their current owner facts.
`prepare(request, GroupAction, keys, (policy, authority), clock, max_groups)`
authenticates the original Groups request, selects its sealed membership effect
and prepares the matching real MLS create/join/update. No caller snapshot or
raw roster substitutes for the original signed consent checks.

`PreparingGroup::commit(keys, store, (policy, authority), clock)` delegates the
single Groups/Threads/outbox CAS and the fresh publication authorization to
Threads. It returns `GroupPublication::{revision,events,effects}` only after
success. The original Groups Request/Command/Consent/GroupView are reexported
for generated API schemas. No Wave or account debit accompanies membership.

This path covers immutable Circle/Ingroup forks. Opening/Public ordered MLS,
Attend history/key handover and group Delivery envelopes remain unavailable;
the facade preserves those owner refusals. Real three-member MLS tests use a
signed fixture registry, not production G3/contact authority or live transport.

## Waves journal

`Inbox::waves(member, store)` loads Waves' committed reservation journal, where
`member` is Accounting's SHA-256 of the canonical pseudonym, supplied by the
trusted runtime. `Waves::{reservations,offer}` are owner views. `prepare_offer`,
`accept_reservations` and `record_outcome` return an opaque `PreparedWave` and
`PreparedWave::commit` delegates the owner's single checkpoint. Accepting
reservations and outcomes consume Wallet's `VerifiedWaveReservation` and
`VerifiedWaveOutcome`, which no caller JSON can construct. This is evidence
progress only: it releases no first content and establishes no contact. Release
still needs the combined Wallet, Contacts, Threads and Delivery checkpoint.

## Own-authority Contacts

`Inbox::contacts(store)` loads the committed relation journal. `Contacts::apply`
signs one Block, Close or Reopen event with this device's own `ctcs.control`
key, checks it against this device's own current lineage from Keys (`OwnDevice`,
which answers for no peer) and delegates the single Contacts checkpoint. The store
operation id is the hash of the signed bytes, so a retry reuses it. Begin (a new
Pending contact) and Answered need first-contact release and verified Waves
accounting evidence; `ctcs::UnavailableOutcomes` refuses them here. Peer-authored
journal merges need a production peer lineage directory and are not exposed.
