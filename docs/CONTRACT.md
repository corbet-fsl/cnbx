# Inbox contract

Inbox wires the four owner libraries; it adds no domain state or protocol.
Idle, WaitingForRelease, LiveConversation and ClosedOrOffline are derived views.
No caller-supplied boolean, raw roster or decoded proof DTO grants authority.

Every successful mutation is the child's actual candidate/checkpoint operation.
Contacts/Threads/Delivery/Wallet outputs share the encrypted cwst transaction
before publication or ACK. Failed/uncertain storage returns refusal/reconcile,
never a fresh operation ID, blind retry or fabricated acceptance.

First-contact release needs real Waves/Wallet accepted reservations and current
record checks. Rooms need the Groups/Attend ordered proof capability. Transport
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
