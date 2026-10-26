# cnbx agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cnbx` — lib `0`, `authority` `1`,
  `contacts` `2`, `handle` `2`, `inbox` `4`, `release` `2`, `waves` `2`
  passed, exit 0
- `~/agents/scratch/cbuild <lane> fmt -p cnbx -- --check` — must be clean
- Full gate (clippy `--locked`, native + actual wasm vectors, 100% reachable
  line and branch coverage) runs in CI: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Only an established matching contact with current peer lineage is authorized
  -> `tests/authority.rs::only_an_established_matching_contact_with_current_peer_lineage_is_authorized`
- Blocks are signed, checkpointed and survive reload; voucher admission shares
  the conversation id
  -> `tests/contacts.rs::block_is_signed_checkpointed_and_survives_reload`,
  `voucher_admission_establishes_the_contact_with_the_shared_conversation_id`
- Handles retained only from signed announcements under the peer's lineage
  -> `tests/handle.rs::a_handle_is_retained_only_from_a_signed_announcement_under_the_peers_lineage`
- Established messages use the real owners through the facade; vault and inbox
  share one checkpoint without relocking
  -> `tests/inbox.rs::established_message_uses_real_owners_through_the_facade`,
  `shared_vault::actual_vault_keys_and_inbox_share_one_checkpoint_without_relocking`
- Refused releases write nothing; Answers need the linked wave with exactly
  that receipt
  -> `tests/release.rs::refused_releases_write_nothing`,
  `answered_needs_a_linked_wave_with_exactly_that_receipt`
- Offers are checkpointed, retained and never replayed; member digests accept
  only the canonical pseudonym string
  -> `tests/waves.rs::offer_is_checkpointed_retained_and_never_replayed`,
  `member_digest_accepts_only_the_canonical_pseudonym_string`
- No domain state of its own; no raw MLS or ledger bypass; frontends use cmsg
  -> `tests/release.rs::refused_releases_write_nothing` (no fabricated acceptance)

Pointers: `src/lib.rs`, `src/authority.rs`, `src/release.rs`,
`docs/CONTRACT.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; FSL-1.1-ALv2; no GPL/AGPL-only deps; never publish to a registry.
