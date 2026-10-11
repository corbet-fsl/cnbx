//! Own-authority Contacts vectors with real scoped Keys. Test issuers are not
//! production G3 authority.
mod support;
use ckmg::Binding;
use cnbx::{ContactState, Contacts, Error, Inbox, OwnAction};
use cwst::{Store, backend::Memory};
use futures::executor::block_on;
use support::{Guard, Time, create, machine, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

async fn store(seed: u8) -> Store<Memory> {
    let cipher = ckmg::passkey::store_cipher(&prf(seed), "alpha").unwrap();
    Store::create(Memory::new(), &cipher, "alpha")
        .await
        .unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn block_is_signed_checkpointed_and_survives_reload() {
    block_on(async {
        let guard = Guard::default();
        let binding = Binding::new("alpha", "alice").unwrap();
        let mut keys = machine(&support::Memory::default(), &Time::default(), &guard, 3);
        create(&mut keys, &guard, &prf(3), &binding).await;
        let handle = Contacts::key(&mut keys).await.unwrap();
        let mut store = store(3).await;
        let inbox = Inbox::new(binding);
        let contacts = inbox.contacts(&store).unwrap();
        assert_eq!(
            contacts.relation("bob").unwrap().state,
            ContactState::Unknown
        );
        assert!(contacts.blocking_rules().unwrap().is_empty());

        let closed = contacts
            .apply("bob", OwnAction::Close, &mut keys, &handle, &mut store)
            .await
            .unwrap();
        assert_eq!(closed.relation("bob").unwrap().state, ContactState::Closed);
        assert!(closed.blocking_rules().unwrap().is_empty());

        let blocked = closed
            .apply("bob", OwnAction::Block, &mut keys, &handle, &mut store)
            .await
            .unwrap();
        assert_eq!(
            blocked.relation("bob").unwrap().state,
            ContactState::Blocked
        );
        assert_eq!(blocked.blocking_rules().unwrap(), vec!["bob".to_string()]);

        let reloaded = inbox.contacts(&store).unwrap();
        assert_eq!(
            reloaded.relation("bob").unwrap().state,
            ContactState::Blocked
        );
        assert_eq!(
            reloaded.export_journal().unwrap(),
            blocked.export_journal().unwrap()
        );

        // Closing never lifts a block.
        let still = reloaded
            .apply("bob", OwnAction::Close, &mut keys, &handle, &mut store)
            .await
            .unwrap();
        assert_eq!(still.relation("bob").unwrap().state, ContactState::Blocked);

        // Only an explicit fresh reopening leaves Blocked, and a conversation id
        // is never reused for a later reopening.
        let reopened = still
            .apply(
                "bob",
                OwnAction::Reopen {
                    conversation: [9; 32],
                },
                &mut keys,
                &handle,
                &mut store,
            )
            .await
            .unwrap();
        let relation = reopened.relation("bob").unwrap();
        assert_eq!(relation.state, ContactState::Pending);
        assert_eq!(relation.conversation, Some([9; 32]));
        let again = reopened
            .apply("bob", OwnAction::Block, &mut keys, &handle, &mut store)
            .await
            .unwrap();
        assert_eq!(
            again
                .apply(
                    "bob",
                    OwnAction::Reopen {
                        conversation: [9; 32]
                    },
                    &mut keys,
                    &handle,
                    &mut store
                )
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Transition))
        );
        // A peer that is not a valid scoped identity, or the member itself, is refused.
        assert_eq!(
            again
                .apply("alice", OwnAction::Block, &mut keys, &handle, &mut store)
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Scope))
        );
    });
}
