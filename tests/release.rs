//! Release preconditions and the Waves-backed Answer authority. The positive
//! sender and recipient releases need Wallet's verified reservations and
//! outcomes (not constructible without real proofs); every refusal below must
//! write nothing.
mod support;
use ckmg::Binding;
use cnbx::{Error, Inbox, OwnAction, OwnDevice, WaveContext, check_release};
use cwst::{Store, backend::Memory};
use futures::executor::block_on;
use sha2::{Digest, Sha256};
use support::{Guard, Time, create, machine, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const ALICE: [u8; 32] = [1; 32];
const BOB: [u8; 32] = [2; 32];

struct Stale;
impl ctcs::DeviceAuthority for Stale {
    async fn current(&mut self, _: &Binding) -> Result<ckmg::Lineage, ctcs::Error> {
        Err(ctcs::Error::Authority)
    }
}

fn pair() -> (WaveContext, WaveContext) {
    let sender = WaveContext {
        community: Sha256::digest(b"alpha").into(),
        owner: ALICE,
        peer: BOB,
        role: 0,
        nonce: [3; 32],
        group: [4; 32],
        contact_policy: [5; 32],
        history: [6; 32],
        challenge: [7; 32],
        opened_at: 900,
        expires_at: 5000,
        owner_authority: [8; 32],
        peer_authority: [9; 32],
    };
    let recipient = WaveContext {
        owner: BOB,
        peer: ALICE,
        role: 1,
        challenge: [10; 32],
        owner_authority: [9; 32],
        peer_authority: [8; 32],
        ..sender.clone()
    };
    (sender, recipient)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn refused_releases_write_nothing() {
    block_on(async {
        let alice = Binding::new("alpha", "alice").unwrap();
        let bob = Binding::new("alpha", "bob").unwrap();
        let (alice_guard, bob_guard) = (Guard::default(), Guard::default());
        let mut alice_keys = machine(
            &support::Memory::default(),
            &Time::default(),
            &alice_guard,
            3,
        );
        create(&mut alice_keys, &alice_guard, &prf(3), &alice).await;
        let mut bob_keys = machine(&support::Memory::default(), &Time::default(), &bob_guard, 4);
        create(&mut bob_keys, &bob_guard, &prf(4), &bob).await;
        let cipher = ckmg::passkey::store_cipher(&prf(3), "alpha").unwrap();
        let mut store = Store::create(Memory::new(), &cipher, "alpha")
            .await
            .unwrap();
        let inbox = Inbox::new(alice.clone());
        let (s, r) = pair();
        let offer = |store: &Store<Memory>| {
            inbox
                .waves(ALICE, store)
                .unwrap()
                .prepare_offer(s.clone(), r.clone(), &mut Time::default())
                .unwrap()
        };
        let version = store.version().unwrap();

        // Waves evidence that is not past Prepared is not a verified reservation.
        assert_eq!(
            check_release(
                &alice,
                "bob",
                [9; 32],
                offer(&store),
                &store,
                &mut OwnDevice(&mut bob_keys)
            )
            .await
            .err(),
            Some(Error::Waves(cwvs::Error::State))
        );
        // A stale or unavailable peer lineage refuses.
        assert_eq!(
            check_release(&alice, "bob", [9; 32], offer(&store), &store, &mut Stale)
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Authority))
        );
        // The member itself and malformed peers are refused.
        assert_eq!(
            check_release(&alice, "alice", [9; 32], offer(&store), &store, &mut Stale)
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Scope))
        );
        // A block in the journal refuses before any lineage is consulted.
        let handle = cnbx::Contacts::key(&mut alice_keys).await.unwrap();
        inbox
            .contacts(&store)
            .unwrap()
            .apply(
                "bob",
                OwnAction::Block,
                &mut alice_keys,
                &handle,
                &mut store,
            )
            .await
            .unwrap();
        let blocked_version = store.version().unwrap();
        assert!(blocked_version > version);
        assert_eq!(
            check_release(&alice, "bob", [9; 32], offer(&store), &store, &mut Stale)
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Transition))
        );
        assert_eq!(store.version().unwrap(), blocked_version);
        assert!(inbox.waves(ALICE, store).unwrap().reservations().is_empty());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn answered_needs_a_linked_wave_with_exactly_that_receipt() {
    use ctcs::OutcomeAuthority;
    block_on(async {
        let alice = Binding::new("alpha", "alice").unwrap();
        let cipher = ckmg::passkey::store_cipher(&prf(3), "alpha").unwrap();
        let store = Store::create(Memory::new(), &cipher, "alpha")
            .await
            .unwrap();
        let inbox = Inbox::new(alice.clone());
        let waves = inbox.waves(ALICE, &store).unwrap();
        let mut outcomes = inbox.outcomes(&waves);
        for evidence in [&[7u8; 32][..], &[7u8; 31][..], &[][..]] {
            assert_eq!(
                outcomes
                    .answered(&alice, &"ab".repeat(48), &[9; 32], evidence)
                    .await,
                Err(ctcs::Error::Authority)
            );
        }
        let other = Binding::new("alpha", "carol").unwrap();
        assert_eq!(
            outcomes
                .answered(&other, &"ab".repeat(48), &[9; 32], &[7; 32])
                .await,
            Err(ctcs::Error::Authority)
        );
        assert_eq!(
            outcomes.answered(&alice, "bob", &[9; 32], &[7; 32]).await,
            Err(ctcs::Error::Authority)
        );
    });
}
