//! Waves journal through the facade. Positive proof transitions need Wallet's
//! real extension capabilities and are covered by the owner's own vectors.
mod support;
use ckmg::Binding;
use cnbx::{Error, Inbox, WaveContext, WaveState};
use cwst::{Store, backend::Memory};
use futures::executor::block_on;
use sha2::{Digest, Sha256};
use support::{Time, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const ALICE: [u8; 32] = [1; 32];
const BOB: [u8; 32] = [2; 32];

fn pair() -> (WaveContext, WaveContext) {
    let community: [u8; 32] = Sha256::digest(b"alpha").into();
    let sender = WaveContext {
        community,
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
fn offer_is_checkpointed_retained_and_never_replayed() {
    block_on(async {
        let cipher = ckmg::passkey::store_cipher(&prf(4), "alpha").unwrap();
        let mut store = Store::create(Memory::new(), &cipher, "alpha")
            .await
            .unwrap();
        let inbox = Inbox::new(Binding::new("alpha", "alice").unwrap());
        assert_eq!(
            inbox.waves([0; 32], &store).err(),
            Some(Error::Waves(cwvs::Error::Scope))
        );
        let waves = inbox.waves(ALICE, &store).unwrap();
        assert!(waves.reservations().is_empty());

        let (sender, recipient) = pair();
        let mut time = Time::default();
        let waves = waves
            .prepare_offer(sender.clone(), recipient.clone(), &mut time)
            .unwrap()
            .commit(&mut store, [11; 32], &mut time)
            .await
            .unwrap();
        let views = waves.reservations();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].state, WaveState::Prepared);
        assert_eq!(views[0].nonce, sender.nonce);

        // A restart sees the exact retained offer, with its original deadlines.
        let reloaded = inbox.waves(ALICE, &store).unwrap();
        let (kept_sender, kept_recipient) = reloaded.offer(&sender.nonce).unwrap();
        assert_eq!(kept_sender, &sender);
        assert_eq!(kept_recipient, &recipient);

        // The same nonce or challenge never identifies a fresh offer.
        assert_eq!(
            reloaded.prepare_offer(sender, recipient, &mut time).err(),
            Some(Error::Waves(cwvs::Error::Replay))
        );
    });
}
