//! Peer lineage-record handles: retained only from a verified signed announcement.
//! Test issuers are not production G3 authority.
mod support;
use ckmg::{Binding, Lineage};
use cnbx::{Error, HandleAnnouncement};
use ctcs::{Action, DeviceAuthority, OutcomeAuthority};
use cwst::{Store, backend::Memory};
use futures::executor::block_on;
use support::{Guard, Time, create, machine, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const CONVERSATION: [u8; 32] = [5; 32];

struct Peer(Option<Lineage>, bool);
impl DeviceAuthority for Peer {
    async fn current(&mut self, _: &Binding) -> Result<Lineage, ctcs::Error> {
        match (&self.0, self.1) {
            (Some(lineage), _) => Ok(lineage.clone()),
            (None, true) => Err(ctcs::Error::Authority),
            (None, false) => Err(ctcs::Error::Unavailable),
        }
    }
}
struct Own(Lineage);
impl DeviceAuthority for Own {
    async fn current(&mut self, _: &Binding) -> Result<Lineage, ctcs::Error> {
        Ok(self.0.clone())
    }
}
struct Answers;
impl OutcomeAuthority for Answers {
    async fn answered(
        &mut self,
        _: &Binding,
        _: &str,
        _: &[u8; 32],
        _: &[u8],
    ) -> Result<(), ctcs::Error> {
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_handle_is_retained_only_from_a_signed_announcement_under_the_peers_lineage() {
    block_on(async {
        let alice = Binding::new("alpha", "alice").unwrap();
        let bob = Binding::new("alpha", "bob").unwrap();
        let (guard_a, guard_b) = (Guard::default(), Guard::default());
        let mut keys_a = machine(&support::Memory::default(), &Time::default(), &guard_a, 5);
        create(&mut keys_a, &guard_a, &prf(5), &alice).await;
        let mut keys_b = machine(&support::Memory::default(), &Time::default(), &guard_b, 6);
        create(&mut keys_b, &guard_b, &prf(6), &bob).await;
        let key_a = keys_a.key(ctcs::purpose()).await.unwrap();
        let key_b = keys_b.key(ctcs::purpose()).await.unwrap();
        let lineage_b = keys_b.lineage().await.unwrap();
        let lineage_a = keys_a.lineage().await.unwrap();

        let cipher = ckmg::passkey::store_cipher(&prf(5), "alpha").unwrap();
        let mut store = Store::create(Memory::new(), &cipher, "alpha")
            .await
            .unwrap();
        let contacts = ctcs::Contacts::load(alice.clone(), &store).unwrap();
        // Begin a Pending relation with bob (own-signed).
        let event = contacts
            .request(
                "bob",
                Action::Begin {
                    conversation: CONVERSATION,
                },
            )
            .unwrap();
        let certificate = key_a.certificate().clone();
        let signature = keys_a
            .sign(&key_a, &event.signing_bytes(&certificate).unwrap())
            .await
            .unwrap();
        let mut own = Own(lineage_a);
        contacts
            .prepare(event.signed(certificate, signature), &mut own, &mut Answers)
            .await
            .unwrap()
            .commit((&mut own, &mut Answers), &mut store, [1; 32], &[], &[])
            .await
            .unwrap();
        let contacts = cnbx::Inbox::new(alice.clone()).contacts(&store).unwrap();
        assert_eq!(contacts.handle("bob").unwrap(), None);

        let announcement = HandleAnnouncement::sign(
            &mut keys_b,
            &key_b,
            &bob,
            CONVERSATION,
            b"bob-record-v1".to_vec(),
        )
        .await
        .unwrap();
        // Missing evidence stays Unavailable; present negative evidence is Authority.
        let mut gone = Peer(None, false);
        assert_eq!(
            contacts
                .retain_handle(&announcement, &mut gone, &mut keys_a, &key_a, &mut store)
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Unavailable))
        );
        let mut negative = Peer(None, true);
        assert_eq!(
            contacts
                .retain_handle(
                    &announcement,
                    &mut negative,
                    &mut keys_a,
                    &key_a,
                    &mut store
                )
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Authority))
        );
        // A lineage that is not bob's cannot vouch for bob's certificate.
        let mut impostor = Peer(Some(keys_a.lineage().await.unwrap()), false);
        assert_eq!(
            contacts
                .retain_handle(
                    &announcement,
                    &mut impostor,
                    &mut keys_a,
                    &key_a,
                    &mut store
                )
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Authority))
        );
        // A tampered handle breaks the signature.
        let mut forged: serde_json::Value = serde_json::to_value(&announcement).unwrap();
        forged["handle"] = serde_json::json!(b"attacker-record".to_vec());
        let forged: HandleAnnouncement = serde_json::from_value(forged).unwrap();
        let mut bobs = Peer(Some(lineage_b.clone()), false);
        assert_eq!(
            contacts
                .retain_handle(&forged, &mut bobs, &mut keys_a, &key_a, &mut store)
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Authority))
        );
        // A different conversation is not this relation.
        let other = HandleAnnouncement::sign(
            &mut keys_b,
            &key_b,
            &bob,
            [6; 32],
            b"bob-record-v1".to_vec(),
        )
        .await
        .unwrap();
        assert_eq!(
            contacts
                .retain_handle(&other, &mut bobs, &mut keys_a, &key_a, &mut store)
                .await
                .err(),
            Some(Error::Contacts(ctcs::Error::Transition))
        );
        // The genuine announcement is retained; a replacement needs a fresh one.
        let contacts = contacts
            .retain_handle(&announcement, &mut bobs, &mut keys_a, &key_a, &mut store)
            .await
            .unwrap();
        assert_eq!(
            contacts.handle("bob").unwrap().as_deref(),
            Some(&b"bob-record-v1"[..])
        );
        let moved = HandleAnnouncement::sign(
            &mut keys_b,
            &key_b,
            &bob,
            CONVERSATION,
            b"bob-record-v2".to_vec(),
        )
        .await
        .unwrap();
        let contacts = contacts
            .retain_handle(&moved, &mut bobs, &mut keys_a, &key_a, &mut store)
            .await
            .unwrap();
        assert_eq!(
            contacts.handle("bob").unwrap().as_deref(),
            Some(&b"bob-record-v2"[..])
        );
    });
}
