//! The production direct authority against real Contacts journals. Test issuers
//! are not production G3 or Waves accounting.
mod support;
use ckmg::{Binding, Lineage};
use cnbx::ContactAuthority;
use ctcs::{Action, Contacts, DeviceAuthority, OutcomeAuthority};
use cthr::{DirectAuthority, Error, Operation};
use cwst::{Store, backend::Memory};
use futures::executor::block_on;
use std::collections::BTreeMap;
use support::{Guard, Time, create, machine, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const CONVERSATION: [u8; 32] = [5; 32];

#[derive(Default)]
struct Directory(BTreeMap<String, Lineage>);
impl DeviceAuthority for Directory {
    async fn current(&mut self, binding: &Binding) -> Result<Lineage, ctcs::Error> {
        self.0
            .get(binding.member())
            .cloned()
            .ok_or(ctcs::Error::Unavailable)
    }
}
// Stand-in for the Waves-backed outcome authority, used only to reach Established.
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

async fn apply(
    contacts: &Contacts,
    keys: &mut support::Machine,
    handle: &ckmg::KeyHandle,
    store: &mut Store<Memory>,
    action: Action,
    operation: u8,
) -> Contacts {
    let event = contacts.request("bob", action).unwrap();
    let certificate = handle.certificate().clone();
    let signature = keys
        .sign(handle, &event.signing_bytes(&certificate).unwrap())
        .await
        .unwrap();
    let signed = event.signed(certificate, signature);
    let lineage = keys.lineage().await.unwrap();
    let mut own = Directory(BTreeMap::from([("alice".to_string(), lineage)]));
    contacts
        .prepare(signed, &mut own, &mut Answers)
        .await
        .unwrap()
        .commit((&mut own, &mut Answers), store, [operation; 32], &[], &[])
        .await
        .unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn only_an_established_matching_contact_with_current_peer_lineage_is_authorized() {
    block_on(async {
        let guard = Guard::default();
        let alice = Binding::new("alpha", "alice").unwrap();
        let mut keys = machine(&support::Memory::default(), &Time::default(), &guard, 5);
        create(&mut keys, &guard, &prf(5), &alice).await;
        let handle = keys.key(ctcs::purpose()).await.unwrap();
        let cipher = ckmg::passkey::store_cipher(&prf(5), "alpha").unwrap();
        let mut store = Store::create(Memory::new(), &cipher, "alpha")
            .await
            .unwrap();
        let bob_lineage = {
            let guard = Guard::default();
            let binding = Binding::new("alpha", "bob").unwrap();
            let mut bob = machine(&support::Memory::default(), &Time::default(), &guard, 6);
            create(&mut bob, &guard, &prf(6), &binding).await;
            bob.lineage().await.unwrap()
        };
        let mut peers = Directory(BTreeMap::from([("bob".to_string(), bob_lineage.clone())]));
        let op = Operation::Send;

        let contacts = Contacts::load(alice.clone(), &store).unwrap();
        let mut gate = ContactAuthority::new(&contacts, &mut peers);
        assert_eq!(
            gate.authorize(&alice, "bob", &CONVERSATION, op).await,
            Err(Error::Authority)
        );

        let pending = apply(
            &contacts,
            &mut keys,
            &handle,
            &mut store,
            Action::Begin {
                conversation: CONVERSATION,
            },
            1,
        )
        .await;
        let mut gate = ContactAuthority::new(&pending, &mut peers);
        assert_eq!(
            gate.authorize(&alice, "bob", &CONVERSATION, op).await,
            Err(Error::Authority)
        );

        let answered = apply(
            &pending,
            &mut keys,
            &handle,
            &mut store,
            Action::Answered {
                conversation: CONVERSATION,
                evidence: vec![1],
            },
            2,
        )
        .await;
        let mut gate = ContactAuthority::new(&answered, &mut peers);
        for op in [Operation::Establish, Operation::Send, Operation::Receive] {
            assert_eq!(
                gate.authorize(&alice, "bob", &CONVERSATION, op).await,
                Ok(())
            );
        }
        assert_eq!(
            gate.authorize(&alice, "bob", &[6; 32], op).await,
            Err(Error::Authority)
        );
        let other = Binding::new("alpha", "carol").unwrap();
        assert_eq!(
            gate.authorize(&other, "bob", &CONVERSATION, op).await,
            Err(Error::Authority)
        );

        // A peer whose current lineage is unavailable is Unavailable, never permissive.
        let mut nobody = Directory::default();
        let mut gate = ContactAuthority::new(&answered, &mut nobody);
        assert_eq!(
            gate.authorize(&alice, "bob", &CONVERSATION, op).await,
            Err(Error::Unavailable)
        );
        // A lineage for another binding is refused.
        let mut wrong = Directory(BTreeMap::from([(
            "bob".to_string(),
            keys.lineage().await.unwrap(),
        )]));
        let mut gate = ContactAuthority::new(&answered, &mut wrong);
        assert_eq!(
            gate.authorize(&alice, "bob", &CONVERSATION, op).await,
            Err(Error::Authority)
        );

        // A committed block takes effect for the next call.
        let blocked = apply(&answered, &mut keys, &handle, &mut store, Action::Block, 3).await;
        let mut gate = ContactAuthority::new(&blocked, &mut peers);
        assert_eq!(
            gate.authorize(&alice, "bob", &CONVERSATION, op).await,
            Err(Error::Authority)
        );
    });
}
