//! Real OpenMLS and scoped Keys vectors. Test issuers are not production G3/G2.
#[path = "support/dropped_facade_candidates.rs"]
mod dropped_facade_candidates;
mod support;
use cdlv::Status;
use ckmg::{Binding, KeyHandle, Lineage};
use cnbx::Inbox;
use ctcs::DeviceAuthority;
use cthr::{DirectAuthority, Error, Event, Operation, Threads, keys::KeyPort};
use cwst::{Store, backend::Memory};
use ed25519_dalek::{Signer, SigningKey};
use futures::executor::block_on;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use support::{Guard, Machine, Time, create, machine, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
const SLOT: [u8; 32] = [17; 32];
#[derive(Clone, Default)]
struct Directory(Rc<RefCell<BTreeMap<String, Lineage>>>);
impl DeviceAuthority for Directory {
    async fn current(&mut self, binding: &Binding) -> Result<Lineage, ctcs::Error> {
        self.0
            .borrow()
            .get(binding.member())
            .filter(|lineage| lineage.binding == *binding)
            .cloned()
            .ok_or(ctcs::Error::Authority)
    }
}
// An independent fixture signs exact participants and conversation. The adapter
// verifies it for every operation; it is not a production accounting substitute.
struct Grant {
    bytes: Vec<u8>,
    signature: [u8; 64],
}
impl Grant {
    fn new() -> Self {
        let bytes =
            serde_json::to_vec(&("test.direct.authorization", "alpha", "alice", "bob", SLOT))
                .unwrap();
        Self {
            signature: SigningKey::from_bytes(&[77; 32]).sign(&bytes).to_bytes(),
            bytes,
        }
    }
}
impl DirectAuthority for Grant {
    async fn authorize(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        _: Operation,
    ) -> cthr::Result<()> {
        let (a, b) = if binding.member() < peer {
            (binding.member(), peer)
        } else {
            (peer, binding.member())
        };
        let expected = serde_json::to_vec(&(
            "test.direct.authorization",
            binding.community(),
            a,
            b,
            conversation,
        ))
        .unwrap();
        if expected != self.bytes {
            return Err(Error::Authority);
        }
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes(),
            &expected,
            &self.signature,
        )
        .map_err(|_| Error::Authority)
    }
}
struct Fixture {
    keys: Machine,
    handle: KeyHandle,
    binding: Binding,
    directory: Directory,
    seed: u8,
}
impl Fixture {
    async fn new(member: &str, seed: u8, directory: Directory) -> Self {
        let guard = Guard::default();
        let binding = Binding::new("alpha", member).unwrap();
        let mut keys = machine(&support::Memory::default(), &Time::default(), &guard, seed);
        create(&mut keys, &guard, &prf(seed), &binding).await;
        let handle = keys.key(cthr::purpose()).await.unwrap();
        directory
            .0
            .borrow_mut()
            .insert(member.into(), guard.0.borrow()["alpha"].clone());
        Self {
            keys,
            handle,
            binding,
            directory,
            seed,
        }
    }
    fn port(&mut self) -> KeyPort<'_, support::Memory, Time, support::Random, Guard, Directory> {
        KeyPort {
            keys: &mut self.keys,
            handle: &self.handle,
            devices: &mut self.directory,
        }
    }
    async fn store(&self) -> (Memory, Store<Memory>) {
        let backend = Memory::new();
        let cipher = ckmg::passkey::store_cipher(&prf(self.seed), "alpha").unwrap();
        let store = Store::create(backend.clone(), &cipher, "alpha")
            .await
            .unwrap();
        (backend, store)
    }
}

// Synthetic signed Waves receipt, used only to establish the test contacts.
// It exercises the owner boundary; it is not accepted production accounting.
struct Answers;
fn answer_bytes(binding: &Binding, peer: &str, id: &[u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&("fixture.answer", binding, peer, id)).unwrap()
}
impl ctcs::OutcomeAuthority for Answers {
    async fn answered(
        &mut self,
        b: &Binding,
        p: &str,
        id: &[u8; 32],
        proof: &[u8],
    ) -> Result<(), ctcs::Error> {
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[72; 32]).verifying_key().to_bytes(),
            &answer_bytes(b, p, id),
            &proof.try_into().map_err(|_| ctcs::Error::Authority)?,
        )
        .map_err(|_| ctcs::Error::Authority)
    }
}
impl Fixture {
    async fn establish(&mut self, peer: &str, store: &mut Store<Memory>) {
        let handle = self.keys.key(ctcs::purpose()).await.unwrap();
        let proof = SigningKey::from_bytes(&[72; 32])
            .sign(&answer_bytes(&self.binding, peer, &SLOT))
            .to_bytes()
            .to_vec();
        for (index, action) in [
            ctcs::Action::Begin { conversation: SLOT },
            ctcs::Action::Answered {
                conversation: SLOT,
                evidence: proof,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let contacts = ctcs::Contacts::load(self.binding.clone(), store).unwrap();
            let event = contacts.request(peer, action).unwrap();
            let cert = handle.certificate().clone();
            let signature = self
                .keys
                .sign(&handle, &event.signing_bytes(&cert).unwrap())
                .await
                .unwrap();
            contacts
                .prepare(
                    event.signed(cert, signature),
                    &mut self.directory,
                    &mut Answers,
                )
                .await
                .unwrap()
                .commit(
                    (&mut self.directory, &mut Answers),
                    store,
                    [(index + 100) as u8; 32],
                    &[],
                    &[],
                )
                .await
                .unwrap();
        }
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn established_message_uses_real_owners_through_the_facade() {
    block_on(async {
        let mut directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let ah = a.keys.key(cdlv::purpose()).await.unwrap();
        let bh = b.keys.key(cdlv::purpose()).await.unwrap();
        let (_, mut astore) = a.store().await;
        let (_, mut bstore) = b.store().await;
        let ai = Inbox::new(a.binding.clone());
        let bi = Inbox::new(b.binding.clone());
        let empty = ai.view(SLOT, &astore).unwrap();
        assert!(empty.history().is_empty());
        assert_eq!(empty.delivery_status(&[0; 32]), None);
        assert_eq!(empty.relation("bob").unwrap().state, ctcs::State::Unknown);
        assert!(empty.relation("alice").is_err());
        assert!(
            Inbox::new(Binding::new("foreign", "alice").unwrap())
                .view(SLOT, &astore)
                .is_err()
        );
        assert!(ai.view([0; 32], &astore).is_err());
        assert!(
            empty
                .send(&mut a.port(), &mut cthr::Unavailable, b"no proof")
                .await
                .is_err()
        );
        a.establish("bob", &mut astore).await;
        b.establish("alice", &mut bstore).await;
        // Real owner-authorized direct setup. Production Wave release is still
        // unavailable; this signed fixture does not claim G2/G3/G5 acceptance.
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let package = bt
            .key_package(&mut b.port())
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [1; 32], &[])
            .await
            .unwrap();
        let Event::KeyPackage { bytes } = &package.events()[0] else {
            panic!()
        };
        let invitation = at
            .create_direct(&mut a.port(), &mut Grant::new(), "bob", bytes)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [1; 32], &[])
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &invitation.events()[0] else {
            panic!()
        };
        package
            .threads()
            .join_direct(&mut b.port(), &mut Grant::new(), "alice", welcome)
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [2; 32], &[])
            .await
            .unwrap();
        let pending = ai
            .view(SLOT, &astore)
            .unwrap()
            .send(&mut a.port(), &mut Grant::new(), b"facade hello")
            .await
            .unwrap();
        assert!(ai.view(SLOT, &astore).unwrap().history().is_empty());
        let sent = pending
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [3; 32],
            )
            .await
            .unwrap();
        let id = sent.outgoing_ids()[0];
        assert_eq!(sent.delivery_status(&id), Some(Status::Pending));
        assert!(sent.history().is_empty());
        assert!(sent.receipt(&id).is_err());
        let wire = sent
            .outgoing(&mut a.keys, &ah, &mut directory, &mut astore, [4; 32])
            .await
            .unwrap();
        assert_eq!(
            bi.view(SLOT, &bstore)
                .unwrap()
                .acknowledge(wire.bytes(), &mut directory)
                .await
                .err(),
            Some(cnbx::Error::UnexpectedMessage)
        );
        let cnbx::Receive::Pending(receiving) = bi
            .view(SLOT, &bstore)
            .unwrap()
            .receive(
                wire.bytes(),
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
        let prepared = receiving.prepare_receipt(&mut b.keys, &bh).await.unwrap();
        assert!(bi.view(SLOT, &bstore).unwrap().history().is_empty());
        let received = prepared
            .commit(
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
                &mut bstore,
                [3; 32],
            )
            .await
            .unwrap();
        assert_eq!(received.history()[0].bytes, b"facade hello");
        assert!(received.outgoing_ids().is_empty());
        assert_eq!(
            received
                .outgoing(&mut b.keys, &bh, &mut directory, &mut bstore, [4; 32])
                .await
                .err(),
            Some(cnbx::Error::UnexpectedMessage)
        );
        let receipt = received.receipt(&id).unwrap();
        assert_eq!(
            ai.view(SLOT, &astore)
                .unwrap()
                .receive(
                    receipt.bytes(),
                    &mut a.port(),
                    &mut Grant::new(),
                    &mut directory
                )
                .await
                .err(),
            Some(cnbx::Error::UnexpectedMessage)
        );
        let cnbx::Acknowledgement::Pending(pending) = ai
            .view(SLOT, &astore)
            .unwrap()
            .acknowledge(receipt.bytes(), &mut directory)
            .await
            .unwrap()
        else {
            panic!()
        };
        let accepted = pending
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [5; 32],
            )
            .await
            .unwrap();
        assert_eq!(accepted.delivery_status(&id), Some(Status::Accepted));
        assert_eq!(accepted.history()[0].bytes, b"facade hello");
        match bi
            .view(SLOT, &bstore)
            .unwrap()
            .receive(
                wire.bytes(),
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
            )
            .await
            .unwrap()
        {
            cnbx::Receive::Duplicate(repeated) => assert_eq!(repeated.bytes(), receipt.bytes()),
            _ => panic!("no second decryption"),
        }
        match ai
            .view(SLOT, &astore)
            .unwrap()
            .acknowledge(receipt.bytes(), &mut directory)
            .await
            .unwrap()
        {
            cnbx::Acknowledgement::AlreadyAccepted(message) => assert_eq!(message, id),
            _ => panic!("no second history checkpoint"),
        }
        let current = ai.view(SLOT, &astore).unwrap();
        assert_eq!(
            current.relation("bob").unwrap().state,
            ctcs::State::Established
        );
        assert_eq!(current.delivery_status(&id), Some(Status::Accepted));
    });
}
