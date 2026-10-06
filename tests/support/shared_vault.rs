//! The real Vault KeyStore and Inbox share ONE original encrypted Store.
//! Signed test admission/Answer authorities remain the explicit parent fixtures;
//! no replacement KeyStore, cached Custody or accepting production G3 is used.
use super::*;
use futures::FutureExt;

struct NoRecords;
impl cvlt::Records for NoRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
struct ExpiringAuthority {
    guard: Guard,
    clock: Time,
}
impl ckmg::Authority for ExpiringAuthority {
    async fn check(&mut self, request: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        if self.clock.0.get() >= 1100 {
            return Err(ckmg::Error::Unauthorized);
        }
        ckmg::Authority::check(&mut self.guard, request).await
    }
}
type TestVault = cvlt::Vault<Memory, Time, support::Random, ExpiringAuthority, NoRecords, ()>;
struct Member {
    vault: TestVault,
    backend: Memory,
    binding: Binding,
    handle: KeyHandle,
    delivery: KeyHandle,
    directory: Directory,
    seed: u8,
    clock: Time,
}
fn batch(expected: u64, operation: u8) -> cvlt::Batch {
    cvlt::Batch {
        expected,
        operation: [operation; 32],
        mutations: vec![],
        outputs: vec![],
    }
}
impl Member {
    async fn new(member: &str, seed: u8, directory: Directory) -> Self {
        let binding = Binding::new("alpha", member).unwrap();
        let backend = Memory::new();
        let cipher = ckmg::passkey::store_cipher(&prf(seed), "alpha").unwrap();
        let store = Store::create(backend.clone(), &cipher, "alpha")
            .await
            .unwrap();
        let guard = Guard::default();
        let clock = Time::default();
        let mut vault = cvlt::Vault::new(
            store,
            "alpha",
            clock.clone(),
            support::Random::new(seed),
            ExpiringAuthority {
                guard: guard.clone(),
                clock: clock.clone(),
            },
            NoRecords,
            (),
        )
        .unwrap();
        let armed = vault.stage_keys(batch(0, 70)).unwrap();
        let receipt = vault
            .keys()
            .create_scope(
                &prf(seed),
                binding.clone(),
                support::info(),
                &support::consent(ckmg::Action::Create, &binding, None, 0, None, None),
            )
            .await
            .unwrap();
        guard.publish(&receipt);
        drop(armed);
        let armed = vault.stage_keys(batch(1, 71)).unwrap();
        vault.keys().acknowledge(receipt.operation).await.unwrap();
        drop(armed);
        let handle = vault.keys().key(cthr::purpose()).await.unwrap();
        let delivery = vault.keys().key(cdlv::purpose()).await.unwrap();
        directory
            .0
            .borrow_mut()
            .insert(member.into(), guard.0.borrow()["alpha"].clone());
        Self {
            vault,
            backend,
            binding,
            handle,
            delivery,
            directory,
            seed,
            clock,
        }
    }
    fn port(
        &mut self,
    ) -> KeyPort<'_, cvlt::KeyStore<Memory>, Time, support::Random, ExpiringAuthority, Directory>
    {
        KeyPort {
            keys: self.vault.keys(),
            handle: &self.handle,
            devices: &mut self.directory,
        }
    }
    async fn view(&self) -> cnbx::View {
        let store = self.vault.storage().lock().await;
        Inbox::new(self.binding.clone()).view(SLOT, &store).unwrap()
    }
    async fn establish(&mut self, peer: &str) {
        let handle = self.vault.keys().key(ctcs::purpose()).await.unwrap();
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
            let contacts = {
                let store = self.vault.storage().lock().await;
                ctcs::Contacts::load(self.binding.clone(), &store).unwrap()
            };
            let event = contacts.request(peer, action).unwrap();
            let certificate = handle.certificate().clone();
            let signature = self
                .vault
                .keys()
                .sign(&handle, &event.signing_bytes(&certificate).unwrap())
                .await
                .unwrap();
            let candidate = contacts
                .prepare(
                    event.signed(certificate, signature),
                    &mut self.directory,
                    &mut Answers,
                )
                .await
                .unwrap();
            let storage = self.vault.storage().clone();
            let mut store = storage.lock().await;
            candidate
                .commit(
                    (&mut self.directory, &mut Answers),
                    &mut store,
                    [(index + 100) as u8; 32],
                    &[],
                    &[],
                )
                .await
                .unwrap();
        }
    }
}

// Memory backend and the original signed fixture authorities do not suspend.
// Bounded polling turns a reentrant mutex regression into an immediate failure.
fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    future
        .now_or_never()
        .expect("original Vault KeyStore must not re-lock the held Store")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn actual_vault_keys_and_inbox_share_one_checkpoint_without_relocking() {
    block_on(async {
        let mut directory = Directory::default();
        let mut alice = Member::new("alice", 31, directory.clone()).await;
        let mut bob = Member::new("bob", 32, directory.clone()).await;
        alice.establish("bob").await;
        bob.establish("alice").await;
        let a_storage = alice.vault.storage().clone();
        let b_storage = bob.vault.storage().clone();

        let package = bob.view().await.key_package(&mut bob.port()).await.unwrap();
        let package = {
            let mut store = b_storage.lock().await;
            ready(package.commit(&mut bob.port(), &mut Grant::new(), &mut store, [1; 32])).unwrap()
        };
        let Event::KeyPackage { bytes } = &package.events()[0] else {
            panic!("actual OpenMLS package required")
        };
        let invitation = alice
            .view()
            .await
            .create_direct(&mut alice.port(), &mut Grant::new(), "bob", bytes)
            .await
            .unwrap();
        let invitation = {
            let mut store = a_storage.lock().await;
            ready(invitation.commit(&mut alice.port(), &mut Grant::new(), &mut store, [1; 32]))
                .unwrap()
        };
        let Event::Invitation { welcome, .. } = &invitation.events()[0] else {
            panic!("actual OpenMLS welcome required")
        };
        let joined = bob
            .view()
            .await
            .join_direct(&mut bob.port(), &mut Grant::new(), "alice", welcome)
            .await
            .unwrap();
        {
            let mut store = b_storage.lock().await;
            ready(joined.commit(&mut bob.port(), &mut Grant::new(), &mut store, [2; 32])).unwrap();
        }
        let pending = alice
            .view()
            .await
            .send(&mut alice.port(), &mut Grant::new(), b"one real Vault")
            .await
            .unwrap();
        let rival = alice
            .view()
            .await
            .send(&mut alice.port(), &mut Grant::new(), b"competing candidate")
            .await
            .unwrap();
        let sent = {
            let mut store = a_storage.lock().await;
            let sent = ready(pending.commit(
                &mut alice.port(),
                &mut Grant::new(),
                &mut directory,
                &mut store,
                [3; 32],
            ))
            .unwrap();
            assert!(
                ready(rival.commit(
                    &mut alice.port(),
                    &mut Grant::new(),
                    &mut directory,
                    &mut store,
                    [30; 32],
                ))
                .is_err()
            );
            sent
        };
        let id = sent.outgoing_ids()[0];
        let wire = {
            let mut store = a_storage.lock().await;
            ready(sent.outgoing(
                alice.vault.keys(),
                &alice.delivery,
                &mut directory,
                &mut store,
                [4; 32],
            ))
            .unwrap()
        };
        let cnbx::Receive::Pending(receiving) = bob
            .view()
            .await
            .receive(
                wire.bytes(),
                &mut bob.port(),
                &mut Grant::new(),
                &mut directory,
            )
            .await
            .unwrap()
        else {
            panic!("actual authenticated delivery required")
        };
        let receipt = receiving
            .prepare_receipt(bob.vault.keys(), &bob.delivery)
            .await
            .unwrap();
        let received = {
            let mut store = b_storage.lock().await;
            ready(receipt.commit(
                &mut bob.port(),
                &mut Grant::new(),
                &mut directory,
                &mut store,
                [3; 32],
            ))
            .unwrap()
        };
        assert_eq!(received.history()[0].bytes, b"one real Vault");
        let acknowledgement = received.receipt(&id).unwrap();
        let cnbx::Acknowledgement::Pending(ack) = alice
            .view()
            .await
            .acknowledge(acknowledgement.bytes(), &mut directory)
            .await
            .unwrap()
        else {
            panic!("actual recipient acknowledgement required")
        };
        {
            let mut store = a_storage.lock().await;
            let accepted = ready(ack.commit(
                &mut alice.port(),
                &mut Grant::new(),
                &mut directory,
                &mut store,
                [5; 32],
            ))
            .unwrap();
            assert_eq!(accepted.delivery_status(&id), Some(Status::Accepted));
            assert_eq!(accepted.history()[0].bytes, b"one real Vault");
        }
        let expired_candidate = alice
            .view()
            .await
            .send(&mut alice.port(), &mut Grant::new(), b"expired authority")
            .await
            .unwrap();
        let locked_candidate = alice
            .view()
            .await
            .send(&mut alice.port(), &mut Grant::new(), b"must not publish")
            .await
            .unwrap();
        // Reproduce the exact owner ordering used by the facade: await the
        // original Store, then recheck Keys before disclosing a view. Authority
        // can expire while the read is queued; no cached successful verdict helps.
        let clock = alice.clock.clone();
        let held = a_storage.lock().await;
        let mut disclosure = Box::pin(async {
            let store = a_storage.lock().await;
            alice.vault.keys().lineage().await?;
            Ok::<_, ckmg::Error>(
                Inbox::new(alice.binding.clone())
                    .view(SLOT, &store)
                    .unwrap(),
            )
        });
        let waker = futures::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(std::future::Future::poll(disclosure.as_mut(), &mut context).is_pending());
        clock.0.set(1100);
        drop(held);
        assert!(matches!(ready(disclosure), Err(ckmg::Error::Unauthorized)));
        {
            let mut store = a_storage.lock().await;
            let version = store.version().unwrap();
            assert!(
                ready(expired_candidate.commit(
                    &mut alice.port(),
                    &mut Grant::new(),
                    &mut directory,
                    &mut store,
                    [60; 32],
                ))
                .is_err()
            );
            assert_eq!(store.version().unwrap(), version);
        }
        alice.vault.keys().lock();
        {
            let mut store = a_storage.lock().await;
            assert!(
                ready(locked_candidate.commit(
                    &mut alice.port(),
                    &mut Grant::new(),
                    &mut directory,
                    &mut store,
                    [6; 32],
                ))
                .is_err()
            );
        }
        bob.vault.lock().await;
        let cipher = ckmg::passkey::store_cipher(&prf(bob.seed), "alpha").unwrap();
        let reopened = Store::open(bob.backend, &cipher, "alpha").await.unwrap();
        let view = Inbox::new(bob.binding).view(SLOT, &reopened).unwrap();
        assert_eq!(view.history()[0].bytes, b"one real Vault");
        assert_eq!(view.delivery_status(&id), Some(Status::Accepted));
    });
}
