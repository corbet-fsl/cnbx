use super::*;

async fn reopen(backend: &Memory, seed: u8) -> Store<Memory> {
    let cipher = ckmg::passkey::store_cipher(&prf(seed), "alpha").unwrap();
    Store::open(backend.clone(), &cipher, "alpha")
        .await
        .unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn dropped_receiving_and_pending_ack_retry_same_wire_and_ack() {
    block_on(async {
        let mut directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let ah = a.keys.key(cdlv::purpose()).await.unwrap();
        let bh = b.keys.key(cdlv::purpose()).await.unwrap();
        let (abackend, mut astore) = a.store().await;
        let (bbackend, mut bstore) = b.store().await;
        let ai = Inbox::new(a.binding.clone());
        let bi = Inbox::new(b.binding.clone());

        // Owner-only connection setup; existing signed fixture authority only.
        a.establish("bob", &mut astore).await;
        b.establish("alice", &mut bstore).await;
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let package = bt
            .key_package(&mut b.port())
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [11; 32], &[])
            .await
            .unwrap();
        let Event::KeyPackage { bytes } = &package.events()[0] else {
            panic!()
        };
        let invitation = at
            .create_direct(&mut a.port(), &mut Grant::new(), "bob", bytes)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [11; 32], &[])
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
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [12; 32], &[])
            .await
            .unwrap();

        // Committed sender wire; the exact bytes retried after every drop.
        let sent = ai
            .view(SLOT, &astore)
            .unwrap()
            .send(&mut a.port(), &mut Grant::new(), b"drop retry")
            .await
            .unwrap()
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [13; 32],
            )
            .await
            .unwrap();
        let id = sent.outgoing_ids()[0];
        let wire = sent
            .outgoing(&mut a.keys, &ah, &mut directory, &mut astore, [14; 32])
            .await
            .unwrap();
        let wire_bytes = wire.bytes().to_vec();

        let recipient_before = bstore.version().unwrap();
        // Drop 1: authenticated Receiving exposes nothing.
        let cnbx::Receive::Pending(receiving) = bi
            .view(SLOT, &bstore)
            .unwrap()
            .receive(
                &wire_bytes,
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
        drop(receiving);
        bstore = reopen(&bbackend, 2).await;
        assert_eq!(bstore.version().unwrap(), recipient_before);
        let fresh = bi.view(SLOT, &bstore).unwrap();
        assert!(fresh.history().is_empty());
        assert_eq!(fresh.delivery_status(&id), None);

        // Ratchet not consumed: same wire re-receives as Pending, not Duplicate.
        let cnbx::Receive::Pending(receiving) = bi
            .view(SLOT, &bstore)
            .unwrap()
            .receive(
                &wire_bytes,
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
            )
            .await
            .unwrap()
        else {
            panic!("ratchet consumed by dropped Receiving")
        };

        // Drop 2: prepared recipient Pending receipt exposes nothing.
        let prepared = receiving.prepare_receipt(&mut b.keys, &bh).await.unwrap();
        drop(prepared);
        bstore = reopen(&bbackend, 2).await;
        assert_eq!(bstore.version().unwrap(), recipient_before);
        let fresh = bi.view(SLOT, &bstore).unwrap();
        assert!(fresh.history().is_empty());
        assert_eq!(fresh.delivery_status(&id), None);

        // Same wire still live: prepare and commit exactly once.
        let cnbx::Receive::Pending(receiving) = bi
            .view(SLOT, &bstore)
            .unwrap()
            .receive(
                &wire_bytes,
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
            )
            .await
            .unwrap()
        else {
            panic!("ratchet consumed by dropped Pending")
        };
        let received = receiving
            .prepare_receipt(&mut b.keys, &bh)
            .await
            .unwrap()
            .commit(
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
                &mut bstore,
                [13; 32],
            )
            .await
            .unwrap();
        assert_eq!(received.history()[0].bytes, b"drop retry");
        let receipt = received.receipt(&id).unwrap();
        let receipt_bytes = receipt.bytes().to_vec();

        let sender_before = astore.version().unwrap();
        // Drop 3: authenticated sender Pending ACK exposes no acceptance.
        let cnbx::Acknowledgement::Pending(pending) = ai
            .view(SLOT, &astore)
            .unwrap()
            .acknowledge(&receipt_bytes, &mut directory)
            .await
            .unwrap()
        else {
            panic!()
        };
        drop(pending);
        astore = reopen(&abackend, 1).await;
        assert_eq!(astore.version().unwrap(), sender_before);
        let fresh = ai.view(SLOT, &astore).unwrap();
        assert!(fresh.history().is_empty());
        assert_eq!(fresh.delivery_status(&id), Some(Status::Pending));

        // Same ACK accepted exactly once after reopen.
        let cnbx::Acknowledgement::Pending(pending) = ai
            .view(SLOT, &astore)
            .unwrap()
            .acknowledge(&receipt_bytes, &mut directory)
            .await
            .unwrap()
        else {
            panic!("ACK consumed by dropped Pending")
        };
        let accepted = pending
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [15; 32],
            )
            .await
            .unwrap();
        assert_eq!(accepted.delivery_status(&id), Some(Status::Accepted));

        // Reopen both encrypted stores; exactly one unique plaintext/ID.
        astore = reopen(&abackend, 1).await;
        bstore = reopen(&bbackend, 2).await;
        let aview = ai.view(SLOT, &astore).unwrap();
        let bview = bi.view(SLOT, &bstore).unwrap();
        assert_eq!(aview.history().len(), 1);
        assert_eq!(bview.history().len(), 1);
        assert_eq!(aview.history()[0].bytes, b"drop retry");
        assert_eq!(bview.history()[0].bytes, b"drop retry");
        assert_eq!(aview.delivery_status(&id), Some(Status::Accepted));
        assert_eq!(aview.history()[0].id, id);
        assert_eq!(bview.history()[0].id, id);
        assert_eq!(bview.delivery_status(&id), Some(Status::Accepted));
        let sender_version = astore.version().unwrap();
        let recipient_version = bstore.version().unwrap();

        // Duplicate data read returns the exact original receipt, no new history.
        match bi
            .view(SLOT, &bstore)
            .unwrap()
            .receive(
                &wire_bytes,
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
            )
            .await
            .unwrap()
        {
            cnbx::Receive::Duplicate(repeated) => {
                assert_eq!(repeated.bytes(), receipt_bytes.as_slice())
            }
            _ => panic!("no second decryption"),
        }

        // Duplicate ACK reports the exact ID, no new transition.
        match ai
            .view(SLOT, &astore)
            .unwrap()
            .acknowledge(&receipt_bytes, &mut directory)
            .await
            .unwrap()
        {
            cnbx::Acknowledgement::AlreadyAccepted(message) => assert_eq!(message, id),
            _ => panic!("no second history checkpoint"),
        }

        // Duplicate reads leave both persisted Store versions unchanged.
        astore = reopen(&abackend, 1).await;
        bstore = reopen(&bbackend, 2).await;
        let aview = ai.view(SLOT, &astore).unwrap();
        let bview = bi.view(SLOT, &bstore).unwrap();
        assert_eq!(astore.version().unwrap(), sender_version);
        assert_eq!(bstore.version().unwrap(), recipient_version);
        assert_eq!(bview.history().len(), 1);
        assert_eq!(aview.history()[0].id, id);
        assert_eq!(bview.history()[0].id, id);
        assert_eq!(bview.history()[0].bytes, b"drop retry");
        assert_eq!(aview.history().len(), 1);
        assert_eq!(aview.delivery_status(&id), Some(Status::Accepted));
    });
}
