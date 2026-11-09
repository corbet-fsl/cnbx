//! Actual Inbox -> Groups -> OpenMLS -> encrypted Store publication. The signed
//! fixture registry is not production G3 or proof of a released first contact.
use super::*;
use cnbx::{Error as InboxError, GroupAction};

async fn package(fixture: &mut Fixture, store: &mut Store<Memory>, op: u8) -> Vec<u8> {
    let inbox = Inbox::new(fixture.binding.clone());
    let opened = inbox
        .view(SLOT, store)
        .unwrap()
        .key_package(&mut fixture.port())
        .await
        .unwrap()
        .commit(&mut fixture.port(), &mut Grant::new(), store, [op; 32])
        .await
        .unwrap();
    match &opened.events()[0] {
        Event::KeyPackage { bytes } => bytes.clone(),
        _ => panic!("expected committed key package"),
    }
}

struct Withdrawn;
impl cgrp::Authority for Withdrawn {
    fn consent(&self, _: &cgrp::Consent, _: u64) -> cgrp::Result<()> {
        Err(cgrp::Error::Authority)
    }
    fn contact(&self, _: &str, _: &str, _: &str, _: u64) -> cgrp::Result<()> {
        Err(cgrp::Error::Authority)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_three_member_consent_and_atomic_publication() {
    block_on(Box::pin(async {
        let directory = Directory::default();
        let mut a = Fixture::new("m0", 31, directory.clone()).await;
        let mut b = Fixture::new("m1", 32, directory.clone()).await;
        let mut c = Fixture::new("m2", 33, directory).await;
        let (backend, mut astore) = a.store().await;
        let (_, mut bstore) = b.store().await;
        let (_, mut cstore) = c.store().await;
        let packages = vec![
            package(&mut b, &mut bstore, 1).await,
            package(&mut c, &mut cstore, 1).await,
        ];
        let inbox = Inbox::new(a.binding.clone());
        let policy = group_authority::SignedPolicy::new(&group_authority::policy());
        let authority = group_authority::TestAuthority;
        let state = cgrp::Snapshot::load("alpha", &astore).unwrap();
        let request = group_authority::request(
            &state,
            cgrp::Command::Create {
                id: SLOT,
                members: group_authority::members(0, 3),
            },
            "m0",
            group_authority::members(0, 3),
            false,
            1000,
        );
        let mut clock = Time::default();
        let view = inbox.group(SLOT, &astore).unwrap();
        assert_eq!(view.revision(), 0);
        assert!(view.snapshot(&policy, 1000).is_err());
        let mut bad = request.clone();
        bad.consents[0].signature[0] ^= 1;
        assert!(matches!(
            view.prepare(
                &bad,
                GroupAction::Create {
                    packages: &packages
                },
                &mut a.port(),
                (&policy, &authority),
                &mut clock,
                128
            )
            .await,
            Err(InboxError::Groups(cgrp::Error::Authority))
        ));
        let before = astore.version().unwrap();
        let abandoned = view
            .prepare(
                &request,
                GroupAction::Create {
                    packages: &packages,
                },
                &mut a.port(),
                (&policy, &authority),
                &mut clock,
                128,
            )
            .await
            .unwrap();
        drop(abandoned);
        assert_eq!(astore.version().unwrap(), before);
        assert!(astore.load_pending().unwrap().is_empty());
        let stale = view
            .prepare(
                &request,
                GroupAction::Create {
                    packages: &packages,
                },
                &mut a.port(),
                (&policy, &authority),
                &mut clock,
                128,
            )
            .await
            .unwrap();
        assert!(matches!(
            stale
                .commit(
                    &mut a.port(),
                    &mut astore,
                    (&policy, &Withdrawn),
                    &mut clock
                )
                .await,
            Err(InboxError::Threads(Error::Authority))
        ));
        assert_eq!(astore.version().unwrap(), before);
        let stale = view
            .prepare(
                &request,
                GroupAction::Create {
                    packages: &packages,
                },
                &mut a.port(),
                (&policy, &authority),
                &mut clock,
                128,
            )
            .await
            .unwrap();
        let pending = view
            .prepare(
                &request,
                GroupAction::Create {
                    packages: &packages,
                },
                &mut a.port(),
                (&policy, &authority),
                &mut clock,
                128,
            )
            .await
            .unwrap();
        let committed = pending
            .commit(
                &mut a.port(),
                &mut astore,
                (&policy, &authority),
                &mut clock,
            )
            .await
            .unwrap();
        assert_eq!(astore.version().unwrap(), before + 1);
        assert_eq!(committed.revision(), 1);
        assert_eq!(committed.effects().len(), 1);
        assert!(matches!(
            stale
                .commit(
                    &mut a.port(),
                    &mut astore,
                    (&policy, &authority),
                    &mut clock
                )
                .await,
            Err(InboxError::Threads(Error::Conflict))
        ));
        let welcome = match &committed.events()[0] {
            Event::Invitation { welcome, .. } => welcome.clone(),
            _ => panic!("expected committed MLS welcome"),
        };
        for (fixture, store) in [(&mut b, &mut bstore), (&mut c, &mut cstore)] {
            let member_inbox = Inbox::new(fixture.binding.clone());
            let before = store.version().unwrap();
            let joined = member_inbox
                .group(SLOT, store)
                .unwrap()
                .prepare(
                    &request,
                    GroupAction::Join { welcome: &welcome },
                    &mut fixture.port(),
                    (&policy, &authority),
                    &mut clock,
                    128,
                )
                .await
                .unwrap()
                .commit(
                    &mut fixture.port(),
                    store,
                    (&policy, &authority),
                    &mut clock,
                )
                .await
                .unwrap();
            assert!(matches!(joined.events(), [Event::Joined]));
            assert_eq!(store.version().unwrap(), before + 1);
            let view = member_inbox
                .group(SLOT, store)
                .unwrap()
                .snapshot(&policy, 1000)
                .unwrap();
            assert_eq!(view.level, cgrp::Level::Circle);
            assert_eq!(view.size, 3);
        }
        // Reopen the real encrypted store; both owner snapshots survive together.
        let cipher = ckmg::passkey::store_cipher(&prf(a.seed), "alpha").unwrap();
        let mut reopened = Store::open(backend, &cipher, "alpha").await.unwrap();
        assert_eq!(
            inbox
                .group(SLOT, &reopened)
                .unwrap()
                .snapshot(&policy, 1000)
                .unwrap()
                .size,
            3
        );
        assert!(cgrp::Snapshot::load("beta", &reopened).is_err());
        let state = cgrp::Snapshot::load("alpha", &reopened).unwrap();
        let leave = group_authority::request(
            &state,
            cgrp::Command::Leave { group: SLOT },
            "m2",
            group_authority::members(2, 3),
            false,
            1000,
        );
        let pending = inbox
            .group(SLOT, &reopened)
            .unwrap()
            .prepare(
                &leave,
                GroupAction::Update,
                &mut a.port(),
                (&policy, &authority),
                &mut clock,
                128,
            )
            .await
            .unwrap();
        pending
            .commit(
                &mut a.port(),
                &mut reopened,
                (&policy, &authority),
                &mut clock,
            )
            .await
            .unwrap();
        assert_eq!(
            inbox
                .group(SLOT, &reopened)
                .unwrap()
                .snapshot(&policy, 1000)
                .unwrap()
                .size,
            2
        );
        // No Wave or account operation is involved in membership consent.
        assert!(reopened.read("cwvs", b"reservations.v1").unwrap().is_none());
        assert!(
            reopened
                .read("cwlt.passport", b"holder.v1")
                .unwrap()
                .is_none()
        );
    }));
}
