//! The atomic first-contact release checkpoint (Waves proposal section 5).
//!
//! One `cwst` commit carries the Waves journal, the Wallet adoption, the Contacts
//! event and the Threads/Delivery state with its pending outputs. Every owner
//! stages its own change; this module only joins them under one version fence.
//! Nothing is published before the commit succeeds and a failure before it
//! reveals nothing. An uncertain write is reconciled from the retained operation
//! id; a release is never regenerated.
use crate::{
    Error, Pending, Published, Result, contacts::Contacts, waves::PreparedWave, waves::Waves,
};
use ckmg::{Binding, Clock};
use cwst::{Change, Store, backend::Backend};

/// One record the Wallet owner (cwlt) adopts in the same transaction. The Wallet
/// stages its own bytes; the facade only carries them.
pub struct WalletChange {
    owner: String,
    key: Vec<u8>,
    value: Vec<u8>,
}
impl WalletChange {
    pub fn new(owner: String, key: Vec<u8>, value: Vec<u8>) -> Self {
        Self { owner, key, value }
    }
}

/// The four owner candidates of one release, sender or recipient side.
pub struct Release {
    pub binding: Binding,
    pub peer: String,
    pub conversation: [u8; 32],
    pub waves: PreparedWave,
    pub contacts: ctcs::Candidate,
    pub delivery: Pending,
    pub wallet: Vec<WalletChange>,
}

/// The committed owner states after a successful release.
pub struct Released {
    pub waves: Waves,
    pub contacts: Contacts,
    pub published: Published,
}

/// G2: the member's own record matches the newest epoch commitment. The Wallet
/// owner supplies the verification; the release never proceeds without it.
#[allow(async_fn_in_trait)]
pub trait OwnRecord {
    async fn matches_newest_epoch(&mut self, binding: &Binding) -> std::result::Result<(), ()>;
}

/// Explicit release preconditions (Waves proposal section 5). Returns the Waves
/// candidate with the released conversation linked; nothing is written. Evidence
/// that the reservations are verified is the candidate itself: only verified
/// Wallet values produce one past `Prepared`, and linking refuses `Prepared`.
pub async fn check<B: Backend, D: ctcs::DeviceAuthority>(
    own: &mut impl OwnRecord,
    binding: &Binding,
    peer: &str,
    conversation: [u8; 32],
    waves: PreparedWave,
    store: &Store<B>,
    devices: &mut D,
) -> Result<PreparedWave> {
    let peer_binding =
        Binding::new(binding.community(), peer).map_err(|_| Error::Contacts(ctcs::Error::Scope))?;
    if peer == binding.member() {
        return Err(Error::Contacts(ctcs::Error::Scope));
    }
    // No block in the committed journal. A block by the peer is never visible
    // here and is handled by the protocol's own Close/Block events.
    let contacts = ctcs::Contacts::load(binding.clone(), store).map_err(Error::Contacts)?;
    if contacts.relation(peer).map_err(Error::Contacts)?.state == ctcs::State::Blocked {
        return Err(Error::Contacts(ctcs::Error::Transition));
    }
    // Peer lineage must be independently current right now.
    devices
        .current(&peer_binding)
        .await
        .map_err(Error::Contacts)?;
    waves
        .0
        .link_conversation(conversation)
        .map(PreparedWave)
        .map_err(Error::Waves)
}

impl Release {
    #[allow(clippy::too_many_arguments)]
    pub async fn commit<B, D, O>(
        self,
        own: &mut impl OwnRecord,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        devices: &mut D,
        outcomes: &mut O,
        store: &mut Store<B>,
        operation: [u8; 32],
        clock: &mut impl Clock,
    ) -> Result<Released>
    where
        B: Backend,
        D: ctcs::DeviceAuthority,
        O: ctcs::OutcomeAuthority,
    {
        let waves = check(
            own,
            &self.binding,
            &self.peer,
            self.conversation,
            self.waves,
            store,
            devices,
        )
        .await?;
        let waves = waves.0.stage(store, clock).map_err(Error::Waves)?;
        let contacts = self
            .contacts
            .stage((&mut *devices, outcomes), store)
            .await
            .map_err(Error::Contacts)?;
        let delivery = self
            .delivery
            .0
            .stage(keys, authority, devices, store, operation)
            .await
            .map_err(Error::Delivery)?;
        // A release is one fence: every owner must have been prepared against
        // the same committed Store version.
        if waves.expected() != contacts.expected() || waves.expected() != delivery.expected() {
            return Err(Error::Waves(cwvs::Error::Conflict));
        }
        let mut changes = vec![waves.change(), contacts.change()];
        changes.extend(delivery.changes());
        for w in &self.wallet {
            changes.push(Change::Put {
                owner: &w.owner,
                key: &w.key,
                value: &w.value,
            });
        }
        let version = store
            .commit(waves.expected(), operation, &changes, delivery.outputs())
            .await
            .map_err(|_| Error::Waves(cwvs::Error::Storage))?;
        Ok(Released {
            waves: Waves(waves.finish(version)),
            contacts: Contacts(contacts.finish(version)),
            published: Published(delivery.finish(version)),
        })
    }
}
