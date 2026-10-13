//! The atomic first-contact release checkpoint (Waves proposal section 5).
//!
//! One `cwst` commit carries the Waves journal, the Wallet adoption, the Contacts
//! `Begin` event and the Threads setup (MLS create or join) with its pending
//! outputs. Every owner stages its own change; this module only joins them under
//! one version fence. The release authorizes its own Threads setup from the Waves
//! candidate it commits, so no caller can supply a more permissive authority.
//! The first message and the Contacts `Answered` event are later checkpoints.
//! Nothing is published before the commit succeeds and a failure before it
//! reveals nothing. An uncertain write is reconciled from the retained operation
//! id; a release is never regenerated.
use crate::{
    Error, Opened, Preparing, Result, contacts::Contacts, waves::PreparedWave, waves::Waves,
    waves::digest_of,
};
use ckmg::{Authority, Binding, Clock, Entropy, KeyHandle, Keys, SecureStore};
use cthr::{DirectAuthority, Operation, keys::KeyPort};
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

/// How the Threads owner sets the conversation up: the sender creates it from the
/// recipient's key package, the recipient joins from the sender's welcome.
pub enum Entry<'a> {
    Create { package: &'a [u8] },
    Join { welcome: &'a [u8] },
}

/// The owner candidates of one release, sender or recipient side. It can only be
/// built by [`Release::prepare`], which links the conversation to its wave first.
pub struct Release {
    binding: Binding,
    peer: String,
    waves: PreparedWave,
    contacts: ctcs::Candidate,
    threads: Preparing,
    wallet: Vec<WalletChange>,
}

/// The committed owner states after a successful release.
pub struct Released {
    pub waves: Waves,
    pub contacts: Contacts,
    pub opened: Opened,
}

/// G2: the member's own record matches the newest epoch commitment. The Wallet
/// owner supplies the verification; the release never proceeds without it.
#[allow(async_fn_in_trait)]
pub trait OwnRecord {
    async fn matches_newest_epoch(&mut self, binding: &Binding) -> std::result::Result<(), ()>;
}

/// The only Threads authority of a release: setting up exactly the conversation
/// linked to the wave this member's candidate carries, for exactly its peer, once
/// the wave holds the evidence that permits it. Send and Receive are never
/// authorized here.
struct ReleaseAuthority<'a> {
    binding: &'a Binding,
    waves: &'a cwvs::Candidate,
}
impl DirectAuthority for ReleaseAuthority<'_> {
    async fn authorize(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        operation: Operation,
    ) -> cthr::Result<()> {
        let peer = digest_of(peer).map_err(|_| cthr::Error::Authority)?;
        if operation != Operation::Establish
            || binding != self.binding
            || !self.waves.releases(conversation, &peer)
        {
            return Err(cthr::Error::Authority);
        }
        Ok(())
    }
}

/// Explicit release preconditions that need no linking: G2 own record, no block
/// in the committed journal, a current peer lineage right now. A block by the
/// peer is never visible here and is handled by the protocol's own events.
async fn preconditions<B: Backend, D: ctcs::DeviceAuthority>(
    own: &mut impl OwnRecord,
    binding: &Binding,
    peer: &str,
    store: &Store<B>,
    devices: &mut D,
) -> Result<()> {
    // G2 first: a stale own record must never reach peers or the journal.
    own.matches_newest_epoch(binding)
        .await
        .map_err(|()| Error::Waves(cwvs::Error::Transcript))?;
    let peer_binding =
        Binding::new(binding.community(), peer).map_err(|_| Error::Contacts(ctcs::Error::Scope))?;
    if peer == binding.member() {
        return Err(Error::Contacts(ctcs::Error::Scope));
    }
    let contacts = ctcs::Contacts::load(binding.clone(), store).map_err(Error::Contacts)?;
    if contacts.relation(peer).map_err(Error::Contacts)?.state == ctcs::State::Blocked {
        return Err(Error::Contacts(ctcs::Error::Transition));
    }
    devices
        .current(&peer_binding)
        .await
        .map_err(Error::Contacts)?;
    Ok(())
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
    preconditions(own, binding, peer, store, devices).await?;
    waves
        .0
        .link_conversation(conversation)
        .map(PreparedWave)
        .map_err(Error::Waves)
}

impl crate::Inbox {
    /// Build the release candidates of this member for `peer` and `conversation`.
    /// `waves` is the accepted-reservations candidate (sender) or the recorded or
    /// claimed own Answer (recipient). Nothing is written; dropping the result reveals
    /// nothing. `contacts_handle` and `threads_handle` are this member's scoped
    /// purpose keys for Contacts and Threads.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_release<S, C, R, A, B, D>(
        &self,
        own: &mut impl OwnRecord,
        keys: &mut Keys<S, C, R, A>,
        contacts_handle: &KeyHandle,
        threads_handle: &KeyHandle,
        devices: &mut D,
        store: &Store<B>,
        peer: &str,
        conversation: [u8; 32],
        waves: PreparedWave,
        entry: Entry<'_>,
        wallet: Vec<WalletChange>,
    ) -> Result<Release>
    where
        S: SecureStore,
        C: Clock,
        R: Entropy,
        A: Authority,
        B: Backend,
        D: ctcs::DeviceAuthority,
    {
        let waves = check(
            own,
            &self.binding,
            peer,
            conversation,
            waves,
            store,
            devices,
        )
        .await?;
        let contacts =
            ctcs::Contacts::load(self.binding.clone(), store).map_err(Error::Contacts)?;
        let event = contacts
            .request(peer, ctcs::Action::Begin { conversation })
            .map_err(Error::Contacts)?;
        let certificate = contacts_handle.certificate().clone();
        let bytes = event.signing_bytes(&certificate).map_err(Error::Contacts)?;
        let signature = keys
            .sign(contacts_handle, &bytes)
            .await
            .map_err(|_| Error::Contacts(ctcs::Error::Authority))?;
        let contacts = contacts
            .prepare(
                event.signed(certificate, signature),
                devices,
                &mut ctcs::UnavailableOutcomes,
            )
            .await
            .map_err(Error::Contacts)?;
        let thread = cthr::Threads::load(self.binding.clone(), conversation, store)
            .map_err(Error::Threads)?;
        let mut authority = ReleaseAuthority {
            binding: &self.binding,
            waves: &waves.0,
        };
        let mut custody = KeyPort {
            keys,
            handle: threads_handle,
            devices,
        };
        let threads = match entry {
            Entry::Create { package } => {
                thread
                    .create_direct(&mut custody, &mut authority, peer, package)
                    .await
            }
            Entry::Join { welcome } => {
                thread
                    .join_direct(&mut custody, &mut authority, peer, welcome)
                    .await
            }
        }
        .map(Preparing)
        .map_err(Error::Threads)?;
        Ok(Release {
            binding: self.binding.clone(),
            peer: peer.into(),
            waves,
            contacts,
            threads,
            wallet,
        })
    }
}

impl Release {
    /// Re-check every precondition and write the one checkpoint. Use a fresh
    /// `operation` per release and reconcile an uncertain write from it.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit<S, C, R, A, B, D>(
        self,
        own: &mut impl OwnRecord,
        keys: &mut Keys<S, C, R, A>,
        threads_handle: &KeyHandle,
        devices: &mut D,
        store: &mut Store<B>,
        operation: [u8; 32],
        clock: &mut impl Clock,
    ) -> Result<Released>
    where
        S: SecureStore,
        C: Clock,
        R: Entropy,
        A: Authority,
        B: Backend,
        D: ctcs::DeviceAuthority,
    {
        preconditions(own, &self.binding, &self.peer, store, devices).await?;
        let mut authority = ReleaseAuthority {
            binding: &self.binding,
            waves: &self.waves.0,
        };
        let mut custody = KeyPort {
            keys,
            handle: threads_handle,
            devices: &mut *devices,
        };
        let threads = self
            .threads
            .0
            .stage(&mut custody, &mut authority, store, operation)
            .await
            .map_err(Error::Threads)?;
        let waves = self.waves.0.stage(store, clock).map_err(Error::Waves)?;
        let contacts = self
            .contacts
            .stage((devices, &mut ctcs::UnavailableOutcomes), store)
            .await
            .map_err(Error::Contacts)?;
        // A release is one fence: every owner must have been prepared against
        // the same committed Store version.
        if waves.expected() != contacts.expected() || waves.expected() != threads.expected() {
            return Err(Error::Waves(cwvs::Error::Conflict));
        }
        let mut changes = vec![waves.change(), contacts.change()];
        changes.extend(threads.changes());
        for w in &self.wallet {
            changes.push(Change::Put {
                owner: &w.owner,
                key: &w.key,
                value: &w.value,
            });
        }
        let version = store
            .commit(waves.expected(), operation, &changes, threads.outputs())
            .await
            .map_err(|_| Error::Waves(cwvs::Error::Storage))?;
        Ok(Released {
            waves: Waves(waves.finish(version)),
            contacts: Contacts(contacts.finish(version)),
            opened: Opened(threads.finish(version)),
        })
    }
}
