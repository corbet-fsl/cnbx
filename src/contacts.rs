//! Contacts operations that need only this device's own current authority.
//!
//! Block, close and reopen are authored and signed by this member's own device.
//! A new contact (`Begin`) and an accepted Answer need first-contact release and
//! verified Waves accounting evidence, so they are not reachable from here.
use crate::{Error, Inbox, Result};
use ckmg::{Authority, Binding, Clock, Entropy, KeyHandle, Keys, Lineage, SecureStore};
use cwst::{Store, backend::Backend};
use serde::{Deserialize, Serialize};

/// The only control actions a member can take alone. Each is signed by the
/// member's own purpose key and checked against the member's own current lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnAction {
    Block,
    Close,
    /// Explicit fresh reopening of a closed contact under a new conversation.
    Reopen {
        conversation: [u8; 32],
    },
}

impl From<OwnAction> for ctcs::Action {
    fn from(action: OwnAction) -> Self {
        match action {
            OwnAction::Block => Self::Block,
            OwnAction::Close => Self::Close,
            OwnAction::Reopen { conversation } => Self::Reopen { conversation },
        }
    }
}

/// This device's own current lineage, read from Keys with its live authority
/// check. It answers only for the member's own binding, never for a peer.
pub struct OwnDevice<'a, S, C, R, A>(pub &'a mut Keys<S, C, R, A>);
impl<S: SecureStore, C: Clock, R: Entropy, A: Authority> ctcs::DeviceAuthority
    for OwnDevice<'_, S, C, R, A>
{
    async fn current(&mut self, binding: &Binding) -> std::result::Result<Lineage, ctcs::Error> {
        let lineage = self.0.lineage().await.map_err(|_| ctcs::Error::Authority)?;
        if lineage.binding == *binding {
            Ok(lineage)
        } else {
            Err(ctcs::Error::Authority)
        }
    }
}

/// Committed relation journal of the bound member. Every fact is the owner's.
pub struct Contacts(pub(crate) ctcs::Contacts);

impl Inbox {
    pub fn contacts<B: Backend>(&self, store: &Store<B>) -> Result<Contacts> {
        ctcs::Contacts::load(self.binding.clone(), store)
            .map(Contacts)
            .map_err(Error::Contacts)
    }
}

impl Contacts {
    pub fn relation(&self, peer: &str) -> Result<ctcs::Relation> {
        self.0.relation(peer).map_err(Error::Contacts)
    }
    /// Blocked peers, for Board's online never-match rules.
    pub fn blocking_rules(&self) -> Result<Vec<String>> {
        self.0.blocking_rules().map_err(Error::Contacts)
    }
    /// Private sync bytes for encrypted owner-to-owner channels or Records only.
    pub fn export_journal(&self) -> Result<Vec<u8>> {
        self.0.export_journal().map_err(Error::Contacts)
    }

    /// The purpose key for own control events. Obtain it before taking the
    /// shared Store: creating a key checkpoints through that same Store.
    pub async fn key<S, C, R, A>(keys: &mut Keys<S, C, R, A>) -> Result<KeyHandle>
    where
        S: SecureStore,
        C: Clock,
        R: Entropy,
        A: Authority,
    {
        keys.key(ctcs::purpose())
            .await
            .map_err(|_| Error::Contacts(ctcs::Error::Authority))
    }

    /// Sign one own-authority control event and checkpoint it. The store
    /// operation id is the hash of the signed bytes, so a lost response is
    /// retried with the same id and never becomes a second operation.
    pub async fn apply<S, C, R, A, B>(
        &self,
        peer: &str,
        action: OwnAction,
        keys: &mut Keys<S, C, R, A>,
        handle: &KeyHandle,
        store: &mut Store<B>,
    ) -> Result<Self>
    where
        S: SecureStore,
        C: Clock,
        R: Entropy,
        A: Authority,
        B: Backend,
    {
        self.author(peer, action.into(), keys, handle, store).await
    }

    /// The newest retained lineage-record handle of `peer`.
    pub fn handle(&self, peer: &str) -> Result<Option<Vec<u8>>> {
        self.0.handle(peer).map_err(Error::Contacts)
    }

    pub(crate) async fn author<S, C, R, A, B>(
        &self,
        peer: &str,
        action: ctcs::Action,
        keys: &mut Keys<S, C, R, A>,
        handle: &KeyHandle,
        store: &mut Store<B>,
    ) -> Result<Self>
    where
        S: SecureStore,
        C: Clock,
        R: Entropy,
        A: Authority,
        B: Backend,
    {
        let event = self.0.request(peer, action).map_err(Error::Contacts)?;
        let authority = Error::Contacts(ctcs::Error::Authority);
        let certificate = handle.certificate().clone();
        let bytes = event.signing_bytes(&certificate).map_err(Error::Contacts)?;
        let operation = *ckmg::hash(&bytes).value();
        let signature = keys.sign(handle, &bytes).await.map_err(|_| authority)?;
        let signed = event.signed(certificate, signature);
        let mut device = OwnDevice(keys);
        let mut outcomes = ctcs::UnavailableOutcomes;
        let candidate = self
            .0
            .prepare(signed, &mut device, &mut outcomes)
            .await
            .map_err(Error::Contacts)?;
        candidate
            .commit((&mut device, &mut outcomes), store, operation, &[], &[])
            .await
            .map(Self)
            .map_err(Error::Contacts)
    }
}
