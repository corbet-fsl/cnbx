//! Direct-session preparation delegates to Threads; first-contact authority is
//! still required from Waves. These methods never authorize a free first contact.
use crate::{Error, Result, View};
use cwst::{Store, backend::Backend};

/// Committed, device-local facts for the member API. No custody or ratchet state.
#[derive(Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConversationView {
    pub relation: ctcs::Relation,
    pub history: Vec<cthr::Message>,
}

/// A real Threads candidate; no package or welcome can escape before persistence.
pub struct Preparing(cthr::Candidate);

/// Setup outputs released only by the owner's successful durable checkpoint.
pub struct Opened(cthr::Committed);

impl View {
    pub async fn key_package(&self, keys: &mut impl cthr::keys::Custody) -> Result<Preparing> {
        self.threads
            .key_package(keys)
            .await
            .map(Preparing)
            .map_err(Error::Threads)
    }

    pub async fn create_direct(
        &self,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        peer: &str,
        package: &[u8],
    ) -> Result<Preparing> {
        self.threads
            .create_direct(keys, authority, peer, package)
            .await
            .map(Preparing)
            .map_err(Error::Threads)
    }

    pub async fn join_direct(
        &self,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        peer: &str,
        welcome: &[u8],
    ) -> Result<Preparing> {
        self.threads
            .join_direct(keys, authority, peer, welcome)
            .await
            .map(Preparing)
            .map_err(Error::Threads)
    }
}

impl Preparing {
    pub async fn commit<B: Backend>(
        self,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<Opened> {
        self.0
            .commit(keys, authority, store, operation, &[])
            .await
            .map(Opened)
            .map_err(Error::Threads)
    }
}

impl Opened {
    pub fn events(&self) -> &[cthr::Event] {
        self.0.events()
    }
}
