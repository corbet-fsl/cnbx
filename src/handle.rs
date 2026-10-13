//! Lineage-record handles of peers. A handle is never looked up by pseudonym.
//! It arrives signed by the peer (first contact, or a later announcement inside
//! the conversation) and is retained in Contacts only after the signature is
//! verified under the peer's current lineage.
use crate::{Contacts, Error, Result};
use ckmg::{
    Authority, Binding, Clock, Entropy, KeyCertificate, KeyHandle, Keys, SecureStore, Signature,
};
use cwst::{Store, backend::Backend};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"cnbx.handle.v1\0";

/// A peer's signed statement of where its certified lineage records live.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleAnnouncement {
    binding: Binding,
    conversation: [u8; 32],
    handle: Vec<u8>,
    certificate: KeyCertificate,
    signature: Signature,
}

fn signing_bytes(
    binding: &Binding,
    conversation: &[u8; 32],
    handle: &[u8],
    certificate: &KeyCertificate,
) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    for part in [binding.community().as_bytes(), binding.member().as_bytes()] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(conversation);
    out.extend_from_slice(&(handle.len() as u32).to_be_bytes());
    out.extend_from_slice(handle);
    out.extend_from_slice(&certificate.epoch.to_be_bytes());
    out.extend_from_slice(certificate.key.value());
    out
}

impl HandleAnnouncement {
    /// Sign this member's own handle with its Contacts purpose key.
    pub async fn sign<S, C, R, A>(
        keys: &mut Keys<S, C, R, A>,
        key: &KeyHandle,
        binding: &Binding,
        conversation: [u8; 32],
        handle: Vec<u8>,
    ) -> Result<Self>
    where
        S: SecureStore,
        C: Clock,
        R: Entropy,
        A: Authority,
    {
        let certificate = key.certificate().clone();
        if handle.is_empty() || handle.len() > ctcs::MAX_HANDLE || conversation == [0; 32] {
            return Err(Error::Contacts(ctcs::Error::Limit));
        }
        let bytes = signing_bytes(binding, &conversation, &handle, &certificate);
        let signature = keys
            .sign(key, &bytes)
            .await
            .map_err(|_| Error::Contacts(ctcs::Error::Authority))?;
        Ok(Self {
            binding: binding.clone(),
            conversation,
            handle,
            certificate,
            signature,
        })
    }

    /// The announced handle bytes, untrusted until [`Contacts::retain_handle`].
    pub fn handle(&self) -> &[u8] {
        &self.handle
    }

    /// The announcing member's binding.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    /// Verify under the announcer's CURRENT lineage from `authority`. The caller
    /// builds `authority` from the previously retained handle when one exists,
    /// otherwise from the announced one. Evidence that is unavailable stays
    /// `Unavailable`; present and wrong evidence is `Authority`.
    async fn verify(
        &self,
        own: &Binding,
        authority: &mut impl ctcs::DeviceAuthority,
    ) -> Result<()> {
        let authority_error = Error::Contacts(ctcs::Error::Authority);
        if self.handle.is_empty()
            || self.handle.len() > ctcs::MAX_HANDLE
            || self.conversation == [0; 32]
            || self.binding.community() != own.community()
            || self.binding.member() == own.member()
            || self.certificate.binding != self.binding
        {
            return Err(authority_error);
        }
        let lineage = authority
            .current(&self.binding)
            .await
            .map_err(Error::Contacts)?;
        self.certificate
            .verify(&lineage, &ctcs::purpose())
            .map_err(|_| authority_error)?;
        let bytes = signing_bytes(
            &self.binding,
            &self.conversation,
            &self.handle,
            &self.certificate,
        );
        ckmg::verify(&self.certificate.key, &bytes, &self.signature).map_err(|_| authority_error)
    }
}

impl Contacts {
    /// Verify `announcement` and retain its handle for the announcing peer, as a
    /// new own-signed journal event. Replaces an older handle only after this
    /// verification. The peer must be in a Pending or Established relation of
    /// exactly the announced conversation.
    pub async fn retain_handle<S, C, R, A, B>(
        &self,
        announcement: &HandleAnnouncement,
        authority: &mut impl ctcs::DeviceAuthority,
        keys: &mut Keys<S, C, R, A>,
        key: &KeyHandle,
        store: &mut Store<B>,
    ) -> Result<Self>
    where
        S: SecureStore,
        C: Clock,
        R: Entropy,
        A: Authority,
        B: Backend,
    {
        let own = self.0.binding().clone();
        announcement.verify(&own, authority).await?;
        let peer = announcement.binding.member();
        let relation = self.0.relation(peer).map_err(Error::Contacts)?;
        if relation.conversation != Some(announcement.conversation) {
            return Err(Error::Contacts(ctcs::Error::Transition));
        }
        self.author(
            peer,
            ctcs::Action::Handle {
                handle: announcement.handle.clone(),
            },
            keys,
            key,
            store,
        )
        .await
    }
}
