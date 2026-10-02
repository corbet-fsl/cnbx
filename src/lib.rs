//! Thin device Inbox composition. Every fact and mutation comes from its owner.
mod conversation;
pub use cdlv::{Status as DeliveryStatus, Wire};
pub use ckmg::Binding;
use ckmg::{Authority, Clock, Entropy, KeyHandle, Keys, SecureStore};
pub use conversation::{ConversationView, Opened, Preparing};
pub use ctcs::{DeviceAuthority, Relation, State as ContactState};
pub use cthr::keys::{Custody, KeyPort};
pub use cthr::{DirectAuthority, Event as ConversationEvent, Message, Operation};
use cwst::{Store, backend::Backend};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum Error {
    Contacts(ctcs::Error),
    Threads(cthr::Error),
    Delivery(cdlv::Error),
    UnexpectedMessage,
}
pub type Result<T> = std::result::Result<T, Error>;
pub struct Inbox {
    binding: Binding,
}
pub struct View {
    contacts: ctcs::Contacts,
    threads: cthr::Threads,
    delivery: cdlv::Delivery,
}
pub struct Pending(cdlv::Candidate);
pub struct Published(cdlv::Committed);
/// An authenticated real MLS receive, still with no visible plaintext or ACK.
pub enum Receive {
    Pending(Box<Receiving>),
    Duplicate(cdlv::Wire),
}
pub enum Acknowledgement {
    Pending(Box<Pending>),
    AlreadyAccepted([u8; 32]),
}
pub struct Receiving {
    delivery: cdlv::Delivery,
    threads: cthr::Candidate,
    incoming: cdlv::Incoming,
}
impl Inbox {
    pub fn new(binding: Binding) -> Self {
        Self { binding }
    }
    pub fn view<B: Backend>(&self, conversation: [u8; 32], store: &Store<B>) -> Result<View> {
        Ok(View {
            contacts: ctcs::Contacts::load(self.binding.clone(), store).map_err(Error::Contacts)?,
            threads: cthr::Threads::load(self.binding.clone(), conversation, store)
                .map_err(Error::Threads)?,
            delivery: cdlv::Delivery::load(self.binding.clone(), store).map_err(Error::Delivery)?,
        })
    }
}
impl View {
    /// Local API projection; every field is derived from the committed owners.
    pub fn snapshot(&self, peer: &str) -> Result<ConversationView> {
        Ok(ConversationView {
            relation: self.relation(peer)?,
            history: self.history().to_vec(),
        })
    }

    /// Reload the view after any checkpoint; retries reuse the exact durable wire.
    pub async fn retry(
        &self,
        message: &[u8; 32],
        devices: &mut impl ctcs::DeviceAuthority,
    ) -> Result<cdlv::Wire> {
        self.delivery
            .retry(message, devices, &self.contacts)
            .await
            .map_err(Error::Delivery)
    }

    pub fn relation(&self, peer: &str) -> Result<ctcs::Relation> {
        self.contacts.relation(peer).map_err(Error::Contacts)
    }
    pub fn history(&self) -> &[cthr::Message] {
        self.threads.history()
    }
    pub fn delivery_status(&self, message: &[u8; 32]) -> Option<cdlv::Status> {
        self.delivery.status(message)
    }
    pub async fn send(
        &self,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        bytes: &[u8],
    ) -> Result<Pending> {
        let threads = self
            .threads
            .send(keys, authority, bytes)
            .await
            .map_err(Error::Threads)?;
        Ok(Pending(
            self.delivery
                .outgoing(threads, &self.contacts)
                .map_err(Error::Delivery)?,
        ))
    }
    pub async fn receive(
        self,
        wire: &[u8],
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        devices: &mut impl ctcs::DeviceAuthority,
    ) -> Result<Receive> {
        let incoming = match self
            .delivery
            .authenticate(wire, devices, &self.contacts)
            .await
            .map_err(Error::Delivery)?
        {
            cdlv::Authenticated::Data(incoming) => incoming,
            cdlv::Authenticated::Duplicate(receipt) => return Ok(Receive::Duplicate(receipt)),
            _ => return Err(Error::UnexpectedMessage),
        };
        let threads = self
            .threads
            .receive(keys, authority, incoming.ciphertext())
            .await
            .map_err(Error::Threads)?;
        Ok(Receive::Pending(Box::new(Receiving {
            delivery: self.delivery,
            threads,
            incoming,
        })))
    }
    pub async fn acknowledge(
        &self,
        wire: &[u8],
        devices: &mut impl ctcs::DeviceAuthority,
    ) -> Result<Acknowledgement> {
        let ack = match self
            .delivery
            .authenticate(wire, devices, &self.contacts)
            .await
            .map_err(Error::Delivery)?
        {
            cdlv::Authenticated::Ack(ack) => ack,
            cdlv::Authenticated::AlreadyAccepted(message) => {
                return Ok(Acknowledgement::AlreadyAccepted(message));
            }
            _ => return Err(Error::UnexpectedMessage),
        };
        Ok(Acknowledgement::Pending(Box::new(Pending(
            self.delivery
                .acknowledged(&self.threads, ack)
                .map_err(Error::Delivery)?,
        ))))
    }
}
impl Receiving {
    pub async fn prepare_receipt<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
        self,
        keys: &mut Keys<S, C, R, A>,
        handle: &KeyHandle,
    ) -> Result<Pending> {
        Ok(Pending(
            self.delivery
                .received(self.threads, self.incoming, keys, handle)
                .await
                .map_err(Error::Delivery)?,
        ))
    }
}
impl Pending {
    pub async fn commit<B: Backend>(
        self,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        devices: &mut impl ctcs::DeviceAuthority,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<Published> {
        Ok(Published(
            self.0
                .commit(keys, authority, devices, store, operation)
                .await
                .map_err(Error::Delivery)?,
        ))
    }
}
impl Published {
    pub fn outgoing_ids(&self) -> Vec<[u8; 32]> {
        self.0
            .threads
            .outgoing()
            .iter()
            .map(|output| *output.id())
            .collect()
    }
    pub fn history(&self) -> &[cthr::Message] {
        self.0.threads.threads().history()
    }
    pub fn delivery_status(&self, message: &[u8; 32]) -> Option<cdlv::Status> {
        self.0.delivery.status(message)
    }
    /// Persist the owner's exact transport envelope before exposing it to Mesh.
    pub async fn outgoing<S: SecureStore, C: Clock, R: Entropy, A: Authority, B: Backend>(
        &self,
        keys: &mut Keys<S, C, R, A>,
        handle: &KeyHandle,
        devices: &mut impl ctcs::DeviceAuthority,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<cdlv::Wire> {
        let outgoing = self.0.threads.outgoing();
        let output = outgoing.first().ok_or(Error::UnexpectedMessage)?;
        let (_, wire) = self
            .0
            .delivery
            .wrap(output, keys, handle, devices, store, operation)
            .await
            .map_err(Error::Delivery)?;
        Ok(wire)
    }
    pub fn receipt(&self, message: &[u8; 32]) -> Result<cdlv::Wire> {
        self.0.delivery.ack(message).map_err(Error::Delivery)
    }
}
