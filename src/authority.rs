//! Production direct-conversation authority: an Established contact, the exact
//! conversation, and a current peer lineage. Nothing else grants access.
use ckmg::Binding;
use cthr::{DirectAuthority, Error, Operation, Result};

/// Reads the committed relation journal and asks `peers` for the peer's CURRENT
/// lineage. Missing peer evidence is `Unavailable`; present but negative
/// evidence is `Authority`. No caller boolean, roster or cached verdict exists.
pub struct ContactAuthority<'a, P> {
    contacts: &'a ctcs::Contacts,
    peers: &'a mut P,
}

impl<'a, P: ctcs::DeviceAuthority> ContactAuthority<'a, P> {
    pub fn new(contacts: &'a ctcs::Contacts, peers: &'a mut P) -> Self {
        Self { contacts, peers }
    }
}

impl<P: ctcs::DeviceAuthority> DirectAuthority for ContactAuthority<'_, P> {
    /// Establish, Send and Receive share one rule: first contact (Pending) is
    /// not covered here, it needs the Waves release capability.
    async fn authorize(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        _: Operation,
    ) -> Result<()> {
        if binding != self.contacts.binding() {
            return Err(Error::Authority);
        }
        let relation = self.contacts.relation(peer).map_err(|_| Error::Authority)?;
        if relation.state != ctcs::State::Established
            || relation.conflicted
            || relation.conversation != Some(*conversation)
        {
            return Err(Error::Authority);
        }
        let peer_binding = Binding::new(binding.community(), peer).map_err(|_| Error::Authority)?;
        let lineage = self
            .peers
            .current(&peer_binding)
            .await
            .map_err(|error| match error {
                // Present and negative evidence only; anything missing or stale is Unavailable.
                ctcs::Error::Authority => Error::Authority,
                _ => Error::Unavailable,
            })?;
        if lineage.binding == peer_binding {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
}
