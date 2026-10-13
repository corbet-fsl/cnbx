//! First-contact reservation and outcome journal over Waves.
//!
//! Every transition consumes the actual Wallet capability Waves requires; the
//! facade adds no state. Evidence progress is not release: no method here lets
//! protected first content leave the device or establishes a contact.
use crate::{Error, Inbox, Result};
use ckmg::{Binding, Clock};
use cwst::{Store, backend::Backend};
pub use cwvs::{
    ReservationView, State as WaveState, VerifiedWaveOutcome, VerifiedWaveReservation, WaveContext,
    WaveOutcome,
};

/// Committed journal for this member. `member` is Accounting's SHA-256 of the
/// canonical pseudonym, supplied by the trusted runtime.
pub struct Waves(pub(crate) cwvs::Waves);
/// A real Waves candidate, not yet durable.
pub struct PreparedWave(pub(crate) cwvs::Candidate);

impl Inbox {
    /// Accounting's member digest: SHA-256 of the 48 pseudonym bytes. The bound
    /// member string must be exactly cpsd's `Pseudonym::to_hex` (96 lowercase hex
    /// characters); anything else is refused. Curve validity is enforced where
    /// pseudonyms are created and verified, not here.
    pub fn member_digest(&self) -> Result<[u8; 32]> {
        digest_of(self.binding.member())
    }
    /// The Contacts outcome authority backed by this member's Waves journal.
    pub fn outcomes<'a>(&'a self, waves: &'a Waves) -> WavesOutcomes<'a> {
        WavesOutcomes {
            binding: &self.binding,
            waves,
        }
    }
    pub fn waves<B: Backend>(&self, member: [u8; 32], store: &Store<B>) -> Result<Waves> {
        cwvs::Waves::load(self.binding.community(), member, store)
            .map(Waves)
            .map_err(Error::Waves)
    }
}

impl Waves {
    pub fn reservations(&self) -> Vec<ReservationView> {
        self.0.reservations()
    }
    /// True while this member's Answer for `conversation` is claimed and its proof pending.
    pub fn claimed(
        &self,
        conversation: &[u8; 32],
        peer: &[u8; 32],
        receipt_digest: &[u8; 32],
    ) -> bool {
        self.0.claimed(conversation, peer, receipt_digest)
    }
    /// The claim that lets the recipient SEND in the Pending conversation while
    /// its Answer is claimed. `None` unless `claimed` holds right now for exactly
    /// this peer, conversation and receipt digest (a reverted claim yields None).
    pub fn claim(
        &self,
        conversation: &[u8; 32],
        peer: &str,
        receipt_digest: &[u8; 32],
    ) -> Option<cdlv::Claim> {
        let digest = digest_of(peer).ok()?;
        self.0
            .claimed(conversation, &digest, receipt_digest)
            .then(|| cdlv::Claim::new(peer, conversation))
    }
    /// Public proof contexts of a retained offer, for resuming after restart.
    pub fn offer(&self, nonce: &[u8; 32]) -> Option<(&WaveContext, &WaveContext)> {
        self.0.offer(nonce)
    }
    pub fn prepare_offer(
        self,
        sender: WaveContext,
        recipient: WaveContext,
        clock: &mut impl Clock,
    ) -> Result<PreparedWave> {
        self.0
            .prepare_offer(sender, recipient, clock)
            .map(PreparedWave)
            .map_err(Error::Waves)
    }
    pub fn accept_reservations(
        self,
        sender: VerifiedWaveReservation,
        recipient: VerifiedWaveReservation,
        clock: &mut impl Clock,
    ) -> Result<PreparedWave> {
        self.0
            .accept_reservations(sender, recipient, clock)
            .map(PreparedWave)
            .map_err(Error::Waves)
    }
    /// The recipient's own Answer, claimed before its proof exists: the
    /// conversation may open at once and the proof settles or reverts the claim.
    pub fn claim_answer(
        self,
        nonce: &[u8; 32],
        receipt_digest: [u8; 32],
        clock: &mut impl Clock,
    ) -> Result<PreparedWave> {
        self.0
            .claim_answer(nonce, receipt_digest, clock)
            .map(PreparedWave)
            .map_err(Error::Waves)
    }
    /// A claimed Answer whose proof failed or stayed uncertain returns to pending.
    pub fn revert_claim(self, nonce: &[u8; 32], clock: &mut impl Clock) -> Result<PreparedWave> {
        self.0
            .revert_claim(nonce, clock)
            .map(PreparedWave)
            .map_err(Error::Waves)
    }
    /// The sender records the recipient's Answer after verifying its proof.
    pub fn record_peer_answer(
        self,
        proof: VerifiedWaveOutcome,
        clock: &mut impl Clock,
    ) -> Result<PreparedWave> {
        self.0
            .record_peer_answer(proof, clock)
            .map(PreparedWave)
            .map_err(Error::Waves)
    }
    pub fn record_outcome(
        self,
        proof: VerifiedWaveOutcome,
        clock: &mut impl Clock,
    ) -> Result<PreparedWave> {
        self.0
            .record_outcome(proof, clock)
            .map(PreparedWave)
            .map_err(Error::Waves)
    }
}

impl PreparedWave {
    /// Checkpoint the evidence. After an unknown write, reopen the same Store
    /// and inspect the original nonce; never regenerate the offer.
    pub async fn commit<B: Backend>(
        self,
        store: &mut Store<B>,
        operation: [u8; 32],
        clock: &mut impl Clock,
    ) -> Result<Waves> {
        self.0
            .commit(store, operation, clock)
            .await
            .map(Waves)
            .map_err(Error::Waves)
    }
}

/// Contacts `Answered` as its own later checkpoint (never part of the release):
/// accepted only with the evidence this member's Waves journal holds for exactly
/// this conversation, peer and receipt digest.
impl Inbox {
    #[allow(clippy::too_many_arguments)]
    pub async fn mark_answered<S, C, R, A, B>(
        &self,
        waves: &Waves,
        peer: &str,
        conversation: [u8; 32],
        receipt_digest: [u8; 32],
        keys: &mut ckmg::Keys<S, C, R, A>,
        handle: &ckmg::KeyHandle,
        store: &mut Store<B>,
    ) -> Result<crate::Contacts>
    where
        S: ckmg::SecureStore,
        C: Clock,
        R: ckmg::Entropy,
        A: ckmg::Authority,
        B: Backend,
    {
        let authority = Error::Contacts(ctcs::Error::Authority);
        let contacts =
            ctcs::Contacts::load(self.binding.clone(), store).map_err(Error::Contacts)?;
        let event = contacts
            .request(
                peer,
                ctcs::Action::Answered {
                    conversation,
                    evidence: receipt_digest.to_vec(),
                },
            )
            .map_err(Error::Contacts)?;
        let certificate = handle.certificate().clone();
        let bytes = event.signing_bytes(&certificate).map_err(Error::Contacts)?;
        let operation = *ckmg::hash(&bytes).value();
        let signature = keys.sign(handle, &bytes).await.map_err(|_| authority)?;
        let signed = event.signed(certificate, signature);
        let mut device = crate::OwnDevice(keys);
        let mut outcomes = self.outcomes(waves);
        let candidate = contacts
            .prepare(signed, &mut device, &mut outcomes)
            .await
            .map_err(Error::Contacts)?;
        candidate
            .commit((&mut device, &mut outcomes), store, operation, &[], &[])
            .await
            .map(crate::Contacts)
            .map_err(Error::Contacts)
    }
}

pub fn digest_of(member: &str) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let text = member.as_bytes();
    if text.len() != 96 {
        return Err(Error::Waves(cwvs::Error::Scope));
    }
    let mut bytes = [0u8; 48];
    for (byte, pair) in bytes.iter_mut().zip(text.as_chunks::<2>().0) {
        let nibble = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Error::Waves(cwvs::Error::Scope)),
        };
        *byte = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Ok(Sha256::digest(bytes).into())
}

/// Accepts `Answered{conversation, evidence}` only if this member's Waves journal
/// links the conversation to a wave holding an Answer outcome whose receipt
/// digest is exactly `evidence` (32 bytes), for exactly this peer.
pub struct WavesOutcomes<'a> {
    binding: &'a Binding,
    waves: &'a Waves,
}
impl ctcs::OutcomeAuthority for WavesOutcomes<'_> {
    async fn answered(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        evidence: &[u8],
    ) -> std::result::Result<(), ctcs::Error> {
        let digest: &[u8; 32] = evidence.try_into().map_err(|_| ctcs::Error::Authority)?;
        let peer = digest_of(peer).map_err(|_| ctcs::Error::Authority)?;
        if binding != self.binding || !self.waves.0.answered(conversation, &peer, digest) {
            return Err(ctcs::Error::Authority);
        }
        Ok(())
    }
}
