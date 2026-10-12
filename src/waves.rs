//! First-contact reservation and outcome journal over Waves.
//!
//! Every transition consumes the actual Wallet capability Waves requires; the
//! facade adds no state. Evidence progress is not release: no method here lets
//! protected first content leave the device or establishes a contact.
use crate::{Error, Inbox, Result};
use ckmg::Clock;
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
        use sha2::{Digest, Sha256};
        let text = self.binding.member().as_bytes();
        if text.len() != 96 {
            return Err(Error::Waves(cwvs::Error::Scope));
        }
        let mut bytes = [0u8; 48];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
            let nibble = |c: u8| match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(Error::Waves(cwvs::Error::Scope)),
            };
            *byte = nibble(pair[0])? << 4 | nibble(pair[1])?;
        }
        Ok(Sha256::digest(bytes).into())
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
