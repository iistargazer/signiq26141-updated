use rand::Rng;
use sha2::{Digest, Sha256};

pub mod relay;
pub use relay::{RelayRoute, RelayTransmission};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauliBasis {
    X = 0,
    Y = 1,
    Z = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauliState {
    Positive = 1,
    Negative = -1,
}

impl PauliState {
    fn as_bit(self) -> u8 {
        match self {
            PauliState::Positive => 1,
            PauliState::Negative => 0,
        }
    }
}

pub struct QuantumKeyGenerator {
    key_length: usize,
}

impl QuantumKeyGenerator {
    pub fn new(key_length: usize) -> Result<Self, &'static str> {
        if key_length == 0 {
            return Err("Key length cannot be zero.");
        }
        Ok(Self { key_length })
    }

    /// Alice's private Pauli eigenstates (six-state protocol preparation)
    pub fn generate_eigenstates(&self, rng: &mut impl Rng) -> Vec<(PauliBasis, PauliState)> {
        let mut keys = Vec::with_capacity(self.key_length);
        for _ in 0..self.key_length {
            let basis = match rng.gen_range(0..3) {
                0 => PauliBasis::X,
                1 => PauliBasis::Y,
                _ => PauliBasis::Z,
            };
            let state = if rng.gen_bool(0.5) {
                PauliState::Positive
            } else {
                PauliState::Negative
            };
            keys.push((basis, state));
        }
        keys
    }
}

/// Simulation result carrying raw sifted bits and sifting metrics
pub struct SiftedKeyResult {
    /// Bob's bits at ALL sifted positions — errors included
    pub sifted_key_bits: Vec<u8>,
    /// Alice's bits at the same positions (for parameter estimation)
    pub alice_sifted_bits: Vec<u8>,
    pub mismatch_rate: f64,
    pub matching_bases_count: usize,
    /// Environmental noise rate used for this transmission (independent of
    /// any attack): the probability a sifted bit is flipped in flight.
    pub noise_rate: f64,
}

pub(crate) fn random_basis(rng: &mut impl Rng) -> PauliBasis {
    match rng.gen_range(0..3) {
        0 => PauliBasis::X,
        1 => PauliBasis::Y,
        _ => PauliBasis::Z,
    }
}

/// Six-state prepare-and-measure transmission, sifting, and QBER estimation.
pub fn simulate_six_state_transmission(
    private_key: &[(PauliBasis, PauliState)],
    intercept_resend: bool,
    rng: &mut impl Rng,
) -> SiftedKeyResult {
    simulate_six_state_transmission_ratio(
        private_key,
        if intercept_resend { 1.0 } else { 0.0 },
        0.0,
        rng,
    )
}

/// Incremental six-state channel session: feed Alice's qubits one at a time
/// and observe running sifting statistics. Powers streaming simulations.
pub struct ChannelSession {
    intercept_ratio: f64,
    /// Environmental (non-adversarial) bit-flip probability applied to the
    /// state in flight — fiber attenuation / turbulence model. Independent
    /// of `intercept_ratio`: Eve measures-and-resends, nature just flips.
    noise_rate: f64,
    sifted_key_bits: Vec<u8>,
    alice_sifted_bits: Vec<u8>,
    mismatches: usize,
    matching_bases_count: usize,
}

/// A sifted measurement outcome (only emitted when Bob's basis matched Alice's).
#[derive(Debug, Clone, Copy)]
pub struct TransmissionStep {
    pub sifted_index: usize,
    pub alice_bit: u8,
    pub bob_bit: u8,
    pub basis_alice: PauliBasis,
    pub basis_bob: PauliBasis,
}

impl ChannelSession {
    pub fn new(intercept_ratio: f64) -> Self {
        Self {
            intercept_ratio: intercept_ratio.clamp(0.0, 1.0),
            noise_rate: 0.0,
            sifted_key_bits: Vec::new(),
            alice_sifted_bits: Vec::new(),
            mismatches: 0,
            matching_bases_count: 0,
        }
    }

    /// Builder: set the environmental bit-flip probability (0.0–1.0).
    pub fn with_noise(mut self, noise_rate: f64) -> Self {
        self.noise_rate = noise_rate.clamp(0.0, 1.0);
        self
    }

    /// Environmental noise level this session was configured with.
    pub fn noise_rate(&self) -> f64 {
        self.noise_rate
    }

    /// Transmit one qubit. Returns `Some(step)` when the bases matched and
    /// the position is retained after sifting.
    pub fn transmit(
        &mut self,
        basis_alice: PauliBasis,
        state_alice: PauliState,
        rng: &mut impl Rng,
    ) -> Option<TransmissionStep> {
        let basis_bob = random_basis(rng);

        // State on the wire when it reaches Bob
        let (mut current_state, mut current_basis) = (state_alice, basis_alice);

        // Environmental noise: a fiber-photon loss/impurity event flips the
        // polarization in flight. Unlike intercept-resend this does NOT
        // change the state's basis — nature disturbs, Eve measures.
        if self.noise_rate > 0.0 && rng.gen_bool(self.noise_rate) {
            current_state = match current_state {
                PauliState::Positive => PauliState::Negative,
                PauliState::Negative => PauliState::Positive,
            };
        }

        let intercepted = self.intercept_ratio > 0.0 && rng.gen_bool(self.intercept_ratio);
        if intercepted {
            let basis_eve = random_basis(rng);
            if basis_eve != current_basis {
                // Eve measured in the wrong basis: her outcome is random,
                // the state collapses, and she resends in HER basis
                current_state = if rng.gen_bool(0.5) {
                    PauliState::Positive
                } else {
                    PauliState::Negative
                };
                current_basis = basis_eve;
            }
        }

        // Sift against ALICE's basis, never Eve's resend basis
        if basis_bob == basis_alice {
            self.matching_bases_count += 1;

            // Bob's outcome is deterministic only if he measures in the
            // outgoing basis; otherwise it is random (state disturbance)
            let bob_bit = if basis_bob == current_basis {
                current_state.as_bit()
            } else if rng.gen_bool(0.5) {
                1
            } else {
                0
            };

            let alice_bit = state_alice.as_bit();
            if bob_bit != alice_bit {
                self.mismatches += 1;
            }

            // Keep every sifted bit — errors are only revealed later
            self.sifted_key_bits.push(bob_bit);
            self.alice_sifted_bits.push(alice_bit);

            return Some(TransmissionStep {
                sifted_index: self.sifted_key_bits.len() - 1,
                alice_bit,
                bob_bit,
                basis_alice,
                basis_bob,
            });
        }
        None
    }

    pub fn sifted_count(&self) -> usize {
        self.sifted_key_bits.len()
    }

    pub fn mismatch_count(&self) -> usize {
        self.mismatches
    }

    pub fn qber(&self) -> f64 {
        if self.matching_bases_count == 0 {
            1.0
        } else {
            self.mismatches as f64 / self.matching_bases_count as f64
        }
    }

    pub fn matching_bases_count(&self) -> usize {
        self.matching_bases_count
    }

    /// Consume the session and produce the final sifted-key result.
    pub fn finish(self) -> SiftedKeyResult {
        let mismatch_rate = self.qber();
        SiftedKeyResult {
            sifted_key_bits: self.sifted_key_bits,
            alice_sifted_bits: self.alice_sifted_bits,
            mismatch_rate,
            matching_bases_count: self.matching_bases_count,
            noise_rate: self.noise_rate,
        }
    }
}

/// Six-state transmission with Eve intercepting a fraction `intercept_ratio`
/// of the qubits (0.0 = clean channel, 1.0 = full intercept-resend).
/// Expected QBER ≈ intercept_ratio / 3. `noise_rate` is the independent
/// environmental bit-flip probability (e.g. 0.03 = 3% fiber noise).
pub fn simulate_six_state_transmission_ratio(
    private_key: &[(PauliBasis, PauliState)],
    intercept_ratio: f64,
    noise_rate: f64,
    rng: &mut impl Rng,
) -> SiftedKeyResult {
    let mut session = ChannelSession::new(intercept_ratio).with_noise(noise_rate);
    for &(basis_alice, state_alice) in private_key {
        session.transmit(basis_alice, state_alice, rng);
    }
    session.finish()
}

/// Simplified privacy amplification (SHA-256). Real QKD needs a universal2
/// hash with output length tied to estimated entropy and leakage.
pub fn privacy_amplification(sifted_bits: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sifted_bits);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_key(n: usize, seed: u64) -> Vec<(PauliBasis, PauliState)> {
        QuantumKeyGenerator::new(n)
            .unwrap()
            .generate_eigenstates(&mut StdRng::seed_from_u64(seed))
    }

    #[test]
    fn zero_ratio_matches_secure_channel() {
        let key = make_key(4000, 7);
        let res = simulate_six_state_transmission_ratio(&key, 0.0, 0.0, &mut StdRng::seed_from_u64(7));
        assert_eq!(res.sifted_key_bits, res.alice_sifted_bits);
        assert_eq!(res.mismatch_rate, 0.0);
    }

    #[test]
    fn full_ratio_matches_intercept_resend() {
        let key = make_key(4000, 7);
        let res = simulate_six_state_transmission_ratio(&key, 1.0, 0.0, &mut StdRng::seed_from_u64(7));
        assert_ne!(res.sifted_key_bits, res.alice_sifted_bits);
        // Intercept-resend QBER on six-state ≈ 1/3
        assert!(res.mismatch_rate > 0.2 && res.mismatch_rate < 0.45);
    }

    #[test]
    fn partial_ratio_yields_intermediate_qber() {
        let key = make_key(20000, 11);
        let res = simulate_six_state_transmission_ratio(&key, 0.3, 0.0, &mut StdRng::seed_from_u64(11));
        // Expected ≈ 0.1
        assert!(res.mismatch_rate > 0.04 && res.mismatch_rate < 0.16);
    }

    #[test]
    fn environmental_noise_adds_qber_without_eve() {
        // Pure 3% fiber noise, no eavesdropping: QBER ≈ noise_rate.
        let key = make_key(20000, 13);
        let res = simulate_six_state_transmission_ratio(&key, 0.0, 0.03, &mut StdRng::seed_from_u64(13));
        assert!(res.mismatch_rate > 0.015 && res.mismatch_rate < 0.05, "qber {}", res.mismatch_rate);
    }

    #[test]
    fn noise_and_attack_are_independent_contributions() {
        // intercept 0.15 ⇒ ≈5% + noise 5% ⇒ ≈10% QBER (independent events).
        let key = make_key(30000, 17);
        let res = simulate_six_state_transmission_ratio(&key, 0.15, 0.05, &mut StdRng::seed_from_u64(17));
        assert!(res.mismatch_rate > 0.055 && res.mismatch_rate < 0.145, "qber {}", res.mismatch_rate);
    }
}
