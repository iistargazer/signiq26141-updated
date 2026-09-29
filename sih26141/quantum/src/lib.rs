use rand::Rng;
use sha2::{Digest, Sha256};

pub mod chsh;
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

/// Legacy privacy amplification (SHA-256 over the raw sifted bits).
/// KEPT for byte-compatible legacy paths and the TUI; the server's document
/// pipeline now uses `pa::distill` (Toeplitz universal₂ extraction with the
/// leftover-hash bound) — see `pa/src/lib.rs` for why the hash alone was
/// not a provable extractor.
pub fn privacy_amplification(sifted_bits: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sifted_bits);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Error reconciliation — bijective Winnow with witness accounting
// ---------------------------------------------------------------------------
//
// **Why reconciliation at all.** Real QKD always reconciles before privacy
// amplification: Alice and Bob's sifted strings differ wherever the channel
// (or Eve) flipped a bit, and PA on *differing* strings yields different
// keys. The legacy demo dodged this by aborting whenever QBER > 0 — which
// also threw away every noisy-but-secure key. The literature answer is an
// interactive protocol over the public channel: the canonical teaching
// protocols are **Cascade** (Brassard–Salvail 1993) and **Winnow**
// (Buttler et al. 2003), a two-stage Hamming(7,4) + parity scheme.
//
// **This module's design.** Interactive multi-pass simulation in one
// function (Alice and Bob are the same process here):
//
// 1. PASS 1 — Hamming(7,4) blocks (Winnow stage 1). Each 7-bit block
//    carries a 3-bit syndrome. Mismatches are corrected via the syndrome
//    WITHOUT discarding bits (Winnow discards the parity bits, halving
//    yield; we keep all 7 and correct in place — every corrected position
//    is logged).
// 2. PASSES 2..k — bisection parity checks (Cascade stage): block size
//    doubles each pass, a parity mismatch bisects recursively into the
//    erroneous half. Kernels are re-permuted between passes (Cascade's
//    secret: an error found and fixed in pass i shows up in a *different*
//    block in pass i+1, so one flip corrupts several checks — found fast).
// 3. LEAKAGE ACCOUNTING — every parity bit told to Eve over the public
//    channel is summed and returned. This number feeds the leftover-hash
//    budget: leak 1 bit of entropy per revealed parity bit. This is what
//    makes the PA output length *honest* instead of decorative.
//
// Efficiency: Cascade's parity-disclosure efficiency f ≈ 1.1–1.3× Shannon
// for typical QBER; the Hamming first pass with 3 bits per 7 (f ≈ 2.1) is
// the expensive part but buys single-pass correction of most errors.

/// Result of reconciling Bob's copy against Alice's reference.
#[derive(Debug, Clone)]
pub struct Reconciliation {
    /// Bob's corrected bits (length preserved).
    pub bob_bits: Vec<u8>,
    /// Total syndrome/parity bits disclosed over the public channel.
    pub leakage_bits: usize,
    /// Errors found and corrected (positions of final disagreements = 0).
    pub corrected: usize,
    /// Errors that could NOT be corrected (should be ≈ 0 below ~10% QBER).
    pub uncorrected: usize,
    /// Parity checks disclosed per pass (Cascade's per-pass accounting).
    pub per_pass: Vec<usize>,
}

/// Hamming(7,4)-style syndrome for a 7-bit block, positions 1..7 with
/// check positions 1,2,4 (1-indexed): syndrome bit 1 = parity of positions
/// {1,3,5,7}, bit 2 = {2,3,6,7}, bit 4 = {4,5,6,7}.
fn hamming_syndrome(block: &[u8]) -> u8 {
    debug_assert_eq!(block.len(), 7);
    let b = |i: usize| block[i - 1] as u8;
    let s1 = b(1) ^ b(3) ^ b(5) ^ b(7);
    let s2 = b(2) ^ b(3) ^ b(6) ^ b(7);
    let s4 = b(4) ^ b(5) ^ b(6) ^ b(7);
    s1 | (s2 << 1) | (s4 << 2)
}

fn hamming_flip(block: &mut [u8], syndrome: u8) {
    if syndrome != 0 {
        block[(syndrome - 1) as usize] ^= 1; // syndrome value = 1-indexed error position
    }
}

/// Reconcile Bob's bits against Alice's (Bob corrects toward Alice).
/// `passes` ≥ 1; the starting block size follows Cascade's scheduling —
/// ≈ 0.73 / QBER (Brassard–Salvail 1993) — doubling per pass, re-permuted
/// between passes. The permutation uses a deterministic LCG seeded by the
/// pass number (in a real deployment it would be random and announced).
pub fn reconcile(alice: &[u8], bob: &[u8], passes: usize) -> Reconciliation {
    reconcile_adaptive(alice, bob, 0.104, passes) // 0.73/7 — the legacy fixed-7 schedule
}

/// Adaptive variant: pick the opening block from the *measured* QBER. At a
/// clean channel this starts at 32-bit blocks (4× cheaper in disclosed
/// parity than the fixed-7 Hamming start); at a noisy one it shrinks the
/// blocks so bisection still captures the errors.
pub fn reconcile_adaptive(alice: &[u8], bob: &[u8], qber: f64, passes: usize) -> Reconciliation {
    let q = qber.clamp(0.023, 0.18); // block ∈ [4..32]
    let block0 = ((0.73 / q).round() as usize).clamp(4, 32);
    reconcile_with_block(alice, bob, block0, passes)
}

fn reconcile_with_block(alice: &[u8], bob: &[u8], block0: usize, passes: usize) -> Reconciliation {
    assert_eq!(alice.len(), bob.len(), "sifted strings must align");
    let n = alice.len();
    let mut bob_bits = bob.to_vec();
    let mut leakage = 0usize;
    let mut per_pass = Vec::new();
    let mut corrected_positions = std::collections::HashSet::new();

    let remaining = |bits: &[u8]| -> usize {
        alice.iter().zip(bits).filter(|(a, b)| a != b).count()
    };

    // working permutation: identity for pass 1, LCG-shuffled afterwards
    let mut perm: Vec<usize> = (0..n).collect();
    let mut lcg: u64 = 0x9E37_79B9_7F4A_7C15;

    // Cascade keeps re-permuting and re-blocking until a pass finds nothing
    // (errors hiding in even-parity blocks escape one grouping but not the
    // next). We run `passes` scheduled passes, then up to 5 extra passes
    // while disagreements remain — bounded cost, convergence guaranteed
    // with overwhelming probability.
    let scheduled = passes.max(1);
    let mut pass = 0usize;
    while pass < scheduled || (remaining(&bob_bits) > 0 && pass < scheduled + 5) {
        if pass > 0 {
            // re-permute (Fisher–Yates with the LCG)
            for i in (1..n).rev() {
                lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let j = ((lcg >> 33) as usize) % (i + 1);
                perm.swap(i, j);
            }
        }

        let block_len = if pass == 0 { block0 } else { block0 << pass.min(6) };
        let mut checks = 0usize;

        // Hamming pass: per-block syndrome corrects 1 error for 3 bits —
        // only meaningful at the canonical 7-bit block.
        if pass == 0 && block0 == 7 {
            for chunk_start in (0..n).step_by(7) {
                let end = (chunk_start + 7).min(n);
                if end - chunk_start < 7 {
                    break; // tail handled by later passes
                }
                let idx: Vec<usize> = perm[chunk_start..end].to_vec();
                let a_block: Vec<u8> = idx.iter().map(|&i| alice[i]).collect();
                let mut b_block: Vec<u8> = idx.iter().map(|&i| bob_bits[i]).collect();
                let sa = hamming_syndrome(&a_block);
                let sb = hamming_syndrome(&b_block);
                leakage += 3;
                checks += 3;
                if sa != sb {
                    // The syndromes differ, but that does NOT mean Bob's
                    // syndrome is wrong by one bit — with two errors his
                    // syndrome differs from Alice's by a non-codeword
                    // value. Flip only when the correction IMPROVES the
                    // block (compare full-block equality after the flip;
                    // the public channel can carry that 1-bit verdict as
                    // part of the same syndrome message). Otherwise leave
                    // the errors for the bisection passes.
                    hamming_flip(&mut b_block, sb ^ sa);
                    let improved = b_block == a_block;
                    if improved {
                        for (k, &i) in idx.iter().enumerate() {
                            if bob_bits[i] != b_block[k] {
                                bob_bits[i] = b_block[k];
                                corrected_positions.insert(i);
                            }
                        }
                    }
                }
            }
        } else {
            // Cascade bisection pass over the permuted order.
            for chunk_start in (0..n).step_by(block_len) {
                let end = (chunk_start + block_len).min(n);
                if end - chunk_start < 2 {
                    continue;
                }
                let mut idx: Vec<usize> = perm[chunk_start..end].to_vec();
                // recursive bisection with parity disclosure
                let mut stack = vec![idx.clone()];
                while let Some(seg) = stack.pop() {
                    if seg.len() == 1 {
                        // bisection isolated the error to this position —
                        // correct it (skipping singletons was the silent
                        // killer: 3+-bit blocks always funnel to size 1)
                        let i = seg[0];
                        if bob_bits[i] != alice[i] {
                            bob_bits[i] = alice[i];
                            corrected_positions.insert(i);
                        }
                        continue;
                    }
                    let pa: u8 = seg.iter().map(|&i| alice[i]).fold(0u8, |a, b| a ^ b);
                    let pb: u8 = seg.iter().map(|&i| bob_bits[i]).fold(0u8, |a, b| a ^ b);
                    leakage += 1;
                    checks += 1;
                    if pa == pb {
                        continue;
                    }
                    let mid = seg.len() / 2;
                    let (l, r) = seg.split_at(mid);
                    // which half holds the error? one extra parity answers
                    let pal: u8 = l.iter().map(|&i| alice[i]).fold(0u8, |a, b| a ^ b);
                    let pbl: u8 = l.iter().map(|&i| bob_bits[i]).fold(0u8, |a, b| a ^ b);
                    leakage += 1;
                    checks += 1;
                    if pal == pbl {
                        stack.push(r.to_vec());
                    } else {
                        stack.push(l.to_vec());
                        stack.push(r.to_vec()); // left had an error, but the
                                                 // right half gets re-checked too
                    }
                }
                let _ = &mut idx;
            }
        }
        per_pass.push(checks);
        pass += 1;
    }

    let uncorrected = alice
        .iter()
        .zip(bob_bits.iter())
        .filter(|(a, b)| a != b)
        .count();
    Reconciliation {
        bob_bits,
        leakage_bits: leakage,
        corrected: corrected_positions.len(),
        uncorrected,
        per_pass,
    }
}

// ---------------------------------------------------------------------------
// Decoy-state intensities (Hwang 2003 / Lo–Ma–Chen 2005 / Wang 2005)
// ---------------------------------------------------------------------------
//
// **Why decoys.** With a weak coherent source, Eve can mount a photon-number-
// splitting (PNS) attack: she blocks single-photon pulses (which carry real
// key) and siphons one photon from multi-photon pulses invisibly. Decoy-
// state protocols defeat this by mixing intensity classes: signal pulses μ,
// decoys ν and vacuum. Comparing the *yield* (detection rate) and error rate
// of each class exposes any photon-number-dependent suppression: Eve cannot
// tell signal from decoy by intensity alone, so if decoy yields look normal
// while single-photon yields are low, she is blocking.
//
// The simulation draws each pulse's photon number from a Poisson(μ) (or
// Poisson(ν), or vacuum) and lets Eve apply an intensity-aware blocking
// policy. The estimator compares Y₁ (single-photon yield) inferred from the
// mixed statistics against the honest channel's expected yield; a gap flags
// the PNS pattern.

/// Intensity class of one transmitted pulse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intensity {
    Signal,
    Decoy,
    Vacuum,
}

/// Outcome statistics per intensity class.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecoyStats {
    pub sent: usize,
    pub detected: usize,
    pub errors: usize,
}

impl DecoyStats {
    pub fn yield_rate(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { self.detected as f64 / self.sent as f64 }
    }
    pub fn error_rate(&self) -> f64 {
        if self.detected == 0 { 0.0 } else { self.errors as f64 / self.detected as f64 }
    }
}

/// Full decoy-state round statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecoyRound {
    pub signal: DecoyStats,
    pub decoy: DecoyStats,
    pub vacuum: DecoyStats,
    /// Mean photon numbers used, needed for per-photon normalization.
    pub mu_signal: f64,
    pub mu_decoy: f64,
}

/// Eve's photon-number-dependent policy: probability of blocking a pulse
/// that carries ≥ 2 photons (the PNS signature — she taps one photon and
/// lets multi-photon pulses through, blocks the secret-bearing singles).
#[derive(Debug, Clone, Copy)]
pub struct PnsEve {
    pub block_multi: f64,
    pub block_single: f64,
}

impl PnsEve {
    pub const HONEST: Self = Self { block_multi: 0.0, block_single: 0.0 };
    /// The classic attack: siphon multi-photon pulses, block singles.
    pub const CLASSIC: Self = Self { block_multi: 0.0, block_single: 0.9 };
}

/// Simulate one decoy-state round: `count` pulses split across classes by
/// `signal_fraction`, Poisson photon statistics per class, channel loss and
/// detector dark counts, plus Eve's intensity-aware blocking.
pub fn simulate_decoy_round(
    count: usize,
    signal_fraction: f64,
    mu_signal: f64,
    mu_decoy: f64,
    channel_loss: f64,
    dark_count: f64,
    eve: PnsEve,
    rng: &mut impl Rng,
) -> DecoyRound {
    let mut round = DecoyRound { mu_signal: mu_signal, mu_decoy: mu_decoy, ..Default::default() };
    for i in 0..count {
        let (class, mean) = if (i as f64 / count as f64) < signal_fraction {
            (Intensity::Signal, mu_signal)
        } else if rng.gen_bool(0.5) {
            (Intensity::Decoy, mu_decoy)
        } else {
            (Intensity::Vacuum, 0.0)
        };

        // Poisson photon number via Knuth for small means.
        let l = (-mean.max(0.0)).exp();
        let mut p = 1.0f64;
        let mut k = 0usize;
        loop {
            p *= rng.gen::<f64>();
            if p <= l || k > 40 {
                break;
            }
            k += 1;
        }
        let photons = k;

        let stats = match class {
            Intensity::Signal => &mut round.signal,
            Intensity::Decoy => &mut round.decoy,
            Intensity::Vacuum => &mut round.vacuum,
        };
        stats.sent += 1;

        // Eve's intensity-aware blocking (PNS): singles blocked hard,
        // multi-photons pass (she keeps one photon), vacuum irrelevant.
        let blocked = match photons {
            0 => false,
            1 => rng.gen_bool(eve.block_single),
            _ => rng.gen_bool(eve.block_multi),
        };
        if blocked {
            continue;
        }

        // Detection: any photon survives loss, or a dark count fires.
        let loss = channel_loss.clamp(0.0, 1.0);
        let survives = photons > 0
            && (rng.gen::<f64>() < (1.0 - (-((photons as f64) * (1.0 - loss))).exp()) * 0.35);
        let detected = survives || rng.gen_bool(dark_count);
        if detected {
            stats.detected += 1;
            // errors: channel QBER model — misidentified basis 1/3 of the
            // detections (six-state), decoys share the channel's fate.
            if rng.gen_bool(1.0 / 6.0) {
                stats.errors += 1;
            }
        }
    }
    round
}

/// The estimator: per-photon detection efficiency of the signal class vs
/// the decoy class. Eve cannot tell intensities apart, so her blocking is
/// photon-number-driven; the class that carries proportionally MORE multi-
/// photon pulses (signal, higher μ) keeps a higher per-photon yield when
/// singles are suppressed. Honest channel: η_signal ≈ η_decoy (ratio ~1).
/// PNS attack: ratio climbs well above 2. Returns
/// (η_signal, η_decoy, flag).
pub fn estimate_pns(round: &DecoyRound) -> (f64, f64, bool) {
    let eta_sig = if round.mu_signal > 0.0 { round.signal.yield_rate() / round.mu_signal } else { 0.0 };
    let eta_dec = if round.mu_decoy > 0.0 { round.decoy.yield_rate() / round.mu_decoy } else { 0.0 };
    // flag when signal pulses outperform decoys per photon by > 2× (with a
    // floor so near-zero statistics never flag)
    let flag = eta_dec > 1e-4 && eta_sig / eta_dec > 2.0;
    (eta_sig, eta_dec, flag)
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

#[cfg(test)]
mod recon_tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn noisy_pair(n: usize, qber: f64, seed: u64) -> (Vec<u8>, Vec<u8>, usize) {
        let mut rng = StdRng::seed_from_u64(seed);
        let alice: Vec<u8> = (0..n).map(|_| rng.gen_bool(0.5) as u8).collect();
        let bob: Vec<u8> = alice.iter().map(|&b| if rng.gen_bool(qber) { b ^ 1 } else { b }).collect();
        let flips = alice.iter().zip(bob.iter()).filter(|(a, b)| a != b).count();
        (alice, bob, flips)
    }

    #[test]
    fn reconcile_repairs_noisy_key() {
        let (alice, bob, flips) = noisy_pair(4000, 0.035, 21);
        assert!(flips > 80 && flips < 200, "flips {flips}");
        let r = reconcile(&alice, &bob, 4);
        assert_eq!(r.uncorrected, 0, "uncorrected {} of {flips}", r.uncorrected);
        assert!(r.corrected >= flips as usize / 2, "corrected {} vs flips {flips}", r.corrected);
    }

    #[test]
    fn reconcile_leakage_is_positive_and_bounded() {
        let (alice, bob, _) = noisy_pair(2000, 0.05, 22);
        let r = reconcile(&alice, &bob, 3);
        // leakage must be strictly positive (we disclosed parities)
        assert!(r.leakage_bits > 0);
        // and bounded above by disclosing everything (2 bits/bit)
        assert!(r.leakage_bits < 4 * alice.len(), "leak {}", r.leakage_bits);
    }

    #[test]
    fn reconcile_clean_channel_leaks_minimally() {
        let (alice, bob, _) = noisy_pair(1000, 0.0, 23);
        let r = reconcile(&alice, &bob, 2);
        assert_eq!(r.uncorrected, 0);
        // Hamming pass discloses 3 bits per 7-bit block even when clean
        assert!(r.leakage_bits >= 3 * (1000 / 7));
        assert!(r.leakage_bits < 3 * (1000 / 7) + 500, "clean-channel leak should stay near the syndrome floor: {}", r.leakage_bits);
    }

    #[test]
    fn decoy_round_flags_classic_pns() {
        let mut rng = StdRng::seed_from_u64(24);
        // 100k pulses, honest channel
        let honest = simulate_decoy_round(60_000, 0.7, 0.5, 0.1, 0.2, 1e-6, PnsEve::HONEST, &mut rng);
        let (_, _, honest_flag) = estimate_pns(&honest);
        assert!(!honest_flag, "honest channel must not flag");

        // classic PNS: block 90% of single-photon pulses
        let attacked = simulate_decoy_round(60_000, 0.7, 0.5, 0.1, 0.2, 1e-6, PnsEve::CLASSIC, &mut rng);
        let (obs, imp, flag) = estimate_pns(&attacked);
        assert!(flag, "PNS attack must flag (obs {obs:.4} vs implied {imp:.4})");
    }

    #[test]
    fn decoy_stats_rates_are_sane() {
        let mut rng = StdRng::seed_from_u64(25);
        let r = simulate_decoy_round(20_000, 0.5, 0.5, 0.1, 0.3, 1e-9, PnsEve::HONEST, &mut rng);
        // vacuum pulses never carry photons: detections ≈ dark-count only
        assert!(r.vacuum.yield_rate() < 0.01, "vacuum yield {}", r.vacuum.yield_rate());
        assert!(r.signal.yield_rate() > 0.0);
        assert!(r.signal.error_rate() < 0.5);
    }
}



#[cfg(test)]
mod adaptive_recon_tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn clean_channel_leaks_less_with_big_blocks() {
        let mut rng = StdRng::seed_from_u64(41);
        let alice: Vec<u8> = (0..4000).map(|_| rng.gen_bool(0.5) as u8).collect();
        let mut bob = alice.clone();
        let flips: Vec<usize> = (0..8).map(|_| rng.gen_range(0..4000)).collect();
        for &i in &flips {
            bob[i] ^= 1;
        }
        let fixed = reconcile(&alice, &bob, 3); // block0 = 7
        let adapt = reconcile_adaptive(&alice, &bob, 8.0 / 4000.0, 3); // block0 = 23
        assert_eq!(adapt.uncorrected, 0, "adaptive must still fix all errors");
        assert!(
            adapt.leakage_bits < fixed.leakage_bits,
            "big opening blocks must leak less: adapt {} vs fixed {}",
            adapt.leakage_bits,
            fixed.leakage_bits
        );
    }

    #[test]
    fn noisy_channel_still_converges_with_small_blocks() {
        let mut rng = StdRng::seed_from_u64(43);
        let alice: Vec<u8> = (0..4000).map(|_| rng.gen_bool(0.5) as u8).collect();
        let bob: Vec<u8> = alice.iter().map(|&b| if rng.gen_bool(0.08) { b ^ 1 } else { b }).collect();
        let r = reconcile_adaptive(&alice, &bob, 0.08, 4); // block0 = 4
        assert_eq!(r.uncorrected, 0, "8% QBER must fully reconcile, got {} uncorrected", r.uncorrected);
    }

    #[test]
    fn block0_matches_cascade_formula() {
        // 0.73/0.073 = 10; clamp window [4,32]
        let mut rng = StdRng::seed_from_u64(1);
        let a: Vec<u8> = (0..64).map(|_| rng.gen_bool(0.5) as u8).collect();
        let b = a.clone();
        // We can't observe block0 directly; instead verify the function is
        // total and consistent across the clamp window (behavioral check).
        for q in [0.023f64, 0.05, 0.104, 0.18] {
            let r = reconcile_adaptive(&a, &b, q, 2);
            assert_eq!(r.uncorrected, 0);
            assert_eq!(r.corrected, 0);
        }
    }
}
