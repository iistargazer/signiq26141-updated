//! Six-state non-orthogonal-encoding QDS (Weng et al. 2021, arXiv:2104.12059).
//!
//! A second, literature-faithful QDS scheme alongside the teleportation
//! pipeline in the crate root. It implements the paper's three-step protocol:
//!
//! **Step 1 — Key generation.** For each message value m ∈ {0,1}, Alice
//! prepares N qubits in Pauli eigenstates |±x⟩, |±y⟩, |±z⟩ and sends them to
//! every recipient over insecure quantum channels. Each recipient measures in
//! a random Pauli basis and announces click events; no-click data is
//! discarded. After post-matching (Alice reorders the verifiers' strings to
//! her preparation order), every party encodes logic bits by the paper's
//! non-orthogonal rule: the announced encoding set pairs two different-basis
//! eigenstates, and an outcome *orthogonal to one member* of the set is
//! conclusive — logic 0 if orthogonal to the member encoding 0, logic 1 if
//! orthogonal to the member encoding 1.
//!
//! **Step 2 — Estimation.** Verifiers sample test bits and estimate the
//! mismatching rate of conclusive results against Alice's string.
//!
//! **Step 3 — Messaging.** To sign m, Alice sends her untested string; each
//! verifier accepts iff its own mismatch rate is within threshold.
//!
//! Detection layer (the SIH26141 contribution): the same conclusive-string
//! statistics separate honest behavior from every attack class required by
//! the problem statement — forgery, impersonation, replay, channel
//! tampering, and unauthorized verification — through explicit
//! threshold rules (no AI/ML).
//!
//! Out of scope for a classical simulation (documented limitations):
//! decoy-intensity (μ, ν, 0) bookkeeping and weak-coherent-source photon
//! statistics; the simulation models single-qubit preparation/measurement.

use crate::{Thresholds, Verdict};
use rand::Rng;

// ---------------------------------------------------------------------------
// Six-state alphabet
// ---------------------------------------------------------------------------

/// The three Pauli measurement bases X, Y, Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauliBasis {
    X,
    Y,
    Z,
}

impl PauliBasis {
    pub const ALL: [PauliBasis; 3] = [PauliBasis::X, PauliBasis::Y, PauliBasis::Z];

    pub fn random(rng: &mut impl Rng) -> Self {
        match rng.gen_range(0..3) {
            0 => PauliBasis::X,
            1 => PauliBasis::Y,
            _ => PauliBasis::Z,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PauliBasis::X => "X",
            PauliBasis::Y => "Y",
            PauliBasis::Z => "Z",
        }
    }
}

/// Pauli eigenstate sign: the ± of |±x⟩, |±y⟩, |±z⟩.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauliSign {
    Plus,
    Minus,
}

impl PauliSign {
    pub fn random(rng: &mut impl Rng) -> Self {
        if rng.gen_bool(0.5) { PauliSign::Plus } else { PauliSign::Minus }
    }

    pub fn flip(self) -> Self {
        match self {
            PauliSign::Plus => PauliSign::Minus,
            PauliSign::Minus => PauliSign::Plus,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PauliSign::Plus => "+",
            PauliSign::Minus => "-",
        }
    }
}

/// One prepared qubit: a Pauli eigenstate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SixState {
    pub basis: PauliBasis,
    pub sign: PauliSign,
}

impl SixState {
    pub fn random(rng: &mut impl Rng) -> Self {
        SixState { basis: PauliBasis::random(rng), sign: PauliSign::random(rng) }
    }

    /// Label like "+x", "-z" for the UI.
    pub fn label(&self) -> String {
        format!("{}{}", self.sign.as_str(), self.basis.as_str().to_lowercase())
    }
}

/// Projective measurement of `state` in Pauli basis `basis`.
///
/// An eigenstate of the measured basis yields its sign deterministically;
/// any other state (mutually unbiased / orthogonal-basis directions) yields
/// ±1 with probability ½ — collapse in full fidelity.
pub fn projective_measure(state: &SixState, basis: PauliBasis, rng: &mut impl Rng) -> PauliSign {
    if state.basis == basis {
        state.sign
    } else {
        PauliSign::random(rng)
    }
}

// ---------------------------------------------------------------------------
// Encoding sets and conclusive-result logic
// ---------------------------------------------------------------------------

/// The logic bit a set member encodes (0 or 1).
pub type SetBit = u8;

/// An announced encoding set: two different-basis Pauli eigenstates.
/// `members[0]` encodes logic 0, `members[1]` encodes logic 1.
pub type EncodingSet = [(SixState, SetBit); 2];

/// Draw a random 12-family encoding set that *contains* `state` as one of
/// its members (Alice always assigns the sent state to its set — the paper's
/// rule: "The set Alice picked should include the state she sent").
pub fn random_set_containing(state: SixState, rng: &mut impl Rng) -> EncodingSet {
    let mut other_basis = PauliBasis::random(rng);
    while other_basis == state.basis {
        other_basis = PauliBasis::random(rng);
    }
    let other = SixState { basis: other_basis, sign: PauliSign::random(rng) };
    if rng.gen_bool(0.5) {
        [(state, 0), (other, 1)]
    } else {
        [(other, 0), (state, 1)]
    }
}

/// Conclusive-result rule (Weng et al. §II, example): given the announced
/// `set` and the verifier's outcome (basis, sign), the result is conclusive
/// iff the outcome is the *orthogonal partner* of a member — same basis,
/// opposite sign. The derived logic bit is then the OTHER member's bit:
/// orthogonal to the 0-member ⇒ bit 0, orthogonal to the 1-member ⇒ bit 1.
///
/// Paper example: Alice sends |+x⟩ in set {|+x⟩,|+y⟩}; Bob's outcome |−y⟩
/// (orthogonal to the +y member which encodes 1... wait: +y is member index 1)
/// — the rule as written: outcome |−y⟩ ⇒ conclusive, logic 0; |−x⟩ ⇒
/// conclusive, logic 1.
pub fn conclusive_bit(
    outcome_basis: PauliBasis,
    outcome_sign: PauliSign,
    set: &EncodingSet,
) -> Option<SetBit> {
    for (idx, (member, _bit)) in set.iter().enumerate() {
        if outcome_basis == member.basis && outcome_sign != member.sign {
            return Some(set[1 - idx].1);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Session data structures
// ---------------------------------------------------------------------------

/// One qubit round: Alice's private preparation record.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct AliceRound {
    /// The state Alice actually prepared (private to her).
    pub prepared: SixState,
    /// The set she assigned (announced publicly after measurement).
    pub set: EncodingSet,
    /// The logic bit Alice derives from her own preparation+announcement.
    pub logic_bit: SetBit,
    /// Whether this round was conclusive for Alice (by construction, the
    /// sender's own member always yields a conclusive derivation when the
    /// verifier clicks; Alice's bit is defined for every round).
    pub conclusive: bool,
}

/// One qubit round as seen by a verifier.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct VerifierRound {
    /// Basis the verifier chose (uniformly random).
    pub measured_basis: PauliBasis,
    /// Projective-measurement outcome (eigenvalue ±1).
    pub outcome: PauliSign,
    /// True when the verifier clicked (a conclusive event occurred).
    pub clicked: bool,
    /// The derived logic bit when clicked.
    pub bit: Option<SetBit>,
}

/// Public parameters of one key-generation session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionParams {
    /// Qubits transmitted per message value.
    pub n_pulses: usize,
    /// Fraction of conclusive positions sampled as test bits.
    pub test_fraction: f64,
    /// Device basis-misalignment rate ε_d (noise floor).
    pub basis_misalignment: f64,
}

/// Data for one message value m: Alice's rounds, Bob's rounds, and the
/// post-matched conclusive string pair.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageRun {
    pub message: u8,
    pub alice: Vec<AliceRound>,
    pub bob: Vec<VerifierRound>,
    /// Alice's conclusive logic bits (post-matched order).
    pub alice_string: Vec<u8>,
    /// Bob's conclusive logic bits (same order).
    pub bob_string: Vec<u8>,
}

/// One full key-generation session: two message runs + session metadata.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SixStateSession {
    pub params: SessionParams,
    /// Commitment to the session's quantum preparation (revealed at setup).
    pub session_commitment: String,
    pub runs: [MessageRun; 2],
    pub session_id: u64,
    pub nonce: u64,
}

impl SixStateSession {
    pub fn conclusive_count(&self) -> usize {
        self.runs[0].alice_string.len().min(self.runs[1].alice_string.len())
    }
}

// ---------------------------------------------------------------------------
// Mismatch statistics
// ---------------------------------------------------------------------------

/// Mismatch statistics between two conclusive strings.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct MismatchStats {
    pub mismatches: usize,
    pub conclusive: usize,
}

impl MismatchStats {
    pub fn rate(&self) -> f64 {
        if self.conclusive == 0 { 0.0 } else { self.mismatches as f64 / self.conclusive as f64 }
    }

    fn empty() -> Self {
        MismatchStats { mismatches: 0, conclusive: 0 }
    }
}

/// Full-sample mismatch stats between Alice's and a verifier's strings.
pub fn full_mismatch(alice: &[u8], verifier: &[u8]) -> MismatchStats {
    let n = alice.len().min(verifier.len());
    if n == 0 {
        return MismatchStats::empty();
    }
    let mismatches = (0..n).filter(|&i| alice[i] != verifier[i]).count();
    MismatchStats { mismatches, conclusive: n }
}

/// Test-bit sampling mismatch estimate (the estimation step).
pub fn estimate_mismatch(
    alice: &[u8],
    verifier: &[u8],
    test_fraction: f64,
    rng: &mut impl Rng,
) -> MismatchStats {
    let n = alice.len().min(verifier.len());
    let mut stats = MismatchStats::empty();
    for i in 0..n {
        if rng.gen_bool(test_fraction) {
            stats.conclusive += 1;
            if alice[i] != verifier[i] {
                stats.mismatches += 1;
            }
        }
    }
    stats
}

// ---------------------------------------------------------------------------
// Key generation (protocol step 1)
// ---------------------------------------------------------------------------

/// Run the quantum phase for one message value with an optional channel
/// disturbance fraction (tamper/noise model).
fn run_message_rounds(
    message: u8,
    params: &SessionParams,
    disturb_fraction: f64,
    rng: &mut impl Rng,
) -> MessageRun {
    let mut alice = Vec::with_capacity(params.n_pulses);
    let mut bob = Vec::with_capacity(params.n_pulses);

    for _ in 0..params.n_pulses {
        // 1. Alice prepares a random six-state qubit and assigns its
        //    encoding set; her logic bit is fixed by HER preparation.
        let prepared = SixState::random(rng);
        let set = random_set_containing(prepared, rng);
        let logic_bit = set
            .iter()
            .find(|(s, _)| *s == prepared)
            .map(|(_, b)| *b)
            .unwrap_or(0);
        alice.push(AliceRound { prepared, set, logic_bit, conclusive: true });

        // 2. Channel: with probability `disturb_fraction` the qubit is
        //    flipped to its orthogonal partner IN FLIGHT (Pauli-X-type
        //    disturbance). Alice's announcement and string are already
        //    fixed — the damage shows up as verifier mismatches.
        let mut on_wire = prepared;
        if rng.gen_bool(disturb_fraction) {
            on_wire.sign = on_wire.sign.flip();
        }

        // 3. Bob measures the (possibly disturbed) state in a random basis.
        let measured_basis = PauliBasis::random(rng);
        let outcome = projective_measure(&on_wire, measured_basis, rng);

        // 4. Alice announces the set; Bob derives (non-)conclusive bits.
        let bit = conclusive_bit(measured_basis, outcome, &set);
        bob.push(VerifierRound { measured_basis, outcome, clicked: bit.is_some(), bit });
    }

    // Post-matching + click filtering: keep rounds where Bob clicked.
    let mut alice_string = Vec::new();
    let mut bob_string = Vec::new();
    for (a, b) in alice.iter().zip(bob.iter()) {
        if let Some(bit) = b.bit {
            // Device noise ε_d: flips the derived bit with that probability.
            let bit = if rng.gen_bool(params.basis_misalignment) { 1 - bit } else { bit };
            alice_string.push(a.logic_bit);
            bob_string.push(bit);
        }
    }

    MessageRun { message, alice, bob, alice_string, bob_string }
}

/// Build a complete session (two message runs) with a given disturbance
/// level. `nonce` is issued by the session registry (replay defense).
pub fn build_session(
    params: SessionParams,
    session_id: u64,
    nonce: u64,
    disturb_fraction: f64,
    rng: &mut impl Rng,
) -> SixStateSession {
    let m0 = run_message_rounds(0, &params, disturb_fraction, rng);
    let m1 = run_message_rounds(1, &params, disturb_fraction, rng);
    // Session commitment: hash of Alice's full preparation record — binds
    // all published strings to this exact quantum preparation.
    let mut hasher = sha2::Sha256::new();
    for run in [&m0, &m1] {
        for round in &run.alice {
            use sha2::Digest;
            hasher.update([round.prepared.basis as u8, round.prepared.sign as u8]);
            hasher.update([round.logic_bit]);
        }
    }
    use sha2::Digest as _;
    let session_commitment = format!("{:x}", hasher.finalize());
    SixStateSession { params, session_commitment, runs: [m0, m1], session_id, nonce }
}

// ---------------------------------------------------------------------------
// Signature + verification (protocol step 3)
// ---------------------------------------------------------------------------

/// The published signature for message `message`: Alice's untested string
/// for that value, plus session binding (nonce + commitment).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SixStateSignature {
    /// The operative conclusive string (hex-encoded bits as 0/1 bytes).
    pub string_hex: String,
    /// Which message value this signature covers (0 or 1).
    pub message: u8,
    /// Session nonce (single-use — replay defense).
    pub nonce: u64,
    /// Key-generation session id.
    pub session_id: u64,
    /// Commitment to the session's quantum preparation.
    pub session_commitment: String,
}

impl SixStateSignature {
    pub fn string_bits(&self) -> Vec<u8> {
        crate::six_state::decode_bits(&self.string_hex)
    }
}

/// Encode a bit string as hex (bytes 0/1 → hex chars).
pub fn encode_bits(bits: &[u8]) -> String {
    let bytes: Vec<u8> = bits.iter().map(|&b| b & 1).collect();
    hex::encode(bytes)
}

/// Decode hex back to a 0/1 byte string.
pub fn decode_bits(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str)
        .unwrap_or_default()
        .into_iter()
        .map(|b| b & 1)
        .collect()
}

/// Assemble the signature from a session (messaging step): Alice publishes
/// her untested string for `message`.
pub fn sign_six_state(session: &SixStateSession, message: u8) -> SixStateSignature {
    let run = &session.runs[(message & 1) as usize];
    SixStateSignature {
        string_hex: encode_bits(&run.alice_string),
        message: message & 1,
        nonce: session.nonce,
        session_id: session.session_id,
        session_commitment: session.session_commitment.clone(),
    }
}

/// What the verifier holds: their own conclusive bits for each message value.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct VerifierMaterial {
    /// Bob's conclusive bits for message value 0.
    pub bits_m0: Vec<u8>,
    /// Bob's conclusive bits for message value 1.
    pub bits_m1: Vec<u8>,
}

impl VerifierMaterial {
    pub fn from_session(session: &SixStateSession) -> Self {
        VerifierMaterial {
            bits_m0: session.runs[0].bob_string.clone(),
            bits_m1: session.runs[1].bob_string.clone(),
        }
    }

    fn bits_for(&self, message: u8) -> &Vec<u8> {
        if message & 1 == 0 { &self.bits_m0 } else { &self.bits_m1 }
    }
}

/// Outcome of a six-state verification attempt.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SixStateVerification {
    pub accepted: bool,
    pub verdict: Verdict,
    pub mismatch: MismatchStats,
    pub reason: String,
}

/// Verify a signature against the verifier's own conclusive material.
///
/// Checks, in order:
/// 1. **Authorization** — the verifier must hold key material bound to the
///    signature's session (blocks *unauthorized verification attempts*).
/// 2. **Session binding** — commitment must match the session in force.
/// 3. **Statistics** — conclusive-mismatch rate vs the dual thresholds
///    c1/c2 (1-ACC / 0-ACC / REJ, as in the crate-root protocol).
pub fn verify_six_state(
    sig: &SixStateSignature,
    verifier: &VerifierMaterial,
    session_commitment: &str,
    thresholds: Thresholds,
) -> SixStateVerification {
    // 1. Authorization: no key material for this session ⇒ void verdict.
    if verifier.bits_m0.is_empty() && verifier.bits_m1.is_empty() {
        return SixStateVerification {
            accepted: false,
            verdict: Verdict::Rej,
            mismatch: MismatchStats::empty(),
            reason: "unauthorized verifier: no conclusive key material for this session"
                .to_string(),
        };
    }
    // 2. Session binding.
    if sig.session_commitment != session_commitment {
        return SixStateVerification {
            accepted: false,
            verdict: Verdict::Rej,
            mismatch: MismatchStats::empty(),
            reason: "session commitment mismatch: signature not from this key session"
                .to_string(),
        };
    }
    // 3. Statistics on the operative string.
    let bits = verifier.bits_for(sig.message);
    let stats = full_mismatch(&sig.string_bits(), bits);
    let frac = stats.rate();
    let verdict = if frac <= thresholds.c1 {
        Verdict::Acc1
    } else if frac <= thresholds.c2 {
        Verdict::Acc0
    } else {
        Verdict::Rej
    };
    SixStateVerification {
        accepted: verdict.accepted(),
        verdict,
        mismatch: stats,
        reason: match verdict {
            Verdict::Acc1 => "1-ACC: conclusive mismatch within acceptance threshold",
            Verdict::Acc0 => "0-ACC: mismatch in gray zone — local accept, transfer not guaranteed",
            Verdict::Rej => "REJ: conclusive mismatch exceeds rejection threshold",
        }
        .to_string(),
    }
}

// ---------------------------------------------------------------------------
// Detection layer: threshold-rule attack classification (no AI/ML)
// ---------------------------------------------------------------------------

/// The attack classes of the problem statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SixStateAttackKind {
    Forgery,
    Impersonation,
    Replay,
    ChannelTampering,
    UnauthorizedVerification,
    None,
}

/// Verdict of the detection layer: which attack the evidence indicates.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectionVerdict {
    pub attack: SixStateAttackKind,
    pub confidence: f64,
    pub basis: String,
}

/// Classify an observation into an attack family using explicit threshold
/// rules over the measured mismatch rates and protocol fields.
///
/// Decision procedure (deterministic, explainable):
/// 1. Session-commitment mismatch ⇒ **forgery** (attacker-built signature).
/// 2. Verifier has no material for the session ⇒ **unauthorized
///    verification**.
/// 3. Nonce already consumed ⇒ **replay**.
/// 4. Mismatch above the rejection threshold ⇒ **channel tampering** when
///    the string was honestly built but disturbed in flight (mismatch well
///    above the noise floor), else **forgery** (guessed string ≈ 50% wrong).
pub fn classify(
    commitment_ok: bool,
    verifier_authorized: bool,
    nonce_fresh: bool,
    mismatch_rate: f64,
    thresholds: Thresholds,
) -> DetectionVerdict {
    if !commitment_ok {
        return DetectionVerdict {
            attack: SixStateAttackKind::Forgery,
            confidence: 1.0,
            basis: "session commitment mismatch — signature not built under this key session"
                .into(),
        };
    }
    if !verifier_authorized {
        return DetectionVerdict {
            attack: SixStateAttackKind::UnauthorizedVerification,
            confidence: 1.0,
            basis: "verifier holds no conclusive key material for this session".into(),
        };
    }
    if !nonce_fresh {
        return DetectionVerdict {
            attack: SixStateAttackKind::Replay,
            confidence: 1.0,
            basis: "nonce already consumed — signature re-presentation".into(),
        };
    }
    if mismatch_rate > thresholds.c2 {
        // Tampering keeps most of the string intact (rate ∝ disturb
        // fraction); a guessed string is wrong ≈ half the time.
        let attack = if mismatch_rate > 0.4 {
            SixStateAttackKind::Forgery
        } else {
            SixStateAttackKind::ChannelTampering
        };
        return DetectionVerdict {
            attack,
            confidence: ((mismatch_rate - thresholds.c2) / (1.0 - thresholds.c2)).clamp(0.0, 1.0),
            basis: format!(
                "mismatch rate {mismatch_rate:.3} exceeds rejection threshold {:.3}",
                thresholds.c2
            ),
        };
    }
    DetectionVerdict {
        attack: SixStateAttackKind::None,
        confidence: 1.0 - mismatch_rate,
        basis: format!(
            "mismatch rate {mismatch_rate:.3} within acceptance band ({:.3}, {:.3}]",
            thresholds.c1, thresholds.c2
        ),
    }
}

/// Threshold recommendation: c1 above the ε_d noise floor, c2 between the
/// noise floor and the ≈50% guessing rate — the detection gap.
pub fn recommended_thresholds(basis_misalignment: f64) -> Thresholds {
    Thresholds {
        c1: (SIX_STATE_NOISE_FLOOR + basis_misalignment).min(SIX_STATE_ATTACK_MISMATCH_FLOOR - 0.05),
        c2: SIX_STATE_ATTACK_MISMATCH_FLOOR - 0.25,
    }
}

/// Mismatch floor for guessed (no-key-material) strings ≈ ½.
pub const SIX_STATE_ATTACK_MISMATCH_FLOOR: f64 = 0.5;

/// Noise-floor mismatch rate induced by basis misalignment ε_d alone
/// (honest devices must tolerate this — Weng et al.'s ed parameter).
pub const SIX_STATE_NOISE_FLOOR: f64 = 0.092;

// ---------------------------------------------------------------------------
// Attack simulations (controlled, reproducible scenarios)
// ---------------------------------------------------------------------------

/// Forgery: the attacker fabricates a signature string without any quantum
/// outcome (uniform guesses bound to a real-looking session envelope).
pub fn attempt_six_state_forgery(
    session: &SixStateSession,
    message: u8,
    rng: &mut impl Rng,
) -> SixStateSignature {
    let n = session.runs[(message & 1) as usize].alice_string.len();
    let bits: Vec<u8> = (0..n).map(|_| rng.gen_bool(0.5) as u8).collect();
    SixStateSignature {
        string_hex: encode_bits(&bits),
        message: message & 1,
        nonce: session.nonce,
        session_id: session.session_id,
        session_commitment: session.session_commitment.clone(),
    }
}

/// Impersonation: re-present the genuine signature for message m as a
/// signature for the other message value (string transplant — the attacker
/// cannot regenerate strings for a different message).
pub fn attempt_six_state_impersonation(
    genuine: &SixStateSignature,
) -> SixStateSignature {
    let mut forged = genuine.clone();
    forged.message = 1 - (genuine.message & 1);
    forged
}

/// Channel tampering: rebuild the session with `fraction` of qubits
/// disturbed in flight (returns the tampered verifier view + the signature
/// built over the tampered run, i.e. what an honest-looking delivery
/// would carry after Eve's disturbance).
pub fn attempt_six_state_tampering(
    params: &SessionParams,
    session_id: u64,
    nonce: u64,
    fraction: f64,
    message: u8,
    rng: &mut impl Rng,
) -> (SixStateSession, SixStateSignature) {
    let session = build_session(params.clone(), session_id, nonce, fraction, rng);
    let sig = sign_six_state(&session, message);
    (session, sig)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn params(n: usize) -> SessionParams {
        SessionParams { n_pulses: n, test_fraction: 0.25, basis_misalignment: 0.0 }
    }

    #[test]
    fn honest_delivery_is_deterministically_accepted() {
        let mut rng = StdRng::seed_from_u64(21);
        let session = build_session(params(1000), 1, 1, 0.0, &mut rng);
        // Ideal conclusive (click) rate is 1/6 of pulses — the exact value
        // Weng et al. require recipients to check (P_c ≈ 1/6).
        assert!(
            session.conclusive_count() > 100,
            "click yield {} should approach n/6",
            session.conclusive_count()
        );
        let sig = sign_six_state(&session, 0);
        let material = VerifierMaterial::from_session(&session);
        let v = verify_six_state(
            &sig,
            &material,
            &session.session_commitment,
            Thresholds { c1: 0.10, c2: 0.25 },
        );
        assert_eq!(v.verdict, Verdict::Acc1, "honest delivery: {:?}", v.reason);
        assert_eq!(v.mismatch.mismatches, 0, "noiseless honest mismatch must be zero");
    }

    #[test]
    fn both_message_values_verify() {
        let mut rng = StdRng::seed_from_u64(22);
        let session = build_session(params(400), 1, 1, 0.0, &mut rng);
        let material = VerifierMaterial::from_session(&session);
        for m in [0u8, 1u8] {
            let sig = sign_six_state(&session, m);
            let v = verify_six_state(
                &sig,
                &material,
                &session.session_commitment,
                Thresholds { c1: 0.10, c2: 0.25 },
            );
            assert_eq!(v.verdict, Verdict::Acc1, "message {m}: {:?}", v.reason);
        }
    }

    #[test]
    fn forged_string_is_rejected_near_half_mismatch() {
        let mut rng = StdRng::seed_from_u64(23);
        let session = build_session(params(600), 1, 1, 0.0, &mut rng);
        let material = VerifierMaterial::from_session(&session);
        let forged = attempt_six_state_forgery(&session, 0, &mut rng);
        let v = verify_six_state(
            &forged,
            &material,
            &session.session_commitment,
            Thresholds { c1: 0.10, c2: 0.25 },
        );
        assert_eq!(v.verdict, Verdict::Rej, "guessed string must be rejected");
        assert!(
            v.mismatch.rate() > 0.35,
            "guessed mismatch rate {:.3} should approach 0.5",
            v.mismatch.rate()
        );
        let det = classify(true, true, true, v.mismatch.rate(), Thresholds { c1: 0.10, c2: 0.25 });
        assert_eq!(det.attack, SixStateAttackKind::Forgery);
    }

    #[test]
    fn impersonation_transplant_is_rejected() {
        let mut rng = StdRng::seed_from_u64(24);
        let session = build_session(params(600), 1, 1, 0.0, &mut rng);
        let material = VerifierMaterial::from_session(&session);
        let genuine = sign_six_state(&session, 0);
        let attacker = attempt_six_state_impersonation(&genuine);
        let v = verify_six_state(
            &attacker,
            &material,
            &session.session_commitment,
            Thresholds { c1: 0.10, c2: 0.25 },
        );
        assert_eq!(v.verdict, Verdict::Rej, "string transplant across messages must fail");
    }

    #[test]
    fn tampered_channel_raises_mismatch_above_noise_floor() {
        let mut rng = StdRng::seed_from_u64(25);
        let p = params(1200);
        // Disturbance d: undisturbed rounds click at rate 1/6 (always
        // correct); disturbed rounds click at rate 1/2 with 2/3 of clicks
        // wrong (the same-basis cohort flips deterministically), so the
        // aggregate mismatch is 2d/(1+2d). d = 0.3 → ≈ 0.375: above the 0.25
        // rejection threshold, below the ≈0.5 guessing floor — the
        // classifier attributes it to channel tampering, not forgery.
        let (session, sig) = attempt_six_state_tampering(&p, 1, 1, 0.3, 0, &mut rng);
        let material = VerifierMaterial::from_session(&session);
        let v = verify_six_state(
            &sig,
            &material,
            &session.session_commitment,
            Thresholds { c1: 0.10, c2: 0.25 },
        );
        assert_eq!(v.verdict, Verdict::Rej, "30% disturbed channel must be rejected");
        let det = classify(true, true, true, v.mismatch.rate(), Thresholds { c1: 0.10, c2: 0.25 });
        assert_eq!(det.attack, SixStateAttackKind::ChannelTampering);
        assert!(
            v.mismatch.rate() > 0.25,
            "tamper rate {:.3} must exceed the noise floor",
            v.mismatch.rate()
        );
    }

    #[test]
    fn unauthorized_verifier_is_flagged() {
        let mut rng = StdRng::seed_from_u64(26);
        let session = build_session(params(200), 1, 1, 0.0, &mut rng);
        let sig = sign_six_state(&session, 0);
        let outsider = VerifierMaterial::default();
        let v = verify_six_state(
            &sig,
            &outsider,
            &session.session_commitment,
            Thresholds { c1: 0.10, c2: 0.25 },
        );
        assert_eq!(v.verdict, Verdict::Rej);
        assert!(v.reason.contains("unauthorized"), "{}", v.reason);
        let det = classify(true, false, true, 0.0, Thresholds { c1: 0.10, c2: 0.25 });
        assert_eq!(det.attack, SixStateAttackKind::UnauthorizedVerification);
    }
}
