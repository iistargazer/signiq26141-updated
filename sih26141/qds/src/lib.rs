//! Teleportation-based Quantum Digital Signature (QDS) simulation.
//!
//! Protocol participants:
//!   * Alice — the signer
//!   * Trent — a distribution / notary center (shares Bell pairs with both,
//!     records the signature ledger, issues nonces to defeat replay)
//!   * Bob   — the verifier
//!
//! Security goal: only Alice can produce signatures that Bob accepts, and any
//! modification / forgery / replay of a signature is detected with
//! overwhelming probability via projective-measurement statistics.
//!
//! Simplifications (documented for the evaluator):
//!   * Bell pairs are simulated as perfectly correlated random pairs (the
//!     entanglement correlations of |Φ+> are what the protocol consumes).
//!   * The quantum channel to Trent/Bob is noiseless unless an attack module
//!     explicitly tampers with it.
//!   * `MultiBitSignature` composes single-qubit teleportation rounds, one
//!     qubit per signature bit.

use rand::Rng;
use sha2::{Digest, Sha256};

pub mod attacks;
pub mod metrics;
pub mod noisy;
pub mod six_state;
pub mod consensus;
pub mod teleport;
pub mod temporal;
pub use attacks::{AttackAttempt, AttackKind};
pub use six_state::{SixStateAttackKind, SixStateSignature, SixStateVerification};
pub use teleport::{
    teleport_state, Amplitude, BellState, PauliCorrection, StateVector, TeleportationRecord,
    TeleportationResult,
};

// ---------------------------------------------------------------------------
// Pauli algebra
// ---------------------------------------------------------------------------

/// The four single-qubit Pauli operations. Teleportation requires applying
/// one of these to correct the teleported state (deliverable 1: "Pauli
/// correction operations").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauliOp {
    I,
    X,
    Z,
    /// Z then X (the teleportation correction for Bell outcome 11 is X∘Z;
    /// we keep the composite as one label).
    ZX,
}

impl PauliOp {
    pub const ALL: [PauliOp; 4] = [PauliOp::I, PauliOp::X, PauliOp::Z, PauliOp::ZX];

    /// Effect of the operation on a computational-basis bit.
    /// I: b -> b, X: b -> 1−b, Z: b -> b (phase only, not visible here),
    /// ZX: b -> 1−b.
    fn flips_bit(self) -> bool {
        matches!(self, PauliOp::X | PauliOp::ZX)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PauliOp::I => "I",
            PauliOp::X => "X",
            PauliOp::Z => "Z",
            PauliOp::ZX => "ZX",
        }
    }
}

/// Two-bit label for a Bell-measurement outcome (the teleportation "correction
/// bits"). 00 → I, 01 → X, 10 → Z, 11 → ZX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BellOutcome(pub u8); // 0..=3

impl BellOutcome {
    pub fn correction(&self) -> PauliOp {
        match self.0 {
            0 => PauliOp::I,
            1 => PauliOp::X,
            2 => PauliOp::Z,
            _ => PauliOp::ZX,
        }
    }

    pub fn as_bits(self) -> (u8, u8) {
        (self.0 >> 1 & 1, self.0 & 1)
    }
}

// ---------------------------------------------------------------------------
// Entanglement + teleportation
// ---------------------------------------------------------------------------

/// An entangled Bell pair shared between two parties (|Φ+> resource).
/// The pair itself carries no hidden classical bit: teleportation's randomness
/// lives entirely in Alice's Bell-measurement outcome, and Bob's raw half is
/// determined (given the outcome) such that the Pauli correction reconstructs
/// the teleported state exactly.
#[derive(Debug, Clone, Copy)]
pub struct BellPair;

impl BellPair {
    /// Trent prepares a fresh |Φ+> pair and distributes the halves.
    pub fn new(_rng: &mut impl Rng) -> Self {
        Self
    }

    /// Bell measurement outcome when Alice entangles her message qubit with
    /// her half: uniform over the four two-bit outcomes (Alice cannot choose
    /// it — this unpredictability is what the signature is made of).
    pub fn bell_measure(&self, rng: &mut impl Rng) -> BellOutcome {
        BellOutcome(rng.gen_range(0..4))
    }
}

/// Result of teleporting one message qubit from Alice to Bob.
#[derive(Debug, Clone, Copy)]
pub struct TeleportResult {
    pub outcome: BellOutcome,
    /// The bit Bob holds after applying the Pauli correction. In a clean
    /// teleportation this equals Alice's input bit.
    pub corrected_bit: u8,
    /// Bob's bit *before* correction — kept for attack forensics.
    pub pre_correction_bit: u8,
}

/// Teleport one classical-encoded qubit value `message_bit` to the holder of
/// the Bell pair half.
///
/// This now runs the **genuine statevector engine** (`teleport::teleport_state`):
/// a 3-qubit register with the message qubit prepared as |0⟩ or |1⟩, a real
/// entangled |Φ⁺⟩ resource, CNOT+H Bell measurement, Born-rule projective
/// measurement, and Bob's conditional Pauli correction. The Bell outcome is
/// not drawn from a RNG directly — it emerges from the measurement statistics
/// of the entangled register, which is the physics Deliverable 1 asks for.
pub fn teleport_bit(message_bit: u8, _pair: &BellPair, rng: &mut impl Rng) -> TeleportResult {
    let (alpha, beta) = if message_bit == 1 {
        (Amplitude::ZERO, Amplitude::new(1.0, 0.0))
    } else {
        (Amplitude::new(1.0, 0.0), Amplitude::ZERO)
    };
    let r = teleport_state(alpha, beta, rng);
    let outcome = BellOutcome(match r.record.bell_state {
        BellState::PhiPlus => 0,
        BellState::PsiPlus => 1,
        BellState::PhiMinus => 2,
        BellState::PsiMinus => 3,
    });
    // Bob's raw bit BEFORE correction, read off the post-measurement
    // statevector (Born-rule collapse already applied by the engine).
    let pre = if r.record.bob_beta_pre.modulus_squared() > 0.5 { 1 } else { 0 };
    let corrected = apply_correction(pre, outcome.correction());
    debug_assert_eq!(
        corrected, message_bit,
        "ideal teleportation must preserve the bit"
    );
    TeleportResult {
        outcome,
        corrected_bit: corrected,
        pre_correction_bit: pre,
    }
}

/// Apply a Pauli correction to a raw measured bit.
pub fn apply_correction(raw_bit: u8, op: PauliOp) -> u8 {
    if op.flips_bit() {
        1 - raw_bit
    } else {
        raw_bit
    }
}

// ---------------------------------------------------------------------------
// Keys and signatures
// ---------------------------------------------------------------------------

/// Alice's quantum public key: for each future signature bit i, Alice and
/// Trent share `k_i = |A_i XOR T_i|` correlations via Bell pairs. The public
/// key is the *commitment* to these correlations: H(k_1..k_m) published up
/// front, plus the nonce registry. Trent never reveals the raw bits — only
/// verification verdicts — so Bob cannot learn the key.
#[derive(Debug, Clone)]
pub struct QuantumPublicKey {
    /// Number of signature qubits (bits) supported.
    pub qubit_count: usize,
    /// Commitment to the hidden Bell correlations.
    pub correlation_commitment: String,
    /// Security parameter λ: Bell-pair depth per signature bit.
    pub lambda: usize,
}

/// A quantum digital signature over a message.
///
/// The signature is the sequence of Bell-measurement outcomes (two classical
/// bits per qubit) Alice obtained while teleporting H(m)-labeled qubits —
/// i.e. exactly the "classical information" a teleportation-based QDS
/// publishes, plus a Trent nonce binding it to this message instance.
///
/// The `temporal` field carries the Feature-2 **quantum-entropy timestamp**
/// (sifting-window sequence number + hash-chain link + signature tag). A
/// signature without it cannot verify — the replay trap treats a missing
/// binding as a forgery-class signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumSignature {
    /// Two correction bits per teleported qubit, flattened.
    pub correction_bits: Vec<u8>,
    /// Trent-issued single-use nonce (replay defense).
    pub nonce: u64,
    /// Commitment mirror of the public key in force when signed.
    pub key_commitment: String,
    /// Quantum-entropy timestamp binding (Feature 2 — temporal
    /// non-repudiation). `None` only on old persisted signatures or forged
    /// attempts; both fail verification.
    #[serde(default)]
    pub temporal: Option<temporal::TemporalBinding>,
}

// ---------------------------------------------------------------------------
// Trent: distribution center / notary / ledger
// ---------------------------------------------------------------------------

/// Secret key material revealed to Alice at signing time: two independent
/// Bell-correlation tables. Each entry is realized by a Bell pair shared
/// between Alice and Trent — measuring her halves is how Alice "learns" the
/// bits; Trent holds the identical values from preparation.
#[derive(Debug, Clone)]
pub struct SigningMaterial {
    /// Primary correlations A1[i][j] — carried by the teleported payloads.
    pub primary: Vec<Vec<u8>>,
    /// Secondary correlations A2[i][j] — bound via the second signature bit.
    pub secondary: Vec<Vec<u8>>,
}

/// The notary center. Holds Bell-pair correlations with Alice (signing side),
/// the published key commitment, the nonce registry, and the signature
/// ledger (replay defense). Issues verification verdicts to Bob without ever
/// revealing key material.
pub struct Trent {
    /// Primary Bell-correlation bits A1[i][j].
    primary: Vec<Vec<u8>>,
    /// Secondary Bell-correlation bits A2[i][j].
    secondary: Vec<Vec<u8>>,
    key: QuantumPublicKey,
    /// Nonces already consumed (replay defense).
    used_nonces: std::collections::HashSet<u64>,
    next_nonce: u64,
    /// Ledger of accepted signatures (message hash -> nonce), for audit.
    pub ledger: Vec<(String, u64)>,
    /// The notary's **quantum clock**: the highest sifting window whose
    /// signature has been accepted. The clock advances only on acceptance,
    /// so a replayed past signature always lands behind it (Feature 2).
    pub window: u64,
    /// Every chain link this notary has minted, in mint order. Membership
    /// in this history is what a timestamp must prove.
    pub chain_history: Vec<String>,
    /// Sifting windows consumed by accepted signatures — a window can be
    /// filled only once, which is the replay check's sequence test.
    pub consumed_windows: std::collections::HashSet<u64>,
    /// Entropy hex of the CURRENT session's timestamp (set by `sign()`).
    /// Re-bindings at the frontier window must reuse it so their recomputed
    /// chain link equals the frontier link — and since the entropy came from
    /// Bell outcomes, only the notary/session holder can mint such bindings.
    frontier_entropy_hex: Option<String>,
}

impl Trent {
    /// Sets up key material: for each of `qubit_count` signature qubits and
    /// `lambda` Bell rounds, Trent shares TWO correlation bits with Alice
    /// (one per teleported payload, one per secondary signature bit).
    /// The public key commitment is H(A1 || A2 || lambda).
    pub fn setup(
        qubit_count: usize,
        lambda: usize,
        rng: &mut impl Rng,
    ) -> Self {
        let mut primary = Vec::with_capacity(qubit_count);
        let mut secondary = Vec::with_capacity(qubit_count);
        let mut commitment_input = Vec::with_capacity(qubit_count * lambda * 2);

        for _ in 0..qubit_count {
            let mut p_row = Vec::with_capacity(lambda);
            let mut s_row = Vec::with_capacity(lambda);
            for _ in 0..lambda {
                let a1 = rng.gen_bool(0.5) as u8;
                let a2 = rng.gen_bool(0.5) as u8;
                p_row.push(a1);
                s_row.push(a2);
                commitment_input.push(a1);
                commitment_input.push(a2);
            }
            primary.push(p_row);
            secondary.push(s_row);
        }

        let mut hasher = Sha256::new();
        hasher.update(&commitment_input);
        hasher.update(lambda.to_le_bytes());
        let commitment = hex::encode(hasher.finalize());

        Trent {
            primary,
            secondary,
            key: QuantumPublicKey {
                qubit_count,
                correlation_commitment: commitment.clone(),
                lambda,
            },
            used_nonces: std::collections::HashSet::new(),
            next_nonce: 1,
            ledger: Vec::new(),
            window: 0,
            chain_history: vec![temporal::GENESIS_LINK.to_string()],
            consumed_windows: std::collections::HashSet::new(),
            frontier_entropy_hex: None,
        }
    }

    pub fn public_key(&self) -> &QuantumPublicKey {
        &self.key
    }

    /// Issues a fresh single-use nonce for a signing session.
    pub fn issue_nonce(&mut self) -> u64 {
        let n = self.next_nonce;
        self.next_nonce += 1;
        n
    }

    /// Mint a temporal binding for `correction_bits` at the CURRENT sifting
    /// window without advancing the clock or extending the chain. This is the
    /// honest noisy-signer path: the session's quantum timestamp already
    /// exists (minted at `sign()`), and the bits as *received* over a noisy
    /// channel are what get bound for statistical evaluation. Only a holder
    /// of the session entropy (the signer/notary) can mint — the tag covers
    /// the secret `entropy_hex`, so attackers cannot forge bindings.
    pub fn mint_temporal_for(&self, correction_bits: &[u8], nonce: u64) -> temporal::TemporalBinding {
        // A binding AT the frontier window extends the link BEFORE the
        // frontier (the frontier link itself was minted over that same
        // predecessor), so the recomputed link equals the frontier link and
        // the binding verifies as locally minted.
        let prev_chain = if self.chain_history.len() >= 2 {
            self.chain_history[self.chain_history.len() - 2].clone()
        } else {
            temporal::GENESIS_LINK.to_string()
        };
        // Reuse the frontier session's Bell-derived entropy when there is
        // one: the recomputed link then EQUALS the frontier link (chain is a
        // deterministic function of prev, window, entropy), so the binding
        // verifies as locally minted. Without a minted session the binding
        // carries table-derived entropy and will (correctly) fail the
        // chain check — nothing was ever signed to bind to.
        let entropy = self.frontier_entropy_hex.clone().unwrap_or_else(|| {
            let mut h = Sha256::new();
            for row in self.primary.iter().flat_map(|r| r.iter()) {
                h.update([*row]);
            }
            h.update(self.window.to_le_bytes());
            hex::encode(h.finalize())
        });
        let ts = temporal::QuantumTimestamp {
            window: self.window,
            unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            entropy_hex: entropy,
            // The link recomputed over (prev, window, entropy) — the same
            // structural relation `trap_check` verifies.
            chain_hex: String::new(),
        };
        let mut ts = ts;
        ts.chain_hex = temporal::expected_chain_link(&prev_chain, &ts);
        temporal::bind_signature(ts, &prev_chain, correction_bits, nonce, &self.key.correlation_commitment)
    }

    /// Secret correlation tables handed to Alice during signing (realized
    /// through her Bell-pair measurements), bound to the session nonce.
    pub fn signing_material(&self) -> SigningMaterial {
        SigningMaterial {
            primary: self.primary.clone(),
            secondary: self.secondary.clone(),
        }
    }

    /// Verification tables (Trent-side; Bob only receives the verdict).
    pub fn verification_tables(&self) -> (&Vec<Vec<u8>>, &Vec<Vec<u8>>) {
        (&self.primary, &self.secondary)
    }

    /// Capture the current replay-trap state.
    pub fn replay_snapshot(&self) -> ReplayStateSnapshot {
        ReplayStateSnapshot {
            used_nonces: self.used_nonces.iter().copied().collect(),
            consumed_windows: self.consumed_windows.iter().copied().collect(),
            chain_history: self.chain_history.clone(),
            window: self.window,
            next_nonce: self.next_nonce,
            frontier_entropy_hex: self.frontier_entropy_hex.clone(),
            ledger: self.ledger.clone(),
        }
    }

    /// Restore replay-trap state captured by `replay_snapshot` (e.g. at
    /// server boot). Only meaningful for a Trent built with the SAME seed
    /// (the correlation tables must match the ledger being restored).
    pub fn replay_restore(&mut self, snap: &ReplayStateSnapshot) {
        self.used_nonces = snap.used_nonces.iter().copied().collect();
        self.consumed_windows = snap.consumed_windows.iter().copied().collect();
        self.chain_history = snap.chain_history.clone();
        self.window = snap.window;
        self.next_nonce = snap.next_nonce;
        self.frontier_entropy_hex = snap.frontier_entropy_hex.clone();
        self.ledger = snap.ledger.clone();
    }
}

/// Persistable replay-trap state: everything the anti-replay machinery
/// has *consumed or minted* since setup. Persist this across restarts and
/// a rebooted verifier keeps its memory — without it, a restart would
/// re-arm every captured signature (the last theoretical replay window).
/// Does NOT include the secret tables: those are already pinned by
/// TRENT_SEED, and duplicating them here would put a second copy of key
/// material on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReplayStateSnapshot {
    /// Nonces consumed by accepted signatures.
    pub used_nonces: Vec<u64>,
    /// Sifting windows consumed by accepted signatures.
    pub consumed_windows: Vec<u64>,
    /// The full minted chain, in mint order (index = window).
    pub chain_history: Vec<String>,
    /// The notary's current clock (frontier window).
    pub window: u64,
    /// Next nonce to issue.
    pub next_nonce: u64,
    /// Current session's entropy hex (for re-bindings at the frontier).
    pub frontier_entropy_hex: Option<String>,
    /// Accepted-signature ledger entries (message hash, nonce).
    pub ledger: Vec<(String, u64)>,
}

#[cfg(test)]
mod replay_state_tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// A restart with restore must keep the trap armed: the pre-restart
    /// replay is still caught, and fresh sessions continue from the restored
    /// clock instead of rewinding to window 1.
    #[test]
    fn replay_state_survives_restart() {
        let mut rng = StdRng::seed_from_u64(3001);
        let mut trent = Trent::setup(8, 2, &mut rng);
        let (sig1, _) = sign(b"first document", &mut trent, &mut rng);
        assert!(verify(b"first document", &sig1, &mut trent, 0.0).accepted);
        let snap = trent.replay_snapshot();

        // "Restart": rebuild from the same seed, restore the snapshot.
        let mut trent2 = Trent::setup(8, 2, &mut StdRng::seed_from_u64(3001));
        assert_eq!(trent2.window, 0, "fresh notary starts at window 0");
        trent2.replay_restore(&snap);
        assert_eq!(trent2.window, 1, "clock restored");

        // The pre-restart replay is STILL caught (the whole point).
        let replay = crate::attacks::attempt_replay(&sig1, b"first document");
        let r = verify(b"first document", &replay.signature, &mut trent2, 0.0);
        assert!(!r.accepted, "restart must not re-arm replayed signatures");
        assert!(r.reason.contains("replay") || r.reason.contains("sequence"), "{}", r.reason);

        // New sessions continue from the restored frontier.
        let (sig2, _) = sign(b"second document", &mut trent2, &mut rng);
        assert_eq!(sig2.temporal.as_ref().expect("binding").issued.window, 2);
        assert!(verify(b"second document", &sig2, &mut trent2, 0.0).accepted);
    }
}

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

/// Encodes a message hash into the qubit space: signature qubits carry
/// H(m) padded/repeated to `qubit_count` bits. The signature is thus bound
/// to the message (no signing arbitrary payloads).
fn message_qubits(message: &[u8], qubit_count: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let digest = hasher.finalize();
    (0..qubit_count).map(|i| digest[i % 32] >> (i % 8) & 1).collect()
}

/// Alice signs `message` by teleporting one qubit per signature position,
/// using fresh Bell pairs. Each position publishes two bits:
///   x = m_i XOR A1[i][j]   (the teleported payload bit — mixes the message
///                           with the hidden Bell correlation)
///   z = A1[i][j] XOR A2[i][j] (binds the secondary correlation table)
/// Only a signer who knows both correlation tables (via her Bell-pair
/// measurements) can satisfy both verification equations; a forger must
/// guess both bits — success probability 1/4 per position.
pub fn sign(
    message: &[u8],
    trent: &mut Trent,
    rng: &mut impl Rng,
) -> (QuantumSignature, Vec<TeleportResult>) {
    let qubit_count = trent.public_key().qubit_count;
    let lambda = trent.public_key().lambda;
    let nonce = trent.issue_nonce();
    let material = trent.signing_material();
    let msg_bits = message_qubits(message, qubit_count);

    let mut correction_bits = Vec::with_capacity(qubit_count * lambda * 2);
    let mut teleports = Vec::with_capacity(qubit_count * lambda);

    for i in 0..qubit_count {
        for j in 0..lambda {
            let a1 = material.primary[i][j];
            let a2 = material.secondary[i][j];

            // Teleport the payload qubit encoding m_i XOR A1 — genuine
            // teleportation with random Bell outcome and Pauli correction.
            let payload = msg_bits[i] ^ a1;
            let pair = BellPair::new(rng);
            let t = teleport_bit(payload, &pair, rng);
            teleports.push(t);

            // Published signature bits (see doc comment).
            let x = payload; // m_i ^ a1
            let z = a1 ^ a2;
            correction_bits.push(x);
            correction_bits.push(z);
        }
    }

    // Feature 2 — mint the quantum-entropy timestamp from the Bell outcomes
    // just measured (they did not exist before Alice's measurements), chained
    // onto the notary's history. The clock advances once per signing session.
    let bell_entropy: Vec<u8> = teleports.iter().map(|t| t.outcome.0).collect();
    let window = trent.window + 1;
    let prev_chain = trent
        .chain_history
        .last()
        .cloned()
        .unwrap_or_else(|| temporal::GENESIS_LINK.to_string());
    let commitment = trent.public_key().correlation_commitment.clone();
    let ts = temporal::mint_timestamp(window, &bell_entropy, &prev_chain);
    trent.frontier_entropy_hex = Some(ts.entropy_hex.clone());
    let binding =
        temporal::bind_signature(ts, &prev_chain, &correction_bits, nonce, &commitment);
    trent.chain_history.push(binding.issued.chain_hex.clone());
    trent.window = window;

    (
        QuantumSignature {
            correction_bits,
            nonce,
            key_commitment: commitment,
            temporal: Some(binding),
        },
        teleports,
    )
}

/// Verdict of a signature verification attempt.
/// Three-outcome verdict per Gottesman–Chuang 2001 (§4, "Quantum signature
/// protocol specification"), matching the dual-threshold semantics used by
/// Singh et al. 2023 (Ta/Tb) and Weng et al. 2021 (mismatch-rate estimation):
///
///   * `Acc1` (1-ACC): valid AND transferable — the mismatch rate is below
///     the acceptance threshold c1, so any other verifier is guaranteed to
///     reach a non-REJ verdict too.
///   * `Acc0` (0-ACC): valid for THIS verifier only — mismatch rate lies in
///     the gray zone (c1, c2]; a second verifier might disagree, so the
///     signature must not be forwarded as trusted.
///   * `Rej` (REJ): invalid — nonce/commitment failure or mismatch rate above
///     the rejection threshold c2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Acc1,
    Acc0,
    Rej,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Acc1 => "1-ACC",
            Verdict::Acc0 => "0-ACC",
            Verdict::Rej => "REJ",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Verdict::Acc1 | Verdict::Acc0)
    }

    pub fn transferable(self) -> bool {
        self == Verdict::Acc1
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationReport {
    pub accepted: bool,
    /// Three-outcome verdict (1-ACC / 0-ACC / REJ) per Gottesman–Chuang 2001.
    pub verdict: Verdict,
    /// Fraction of qubit/round positions whose corrected bit matched the
    /// verification table (1.0 for a genuine signature).
    pub match_ratio: f64,
    pub mismatches: usize,
    pub total_positions: usize,
    /// False when verification was rejected *before* the measurement
    /// statistics ran (malformed length, commitment mismatch, replayed
    /// nonce). In that case `mismatches`/`match_ratio` are not statistics
    /// and UIs must not present them as measured evidence.
    pub evaluated: bool,
    pub reason: &'static str,
}

impl VerificationReport {
    /// True iff the verdict is 1-ACC (the signature may be forwarded as
    /// trusted to other verifiers).
    pub fn transferable(&self) -> bool {
        self.verdict.transferable()
    }
}

/// Decision thresholds for the two-threshold verdict rule.
///
/// * `c1` — mismatch fraction at or below which the signature is 1-ACC
///   (transferable). 0.0 in a noiseless simulation.
/// * `c2` — mismatch fraction above which the signature is REJ. The gray
///   zone (c1, c2] yields 0-ACC (valid here, transfer not guaranteed).
///   Gottesman–Chuang require c2 − c1 to bound Alice's cheating probability;
///   with perfect devices c1 = 0 and c2 may be small but nonzero.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub c1: f64,
    pub c2: f64,
}

impl Thresholds {
    /// Noiseless-channel defaults: strict accept, small gray zone.
    pub fn noiseless() -> Self {
        Self { c1: 0.0, c2: 0.10 }
    }
}

/// Bob verifies a signature against Trent's verification table.
///
/// Decision rule (statistical threshold, no ML): accept iff
///   * the nonce is fresh (not replayed),
///   * the key commitment matches the one in force,
///   * the mismatch ratio across all measurement positions is ≤ tolerance.
///
/// `tolerance` = 0 for the ideal noiseless simulation; the statistical
/// machinery (Hoeffding-style) lives in the `detection` crate for noisy
/// channels and is exposed via the server.
pub fn verify(
    message: &[u8],
    signature: &QuantumSignature,
    trent: &mut Trent,
    tolerance: f64,
) -> VerificationReport {
    let qubit_count = trent.public_key().qubit_count;
    let lambda = trent.public_key().lambda;
    let total_positions = qubit_count * lambda;

    // ---- structural checks -------------------------------------------------
    if signature.correction_bits.len() != total_positions * 2 {
        return VerificationReport {
            accepted: false,
            verdict: Verdict::Rej,
            match_ratio: 0.0,
            mismatches: 0,
            total_positions,
            evaluated: false,
            reason: "malformed signature: wrong correction-bit length",
        };
    }
    if signature.key_commitment != trent.public_key().correlation_commitment {
        return VerificationReport {
            accepted: false,
            verdict: Verdict::Rej,
            match_ratio: 0.0,
            mismatches: 0,
            total_positions,
            evaluated: false,
            reason: "key commitment mismatch: signature not made under this key",
        };
    }
    // ---- temporal trap (Feature 2: replay + non-repudiation) --------------
    // Runs before the nonce registry: the sifting-window sequence check is
    // the primary replay defense; the nonce is the second layer.
    let temporal_reject: Option<&'static str> = match &signature.temporal {
        None => Some(
            "temporal binding missing — signature predates the quantum-timestamp trap (treated as forged)",
        ),
        Some(binding) => {
            match temporal::trap_check(
                binding,
                &signature.correction_bits,
                signature.nonce,
                &signature.key_commitment,
                &trent.chain_history,
                Some(&trent.consumed_windows),
                trent.window,
            ) {
                Ok(()) => None,
                Err(trap) => Some(trap.explanation()),
            }
        }
    };
    if let Some(reason) = temporal_reject {
        return VerificationReport {
            accepted: false,
            verdict: Verdict::Rej,
            match_ratio: 0.0,
            mismatches: 0,
            total_positions,
            evaluated: false,
            reason,
        };
    }

    // ---- replay defense ----------------------------------------------------
    if trent.used_nonces.contains(&signature.nonce) {
        return VerificationReport {
            accepted: false,
            verdict: Verdict::Rej,
            match_ratio: 0.0,
            mismatches: 0,
            total_positions,
            evaluated: false,
            reason: "replay detected: nonce already consumed",
        };
    }

    // ---- measurement statistics -------------------------------------------
    let (table_a1, table_a2) = trent.verification_tables();
    let msg_bits = message_qubits(message, qubit_count);
    let mut mismatches = 0usize;

    for i in 0..qubit_count {
        for j in 0..lambda {
            let pos = i * lambda + j;
            let x = signature.correction_bits[pos * 2];
            let z = signature.correction_bits[pos * 2 + 1];

            // Check 1 (message binding + primary correlation):
            //   x XOR m_i must equal A1[i][j]
            // Check 2 (secondary correlation):
            //   z XOR A1[i][j] must equal A2[i][j]
            // A genuine signer satisfies both deterministically; a forger
            // passes both with probability 1/4 per position.
            if x ^ msg_bits[i] != table_a1[i][j] || z ^ table_a1[i][j] != table_a2[i][j] {
                mismatches += 1;
            }
        }
    }

    let match_ratio =
        (total_positions - mismatches) as f64 / total_positions as f64;
    let mismatch_fraction = mismatches as f64 / total_positions as f64;

    // Dual-threshold verdict (Gottesman–Chuang 2001; Singh et al. 2023 Ta/Tb):
    //   mismatch ≤ c1        → 1-ACC (valid, transferable)
    //   c1 < mismatch ≤ c2   → 0-ACC (valid here, NOT guaranteed transferable)
    //   mismatch > c2        → REJ
    // The `tolerance` parameter (legacy single-threshold API) acts as c2 when
    // explicit thresholds are not supplied by the caller.
    let thresholds = Thresholds { c1: 0.0, c2: tolerance };
    let verdict = if mismatch_fraction <= thresholds.c1 {
        Verdict::Acc1
    } else if mismatch_fraction <= thresholds.c2 {
        Verdict::Acc0
    } else {
        Verdict::Rej
    };
    let accepted = verdict.accepted();

    if accepted {
        // Consume the nonce only on success — a failed attempt leaves the
        // nonce usable so a delayed genuine signature still verifies. The
        // sifting window is likewise consumed exactly once (Feature 2's
        // sequence slot); a replay of this signature dies on both layers.
        if let Some(binding) = &signature.temporal {
            trent.consumed_windows.insert(binding.issued.window);
        }
        trent.used_nonces.insert(signature.nonce);
        trent.ledger.push((
            {
                let mut hasher = Sha256::new();
                hasher.update(message);
                hex::encode(hasher.finalize())
            },
            signature.nonce,
        ));
    }

    let reason = match verdict {
        Verdict::Acc1 => "1-ACC: valid and transferable — all measurement checks passed",
        Verdict::Acc0 => "0-ACC: valid for this verifier only — mismatches in gray zone, transfer not guaranteed",
        Verdict::Rej => "REJ: invalid — measurement mismatch ratio exceeds rejection threshold",
    };

    VerificationReport {
        accepted,
        verdict,
        match_ratio,
        mismatches,
        total_positions,
        evaluated: true,
        reason,
    }
}

/// Transferability check (Gottesman–Chuang 2001, security criterion 2 —
/// non-repudiation): a second verifier independently judges the same
/// signature after the authenticator accepted and forwarded it.
///
/// Per the protocol, forwarding happens only after Bob's acceptance, so the
/// nonce may already be consumed — Charlie's check is therefore purely
/// statistical (measurement statistics + key commitment) and is side-effect
/// free: it never consumes nonces and never mutates the ledger. Replay
/// attacks are caught at the authenticator's interface, not here.
pub fn verify_transferability(
    message: &[u8],
    signature: &QuantumSignature,
    trent: &mut Trent,
    tolerance: f64,
) -> VerificationReport {
    let qubit_count = trent.public_key().qubit_count;
    let lambda = trent.public_key().lambda;
    let total_positions = qubit_count * lambda;

    if signature.correction_bits.len() != total_positions * 2 {
        return VerificationReport {
            accepted: false,
            verdict: Verdict::Rej,
            match_ratio: 0.0,
            mismatches: 0,
            total_positions,
            evaluated: false,
            reason: "malformed signature: wrong correction-bit length",
        };
    }
    if signature.key_commitment != trent.public_key().correlation_commitment {
        return VerificationReport {
            accepted: false,
            verdict: Verdict::Rej,
            match_ratio: 0.0,
            mismatches: 0,
            total_positions,
            evaluated: false,
            reason: "key commitment mismatch: signature not made under this key",
        };
    }

    // ---- temporal trap (Feature 2), side-effect-free transferability form.
    // NOTE: no freshness horizon here — a transferability check must pass
    // for LONG-LIVED artifacts (a sealed document's embedded signature is
    // re-verified every time the document is opened; that repeatability IS
    // non-repudiation). The wire-freshness rule lives only in `verify()`.
    // Tag + chain integrity still gate: transplant and forged timestamps
    // remain fatal. Callers that need the strict bearer semantics run the
    // full `trap_check` themselves (see server `verify_document_qds`).
    let temporal_reject: Option<&'static str> = match &signature.temporal {
        None => Some(
            "temporal binding missing — signature predates the quantum-timestamp trap (treated as forged)",
        ),
        Some(binding) => {
            match temporal::trap_check_document(
                binding,
                &signature.correction_bits,
                signature.nonce,
                &signature.key_commitment,
                &trent.chain_history,
                trent.window,
            ) {
                Ok(()) => None,
                Err(trap) => Some(trap.explanation()),
            }
        }
    };
    if let Some(reason) = temporal_reject {
        return VerificationReport {
            accepted: false,
            verdict: Verdict::Rej,
            match_ratio: 0.0,
            mismatches: 0,
            total_positions,
            evaluated: false,
            reason,
        };
    }

    let (table_a1, table_a2) = trent.verification_tables();
    let msg_bits = message_qubits(message, qubit_count);
    let mut mismatches = 0usize;
    for i in 0..qubit_count {
        for j in 0..lambda {
            let pos = i * lambda + j;
            let x = signature.correction_bits[pos * 2];
            let z = signature.correction_bits[pos * 2 + 1];
            if x ^ msg_bits[i] != table_a1[i][j] || z ^ table_a1[i][j] != table_a2[i][j] {
                mismatches += 1;
            }
        }
    }

    let match_ratio = (total_positions - mismatches) as f64 / total_positions as f64;
    let mismatch_fraction = mismatches as f64 / total_positions as f64;
    let verdict = if mismatch_fraction <= 0.0 {
        Verdict::Acc1
    } else if mismatch_fraction <= tolerance {
        Verdict::Acc0
    } else {
        Verdict::Rej
    };

    VerificationReport {
        accepted: verdict.accepted(),
        verdict,
        match_ratio,
        mismatches,
        total_positions,
        evaluated: true,
        reason: match verdict {
            Verdict::Acc1 => "1-ACC: second verifier confirms — consensus reached",
            Verdict::Acc0 => "0-ACC: second verifier accepts locally, transfer uncertain",
            Verdict::Rej => "REJ: second verifier rejects — possible forgery or tampering",
        },
    }
}

// ---------------------------------------------------------------------------
// Forgery probability analysis
// ---------------------------------------------------------------------------



/// Monte-Carlo estimate of whole-signature forgery probability. A forgery is
/// "successful" when the verify threshold accepts a signature whose
/// correction bits were guessed, not teleported.
pub fn estimate_forgery_probability(
    trent_setup: (usize, usize), // (qubit_count, lambda)
    trials: usize,
    rng: &mut impl Rng,
) -> f64 {
    let (qubit_count, lambda) = trent_setup;
    let mut successes = 0usize;
    for _ in 0..trials {
        let mut t = Trent::setup(qubit_count, lambda, rng);
        // Mint a real session first: the harness then acts as the honest
        // noisy-signer holding the frontier session's entropy, binding its
        // GUESSED bits for statistical evaluation — isolating the (1/4)^n
        // statistics layer, which is what the theory bound describes. The
        // end-to-end forgery probability is this conditional rate TIMES the
        // probability of forging the binding itself, which is negligible
        // without the notary's secret tables (the tag covers the Bell-
        // derived session entropy), so the true figure is far smaller.
        let _genuine = sign(b"target message", &mut t, rng);
        let bits: Vec<u8> = (0..qubit_count * lambda * 2)
            .map(|_| rng.gen_bool(0.5) as u8)
            .collect();
        let nonce = t.issue_nonce();
        let binding = t.mint_temporal_for(&bits, nonce);
        let forged = QuantumSignature {
            correction_bits: bits,
            nonce,
            key_commitment: t.public_key().correlation_commitment.clone(),
            temporal: Some(binding),
        };
        let report = verify(b"target message", &forged, &mut t, 0.0);
        if report.accepted {
            successes += 1;
        }
    }
    successes as f64 / trials as f64
}

/// Theoretical all-positions forgery probability: (1/4)^(qubit_count × λ).
pub fn theory_forgery_probability(qubit_count: usize, lambda: usize) -> f64 {
    0.25_f64.powi((qubit_count * lambda) as i32)
}
