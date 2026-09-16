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
pub use attacks::{AttackAttempt, AttackKind};
pub use six_state::{SixStateAttackKind, SixStateSignature, SixStateVerification};

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
/// In the simulation the "quantum channel" is ideal, so teleportation
/// transports the bit exactly; the Bell outcome is still random (Alice cannot
/// choose it), which is precisely what makes the correction-bits sequence an
/// unpredictable, verifiable signature.
pub fn teleport_bit(message_bit: u8, pair: &BellPair, rng: &mut impl Rng) -> TeleportResult {
    let outcome = pair.bell_measure(rng);
    // Given the outcome, Bob's raw half is fixed by the entanglement
    // correlations: applying the outcome's Pauli correction must yield the
    // original state — that is the whole content of teleportation.
    let pre = if outcome.correction().flips_bit() {
        1 - message_bit
    } else {
        message_bit
    };
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumSignature {
    /// Two correction bits per teleported qubit, flattened.
    pub correction_bits: Vec<u8>,
    /// Trent-issued single-use nonce (replay defense).
    pub nonce: u64,
    /// Commitment mirror of the public key in force when signed.
    pub key_commitment: String,
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

    (
        QuantumSignature {
            correction_bits,
            nonce,
            key_commitment: trent.public_key().correlation_commitment.clone(),
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
        // nonce usable so a delayed genuine signature still verifies.
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
        let forged = QuantumSignature {
            correction_bits: (0..qubit_count * lambda * 2)
                .map(|_| rng.gen_bool(0.5) as u8)
                .collect(),
            nonce: t.issue_nonce(),
            key_commitment: t.public_key().correlation_commitment.clone(),
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
