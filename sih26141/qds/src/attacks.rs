//! Controlled attack simulations against the QDS protocol.
//!
//! Each attack produces a `QuantumSignature` that is *not* a genuine
//! teleportation product, plus a label describing the threat class. The
//! verifier must reject all of them; `estimate_forgery_probability` in the
//! root module quantifies how overwhelming "must" is.

use crate::{QuantumSignature, Trent};
use rand::Rng;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackKind {
    /// Forger fabricates correction bits without any Bell measurement.
    Forgery,
    /// Attacker re-signs a different message with bits captured from a
    /// signature for another message (signature transplant).
    Impersonation,
    /// Attacker replays a previously accepted signature verbatim.
    Replay,
    /// Eve tampers with teleported qubits in flight; correction bits are
    /// genuine but the received state is disturbed.
    ChannelTampering,
    /// A party without the required key material (or without authorization
    /// from the notary) attempts to run verification. The problem statement
    /// lists "unauthorized verification attempts" among the threats; here
    /// the attacker lacks the correlation tables, so no verdict they reach
    /// can be trusted — the framework flags the attempt itself.
    UnauthorizedVerification,
}

/// A forged signature attempt plus metadata for the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackAttempt {
    pub kind: AttackKind,
    pub signature: QuantumSignature,
    /// Human-readable description of what the attacker did.
    pub description: String,
    /// Original message the signature claims to cover.
    pub claimed_message: String,
}

fn message_hash(message: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(message);
    hex::encode(h.finalize())
}

/// Expose the message-hash binding used by the impersonation check
/// (used by metrics and tests to correlate mismatch counts with digests).
pub fn message_digest_hex(message: &[u8]) -> String {
    message_hash(message)
}

/// Pure guessing forgery: random correction bits under a fresh nonce.
pub fn attempt_forgery(
    claimed_message: &[u8],
    trent: &mut Trent,
    rng: &mut impl Rng,
) -> AttackAttempt {
    let n = trent.public_key().qubit_count * trent.public_key().lambda * 2;
    AttackAttempt {
        kind: AttackKind::Forgery,
        signature: QuantumSignature {
            correction_bits: (0..n).map(|_| rng.gen_bool(0.5) as u8).collect(),
            nonce: trent.issue_nonce(),
            key_commitment: trent.public_key().correlation_commitment.clone(),
        },
        description: "Forger fabricated Bell outcomes uniformly at random (no quantum measurement performed)."
            .into(),
        claimed_message: String::from_utf8_lossy(claimed_message).into_owned(),
    }
}

/// Impersonation: take a genuine signature over `real_message` and present
/// it as a signature over `target_message` (the attacker controls neither
/// the correlations nor the nonce registry).
pub fn attempt_impersonation(
    genuine: &QuantumSignature,
    real_message: &[u8],
    target_message: &[u8],
) -> AttackAttempt {
    let _ = real_message; // captured signature is reused as-is
    AttackAttempt {
        kind: AttackKind::Impersonation,
        signature: QuantumSignature {
            correction_bits: genuine.correction_bits.clone(),
            nonce: genuine.nonce,
            key_commitment: genuine.key_commitment.clone(),
        },
        description: "Attacker transplanted a genuine signature onto a different message (no new teleportation possible without Alice's correlations).".into(),
        claimed_message: String::from_utf8_lossy(target_message).into_owned(),
    }
}

/// Replay: re-present an already-accepted signature for the same message.
pub fn attempt_replay(genuine: &QuantumSignature, message: &[u8]) -> AttackAttempt {
    AttackAttempt {
        kind: AttackKind::Replay,
        signature: QuantumSignature {
            correction_bits: genuine.correction_bits.clone(),
            nonce: genuine.nonce,
            key_commitment: genuine.key_commitment.clone(),
        },
        description: "Attacker replayed a previously accepted signature verbatim (nonce reuse)."
            .into(),
        claimed_message: String::from_utf8_lossy(message).into_owned(),
    }
}

/// Quantum channel tampering: Eve disturbs a fraction f of the teleported
/// qubits in flight, so the correction bits Bob receives no longer match
/// what Alice's teleportation produced: each disturbed position flips one
/// of its two published bits, producing verification mismatches at a rate
/// ∝ f (a Pauli-X-type disturbance flips the decoded bit).
pub fn attempt_channel_tampering(
    genuine: &QuantumSignature,
    tamper_fraction: f64,
    claimed_message: &[u8],
    trent: &Trent,
    rng: &mut impl Rng,
) -> AttackAttempt {
    let lambda = trent.public_key().lambda;
    let _ = lambda; // kept for signature-stability; disturbance is fraction-driven
    let n_positions = genuine.correction_bits.len() / 2;
    let mut bits = genuine.correction_bits.clone();
    let mut disturbed = 0usize;
    for pos in 0..n_positions {
        if rng.gen_bool(tamper_fraction) {
            // Eve's interaction corrupts one of the position's two bits.
            let idx = pos * 2 + rng.gen_range(0..2);
            bits[idx] ^= 1;
            disturbed += 1;
        }
    }
    AttackAttempt {
        kind: AttackKind::ChannelTampering,
        signature: QuantumSignature {
            correction_bits: bits,
            // nonce supplied by caller flow in server; 0 = take a fresh one
            nonce: 0,
            key_commitment: trent.public_key().correlation_commitment.clone(),
        },
        description: format!(
            "Eve disturbed {:.0}% of teleported qubits in flight ({} of {} positions); correction bits decode inconsistently at the receiver.",
            tamper_fraction * 100.0,
            disturbed,
            n_positions
        ),
        claimed_message: String::from_utf8_lossy(claimed_message).into_owned(),
    }
}

/// Tamper fraction used when the caller does not specify one (50% — far
/// above any rejection threshold, easily visible on the dashboard).
pub const DEFAULT_TAMPER_FRACTION: f64 = 0.5;

/// Unauthorized verification attempt: a party that never received Trent's
/// key material (or was not authorized by him) tries to verify a captured
/// signature. They can recompute the message hash and present the captured
/// correction bits, but they hold no correlation tables — the framework
/// flags the attempt regardless of the would-be verdict, and the
/// verification statistics remain meaningless to them (they cannot even
/// tell a valid signature from random bits without Trent's tables).
pub fn attempt_unauthorized_verification(
    genuine: &QuantumSignature,
    _message: &[u8],
    attempted_message: &[u8],
) -> AttackAttempt {
    AttackAttempt {
        kind: AttackKind::UnauthorizedVerification,
        signature: QuantumSignature {
            correction_bits: genuine.correction_bits.clone(),
            nonce: genuine.nonce,
            key_commitment: genuine.key_commitment.clone(),
        },
        description: "Unauthorized party attempted verification without Trent-issued key material; the attempt is flagged and the verdict is untrustworthy."
            .into(),
        claimed_message: String::from_utf8_lossy(attempted_message).into_owned(),
    }
}
