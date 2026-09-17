//! QDS key derivation + quantum digital signatures for the document layer.
//!
//! **Why this module exists.** The document pipeline previously reused the
//! raw-QKD distilled secret (`privacy_amplification` of six-state QKD sifted
//! bits) as its sealing key, and the `qds` crate was a separate demo lab.
//! The user asked for the document layer itself to be built on **QDS
//! algorithms**. This module makes that real, in two halves:
//!
//! 1. **Key derivation** (`derive_qds_session_key`): a six-state QDS
//!    key-generation session (Weng et al. 2021 — the `qds::six_state`
//!    implementation, verified against the crate's threshold tests) is run
//!    per user with a fresh nonce. Bob's conclusive string — the verifier
//!    key material the QDS protocol itself produces — is privacy-amplified
//!    with SHA-256 into the 32-byte session sealing key. The signature
//!    string Alice would publish, the session commitment, mismatch
//!    statistics, and the derived key commitment are returned so the UI can
//!    show *which QDS session* each document key comes from. The QKD layer
//!    (`/api/run`) remains for the channel-security demo and feeds the
//!    legacy path; document keys now come from QDS key generation.
//!
//! 2. **Document signatures** (`sign_document_qds`): every sealed document
//!    gets a genuine teleportation-QDS signature (Gottesman–Chuang style,
//!    via the crate-root `qds::sign`) over the document's SHA-256, issued
//!    by the shared Trent notary. The signature is embedded in the `.qsig`
//!    container and re-verified by Trent whenever the document is opened:
//!    a container whose embedded QDS signature fails is refused even if the
//!    symmetric seal somehow verified. Unlocking thus requires BOTH factors:
//!    the six-state-derived session key AND a valid quantum signature.

use crate::qds_state::chrono_now;
use qds::six_state::{
    sign_six_state, verify_six_state, SixStateSession, VerifierMaterial,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Six-state QDS session size (qubits per message value). Large enough that
/// the conclusive-string statistics are stable, small enough to run on every
/// key request in microseconds.
pub const QDS_SESSION_PULSES: usize = 1200;

/// Six-state QDS device misalignment (the noise floor the thresholds must
/// sit above — the crate's recommended-thresholds rule).
pub const QDS_BASIS_MISALIGNMENT: f64 = 0.02;

/// Result of deriving a document-layer session key from a six-state QDS
/// key-generation session.
#[derive(Debug, Clone, Serialize)]
pub struct QdsKeyDerivation {
    /// The distilled 32-byte hex sealing key (server-side secret; the API
    /// never returns this, only its commitment).
    pub key_hex: String,
    /// SHA-256 of the canonical key (sealing::key_commitment_for).
    pub key_commitment: String,
    /// The six-state session commitment (binds the key to its quantum origin).
    pub session_commitment: String,
    /// Session id / nonce used for the derivation session.
    pub session_id: u64,
    pub nonce: u64,
    /// Qubit rounds per message value.
    pub n_pulses: usize,
    /// Conclusive (click) rounds that survived post-matching.
    pub conclusive_bits: usize,
    /// Mismatch rate between Alice's and Bob's conclusive strings (the
    /// honest channel must show ≈ 0 for an ideal simulation).
    pub mismatch_rate: f64,
    /// Human-readable provenance line for the UI.
    pub provenance: String,
}

/// Run a fresh six-state QDS key-generation session and distill the
/// document-layer sealing key from Bob's conclusive string.
///
/// `seed` pins the session's randomness: two laptops that run the SAME
/// (session_id, nonce, seed) derive the SAME key — that is the shared-secret
/// handshake for the P2P demo (each side calls the endpoint with the seed
/// they agreed out of band, e.g. shown on the dashboard). With `None` the
/// session is freshly random (the natural single-machine path).
///
/// Returns `None` if the session produced no conclusive bits (impossible at
/// `QDS_SESSION_PULSES` in practice — the click yield approaches n/6).
pub fn derive_qds_session_key(
    session_id: u64,
    nonce: u64,
    seed: Option<u64>,
) -> Option<QdsKeyDerivation> {
    let mut rng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    let params = qds::six_state::SessionParams {
        n_pulses: QDS_SESSION_PULSES,
        test_fraction: 0.25,
        basis_misalignment: QDS_BASIS_MISALIGNMENT,
    };
    let session: SixStateSession =
        qds::six_state::build_session(params, session_id, nonce, 0.0, &mut rng);

    // Verify the session honestly first: Alice's signature over the session
    // commitment must verify against Bob's material — this is the QDS
    // protocol's own acceptance gate for the key material.
    let material = VerifierMaterial::from_session(&session);
    let sig = sign_six_state(&session, 0);
    let thresholds = qds::six_state::recommended_thresholds(QDS_BASIS_MISALIGNMENT);
    let verification = verify_six_state(&sig, &material, &session.session_commitment, thresholds);
    if !verification.accepted {
        return None;
    }

    // Distill the key: SHA-256 over Bob's conclusive strings (both message
    // values), the same privacy-amplification pattern the QKD layer uses.
    let mut hasher = Sha256::new();
    hasher.update(session.runs[0].bob_string.as_slice());
    hasher.update(session.runs[1].bob_string.as_slice());
    hasher.update(session.session_commitment.as_bytes());
    let key_hex = hex::encode(hasher.finalize());
    let key_commitment = sealing::key_commitment_for(&sealing::canonicalize_key(
        &hex::decode(&key_hex).ok()?,
    ));

    let conclusive = session.conclusive_count();
    let mismatch_rate = verification.mismatch.rate();
    Some(QdsKeyDerivation {
        key_hex,
        key_commitment,
        session_commitment: session.session_commitment.clone(),
        session_id,
        nonce,
        n_pulses: QDS_SESSION_PULSES,
        conclusive_bits: conclusive,
        mismatch_rate,
        provenance: format!(
            "six-state QDS session #{session_id} (nonce {nonce}): {conclusive} conclusive bits \
             from {n} qubits/message, mismatch {mr:.3} — key = SHA-256(verifier strings ‖ session commitment)",
            n = QDS_SESSION_PULSES,
            mr = mismatch_rate
        ),
    })
}

/// A teleportation-QDS signature over a document, plus its verification
/// state at issuance.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentQdsSignature {
    pub signature: qds::QuantumSignature,
    pub doc_sha256: String,
    /// Teleport-QDS verdict at signing time (always 1-ACC for the genuine
    /// signer; recorded so the audit trail shows the signature was born valid).
    pub accepted_at_signing: bool,
    pub match_ratio: f64,
    pub issued_at: String,
}

/// Sign a document's SHA-256 with the teleportation-QDS protocol (the
/// crate-root signer): Trent issues a nonce, Alice teleports H(doc)-labeled
/// qubits through fresh Bell pairs, and the correction-bit sequence becomes
/// an unforgeable signature bound to the exact document.
pub fn sign_document_qds(
    trent: &mut qds::Trent,
    doc_sha256_hex: &str,
) -> DocumentQdsSignature {
    // The signed message is the document hash (hex), so the signature is
    // bound to exactly these bytes — swapping the document breaks it.
    let message = doc_sha256_hex.as_bytes();
    let mut rng = StdRng::from_entropy();
    let (signature, _teleports) = qds::sign(message, trent, &mut rng);
    // Verify once at issuance (consumes the signature's nonce — the initial
    // honest-delivery verification of the QDS protocol).
    let report = qds::verify(message, &signature, trent, 0.0);
    DocumentQdsSignature {
        signature,
        doc_sha256: doc_sha256_hex.to_string(),
        accepted_at_signing: report.accepted,
        match_ratio: report.match_ratio,
        issued_at: chrono_now(),
    }
}

/// Re-verify an attached QDS signature (side-effect-free transferability
/// check — never consumes nonces). Returns the report either way.
pub fn verify_document_qds(
    trent: &mut qds::Trent,
    doc_sha256_hex: &str,
    signature: &qds::QuantumSignature,
) -> qds::VerificationReport {
    qds::verify_transferability(doc_sha256_hex.as_bytes(), signature, trent, 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_key_is_deterministic_per_session_and_verifiable() {
        let d = derive_qds_session_key(1, 1, Some(4242)).expect("session must yield a key");
        assert_eq!(d.key_hex.len(), 64);
        assert!(d.conclusive_bits > 50, "click yield {}", d.conclusive_bits);
        assert!(d.mismatch_rate <= 0.15, "honest session mismatch {}", d.mismatch_rate);
        // Same (session, nonce, seed) → same key: the cross-laptop handshake.
        let d_same = derive_qds_session_key(1, 1, Some(4242)).expect("replay");
        assert_eq!(d.key_hex, d_same.key_hex, "pinned seed must reproduce the key");
        // Different seed → different key.
        let d2 = derive_qds_session_key(2, 2, Some(99)).expect("second session");
        assert_ne!(d.key_hex, d2.key_hex, "different seeds must give fresh keys");
        // The commitment matches the canonical commitment definition.
        let canonical = sealing::canonicalize_key(&hex::decode(&d.key_hex).unwrap());
        assert_eq!(sealing::key_commitment_for(&canonical), d.key_commitment);
    }

    #[test]
    fn document_signature_verifies_and_binds_to_the_document() {
        let mut rng = StdRng::from_entropy();
        let mut trent = qds::Trent::setup(16, 4, &mut rng);
        let doc_hash = "deadbeef".repeat(8);
        let signed = sign_document_qds(&mut trent, &doc_hash);
        assert!(signed.accepted_at_signing, "genuine signature must verify at issuance");
        // Re-verification passes for the same document...
        let ok = verify_document_qds(&mut trent, &doc_hash, &signed.signature);
        assert!(ok.accepted, "{}", ok.reason);
        // ...and fails for a different document (the binding is the message).
        let other_hash = "feedface".repeat(8);
        let bad = verify_document_qds(&mut trent, &other_hash, &signed.signature);
        assert!(!bad.accepted, "signature must be bound to its document hash");
        // A tampered signature fails statistics.
        let mut forged = signed.signature.clone();
        forged.correction_bits[0] ^= 1;
        let bad2 = verify_document_qds(&mut trent, &doc_hash, &forged);
        assert!(!bad2.accepted, "flipped signature bit must break verification");
    }
}
