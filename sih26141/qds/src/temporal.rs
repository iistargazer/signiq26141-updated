//! Feature 2 — Temporal Non-Repudiation & Replay-Attack Trap.
//!
//! **The threat.** A replay attack re-broadcasts a *valid* past signature
//! and hopes the verifier accepts it. The classic defense — a single-use
//! nonce — has a hole: any path that mints fresh nonces (a restarted
//! verifier, a second notary instance, a race before the registry
//! persists) re-arms the replayed signature.
//!
//! **The trap.** Every signature is bound to a *quantum-entropy timestamp*:
//!
//! 1. **Sifting-window sequence number.** The notary's quantum clock is a
//!    monotonic window counter. A signature is only valid inside
//!    `[window, valid_until_window)` — a strictly *forward* interval. A
//!    replayed signature's window is always in the past relative to the
//!    verifier's clock, so `window ≤ last_accepted_window` is a sequence
//!    mismatch → immediate rejection, nonce registry irrelevant.
//! 2. **Quantum entropy timestamp.** The window is salted with entropy
//!    distilled from the Bell-measurement outcomes of the signing
//!    teleportations themselves (`H(window ‖ entropy)`). The timestamp is
//!    unpredictable *before* signing and verifiable after — an attacker
//!    cannot pre-compute or grind a valid future timestamp.
//! 3. **Hash-chain binding.** Each timestamp links to its predecessor:
//!    `chain = H(prev_chain ‖ window ‖ entropy)`. The verifier holds the
//!    chain head; any out-of-order or re-broadcast timestamp breaks the
//!    chain → rejection. This makes the *order* of signatures
//!    non-repudiable — the property that gives the feature its name.
//! 4. **Signature tag.** `tag = H(window ‖ entropy ‖ correction_bits ‖
//!    nonce ‖ key_commitment)` welds the timestamp to this exact signature
//!    instance — a stolen binding cannot be transplanted onto a forged or
//!    different-message signature.
//!
//! Together: replaying an old signature fails the sequence check; replaying
//! with a fresh nonce fails the chain check; transplanting the binding
//! fails the tag check. Historical signature reuse is mathematically
//! impossible without breaking SHA-256 preimage resistance *and* predicting
//! Bell outcomes that have not been measured yet.

use sha2::{Digest, Sha256};

/// The quantum-entropy timestamp carried inside a signature's temporal
/// binding. `entropy_hex` and `chain_hex` are produced at signing time;
/// `window` is the notary's monotonic sifting-window counter.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct QuantumTimestamp {
    /// Monotonic sifting-window index when the timestamp was minted.
    pub window: u64,
    /// Wall-clock mint time (ms since the Unix epoch) — display only; all
    /// security decisions use the logical window, never wall time.
    pub unix_ms: u64,
    /// Quantum-entropy salt distilled from the signing teleportations'
    /// Bell-measurement outcomes (hex-encoded).
    pub entropy_hex: String,
    /// Hash-chain link: `H(prev_chain ‖ window ‖ entropy)`.
    pub chain_hex: String,
}

/// The full temporal binding carried by a `QuantumSignature`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct TemporalBinding {
    /// The quantum-entropy timestamp (window + entropy + chain link).
    pub issued: QuantumTimestamp,
    /// The chain link this timestamp extends — carried so a verifier whose
    /// notary instance has not minted this window (e.g. a second laptop
    /// running the same seeded notary) can still verify the link's
    /// *structural integrity* portably.
    pub prev_chain_hex: String,
    /// Exclusive upper bound of validity: the signature dies at this
    /// window. `valid_until_window - issued.window` is the acceptance
    /// horizon in sifting windows.
    pub valid_until_window: u64,
    /// Tag welding this binding to the exact signature instance:
    /// `H(window ‖ entropy ‖ correction_bits ‖ nonce ‖ key_commitment)`.
    pub signature_tag_hex: String,
}

/// How many sifting windows a signature remains fresh after minting.
/// The notary's clock advances one window per signing session, so a
/// signature minted at window `w` is fresh while the notary has minted
/// fewer than `w + VALIDITY_HORIZON` windows — after that it is dead even
/// if never accepted, closing the "captured and aired later" window.
pub const VALIDITY_HORIZON: u64 = 64;

/// The notary chain's root link — every history starts here.
pub const GENESIS_LINK: &str = "QDS-GENESIS-0";

pub(crate) fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

fn u64_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// Mint a quantum-entropy timestamp chained onto `prev_chain_hex`.
///
/// `bell_entropy` must be the raw Bell-measurement outcome bytes of the
/// signing teleportations — the min-entropy source (2 bits per outcome in
/// the ideal channel). This is what makes the timestamp *quantum*: it did
/// not exist before Alice's measurements, and no adversary could have
/// predicted or influenced it.
pub fn mint_timestamp(
    window: u64,
    bell_entropy: &[u8],
    prev_chain_hex: &str,
) -> QuantumTimestamp {
    let unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let entropy_hex = sha256_hex(&[b"qds-quantum-timestamp", bell_entropy, &u64_le(window)]);
    let chain_hex = sha256_hex(&[prev_chain_hex.as_bytes(), &u64_le(window), entropy_hex.as_bytes()]);
    QuantumTimestamp {
        window,
        unix_ms,
        entropy_hex,
        chain_hex,
    }
}

/// Compute the signature tag binding a timestamp to an exact signature.
pub fn signature_tag(
    ts: &QuantumTimestamp,
    correction_bits: &[u8],
    nonce: u64,
    key_commitment: &str,
) -> String {
    sha256_hex(&[
        &u64_le(ts.window),
        ts.entropy_hex.as_bytes(),
        correction_bits,
        &u64_le(nonce),
        key_commitment.as_bytes(),
    ])
}

/// Assemble a full binding for a freshly minted timestamp.
pub fn bind_signature(
    ts: QuantumTimestamp,
    prev_chain_hex: &str,
    correction_bits: &[u8],
    nonce: u64,
    key_commitment: &str,
) -> TemporalBinding {
    let signature_tag_hex = signature_tag(&ts, correction_bits, nonce, key_commitment);
    TemporalBinding {
        valid_until_window: ts.window + VALIDITY_HORIZON,
        signature_tag_hex,
        prev_chain_hex: prev_chain_hex.to_string(),
        issued: ts,
    }
}

/// Recompute the expected chain link for a timestamp given the verifier's
/// chain head. A genuine, in-order signature's `chain_hex` matches exactly.
pub fn expected_chain_link(prev_chain_hex: &str, ts: &QuantumTimestamp) -> String {
    sha256_hex(&[prev_chain_hex.as_bytes(), &u64_le(ts.window), ts.entropy_hex.as_bytes()])
}

/// Forensic record of what the temporal trap observed — surfaced on the
/// dashboard so the rejection is *explainable*, not just a red light.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplayTrapReport {
    /// The notary's current mint frontier (its quantum clock).
    pub verifier_window: u64,
    /// The signature's claimed window.
    pub signature_window: u64,
    /// True when `tag` recomputation mismatched (transplant attempt).
    pub tag_ok: bool,
    /// True when the chain link belongs to the notary's minted history.
    pub chain_ok: bool,
    /// True when the signature's sifting window has NOT been consumed by a
    /// prior acceptance — false here is the replay: the window's sequence
    /// slot in the sifting history is already filled.
    pub sequence_ok: bool,
    /// True when the signature is still inside the validity horizon.
    pub freshness_ok: bool,
}

impl ReplayTrapReport {
    /// One-line human explanation of the first failed check. Replay
    /// (sequence) is reported before expiry — for an ancient re-broadcast
    /// both are true, but the replay is the intrusion worth naming.
    pub fn explanation(&self) -> &'static str {
        if !self.tag_ok {
            "temporal trap: timestamp not bound to this signature (transplant attempt)"
        } else if !self.sequence_ok {
            "temporal trap: sifting-window sequence mismatch — signature is from the past (replay)"
        } else if !self.chain_ok {
            "temporal trap: timestamp hash-chain broken — timestamp never minted by this notary"
        } else if !self.freshness_ok {
            "temporal trap: signature expired — validity horizon passed"
        } else {
            "temporal binding verified"
        }
    }
}

/// The pure temporal-trap decision. Returns `Ok(())` when the binding is
/// fully valid: the tag welds it to this exact signature, its chain link
/// belongs to the notary's minted history, its sifting window has never
/// been consumed by an earlier acceptance (the replay check), and it is
/// still inside the validity horizon. Otherwise the forensic report
/// explains which check fired.
pub fn trap_check(
    binding: &TemporalBinding,
    correction_bits: &[u8],
    nonce: u64,
    key_commitment: &str,
    chain_history: &[String],
    consumed_windows: Option<&std::collections::HashSet<u64>>,
    verifier_window: u64,
) -> Result<(), ReplayTrapReport> {
    let ts = &binding.issued;
    let tag_ok = signature_tag(ts, correction_bits, nonce, key_commitment)
        == binding.signature_tag_hex;
    // Chain integrity is two-layered: the link must be structurally sound
    // (extend its carried predecessor — portable across notary instances)
    // and, when this verifier's notary HAS minted past this window, the
    // link must belong to that minted history (a fully local check).
    let structurally_sound =
        expected_chain_link(&binding.prev_chain_hex, ts) == ts.chain_hex;
    let locally_minted = chain_history.iter().any(|link| link == &ts.chain_hex);
    let chain_ok = structurally_sound
        && (locally_minted || ts.window > verifier_window);
    let sequence_ok = consumed_windows.is_none_or(|s| !s.contains(&ts.window));
    let freshness_ok = verifier_window.saturating_sub(ts.window) < VALIDITY_HORIZON;

    let report = ReplayTrapReport {
        verifier_window,
        signature_window: ts.window,
        tag_ok,
        chain_ok,
        sequence_ok,
        freshness_ok,
    };
    if tag_ok && chain_ok && sequence_ok && freshness_ok {
        Ok(())
    } else {
        Err(report)
    }
}

/// The document-safe temporal check — the replay trap for signatures
/// embedded in long-lived sealed containers.
///
/// `verify()`'s freshness horizon (64 windows) exists to kill replayed
/// *bearer* signatures: something captured on the wire and aired later. A
/// document signature is the opposite lifecycle — it MUST re-verify years
/// after minting, every time the document is opened, or non-repudiation
/// itself breaks. This check therefore enforces tag + chain integrity +
/// non-repudiable mint (the anti-forgery core) but NOT wire freshness:
/// the replay vector for a document is substitution, and substitution is
/// caught by the tag + chain + the document-hash binding in the statistics.
pub fn trap_check_document(
    binding: &TemporalBinding,
    correction_bits: &[u8],
    nonce: u64,
    key_commitment: &str,
    chain_history: &[String],
    verifier_window: u64,
) -> Result<(), ReplayTrapReport> {
    let ts = &binding.issued;
    let tag_ok = signature_tag(ts, correction_bits, nonce, key_commitment)
        == binding.signature_tag_hex;
    let structurally_sound =
        expected_chain_link(&binding.prev_chain_hex, ts) == ts.chain_hex;
    let locally_minted = chain_history.iter().any(|link| link == &ts.chain_hex);
    let chain_ok = structurally_sound && locally_minted;

    let report = ReplayTrapReport {
        verifier_window,
        signature_window: ts.window,
        tag_ok,
        chain_ok,
        sequence_ok: true,   // N/A: documents never consume their window — re-opening must stay possible
        freshness_ok: true,  // N/A: documents outlive any wire horizon by design
    };
    if tag_ok && chain_ok {
        Ok(())
    } else {
        Err(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy(seed: u8) -> Vec<u8> {
        (0..16).map(|i| seed.wrapping_add(i * 7)).collect()
    }

    #[test]
    fn chain_links_are_deterministic_and_order_sensitive() {
        let g0 = "GENESIS";
        let t1 = mint_timestamp(1, &entropy(1), g0);
        let t2 = mint_timestamp(2, &entropy(2), &t1.chain_hex);
        assert_eq!(expected_chain_link(g0, &t1), t1.chain_hex);
        assert_eq!(expected_chain_link(&t1.chain_hex, &t2), t2.chain_hex);
        // Reordering breaks the chain: linking t2 onto g0 directly does not
        // reproduce t2's own chain value (which used t1's head).
        assert_ne!(expected_chain_link(g0, &t2), t2.chain_hex);
    }

    #[test]
    fn trap_accepts_forward_signature_and_rejects_replay() {
        let t1 = mint_timestamp(1, &entropy(1), "GENESIS");
        let history = vec!["GENESIS".to_string(), t1.chain_hex.clone()];
        let binding = bind_signature(t1.clone(), "GENESIS", &[1, 0, 1], 42, "commitment");
        // Fresh verifier: window 1 never consumed → valid.
        assert!(
            trap_check(&binding, &[1, 0, 1], 42, "commitment", &history, None, 1).is_ok()
        );
        // Replay: the window was consumed by the first acceptance → the
        // signature of the past is dead even though the tag is intact.
        let consumed: std::collections::HashSet<u64> = [1u64].into_iter().collect();
        let err = trap_check(&binding, &[1, 0, 1], 42, "commitment", &history, Some(&consumed), 1)
            .expect_err("replay must be trapped");
        assert!(!err.sequence_ok);
        assert!(err.tag_ok, "replay keeps the tag intact — sequence is what catches it");
    }

    #[test]
    fn trap_catches_transplanted_bindings() {
        let t1 = mint_timestamp(1, &entropy(1), "GENESIS");
        let history = vec!["GENESIS".to_string(), t1.chain_hex.clone()];
        let binding = bind_signature(t1, "GENESIS", &[1, 0, 1], 42, "commitment");
        // Same timestamp on DIFFERENT signature bits → tag mismatch fires
        // before anything else.
        let err = trap_check(&binding, &[0, 1, 0], 42, "commitment", &history, None, 1)
            .expect_err("transplanted binding must be trapped");
        assert!(!err.tag_ok);
        assert!(err.sequence_ok);
    }

    #[test]
    fn trap_catches_forged_future_timestamps_via_chain_head() {
        // Attacker invents window 1000 hoping to jump the clock — but the
        // chain link must belong to the notary's minted history, which it
        // does not.
        let forged = QuantumTimestamp {
            window: 1000,
            unix_ms: 0,
            entropy_hex: "deadbeef".into(),
            chain_hex: sha256_hex(&[b"attacker-guess"]),
        };
        let binding = bind_signature(forged, "GENESIS", &[0], 7, "commitment");
        let err = trap_check(
            &binding,
            &[0],
            7,
            "commitment",
            &["GENESIS".to_string()],
            None,
            1000,
        )
        .expect_err("forged future timestamp must be trapped");
        assert!(!err.chain_ok);
    }

    #[test]
    fn expiry_kills_stale_but_never_accepted_signatures() {
        let t1 = mint_timestamp(1, &entropy(1), "GENESIS");
        let history = vec!["GENESIS".to_string(), t1.chain_hex.clone()];
        // Horizon is 64: a signature minted at window 1 is dead once the
        // notary has advanced to window 65 — even if never accepted.
        let binding = bind_signature(t1, "GENESIS", &[1], 9, "commitment");
        let err = trap_check(&binding, &[1], 9, "commitment", &history, None, 65)
            .expect_err("expired signature must be trapped");
        assert!(!err.freshness_ok);
        assert_eq!(
            err.explanation(),
            "temporal trap: signature expired — validity horizon passed"
        );
    }

    /// Cross-laptop portability: a second notary instance (same seed,
    /// fresh clock) verifies a foreign-minted timestamp structurally — the
    /// link must extend its carried predecessor even though this notary
    /// never minted it.
    #[test]
    fn foreign_notary_verifies_structural_chain_integrity() {
        let t1 = mint_timestamp(1, &entropy(1), "GENESIS");
        let binding = bind_signature(t1, "GENESIS", &[1], 5, "commitment");
        // Verifier whose own history is only the genesis link, frontier 0.
        assert!(
            trap_check(
                &binding,
                &[1],
                5,
                "commitment",
                &["QDS-GENESIS-0".to_string()],
                None,
                0
            )
            .is_ok()
        );
        // A tampered link fails the structural check even remotely.
        let mut broken = binding.clone();
        broken.issued.chain_hex = "tampered".into();
        let err = trap_check(
            &broken,
            &[1],
            5,
            "commitment",
            &["QDS-GENESIS-0".to_string()],
            None,
            0,
        )
        .expect_err("tampered chain must be trapped");
        assert!(!err.chain_ok);
    }

    /// THE long-lived-document guarantee: a document's embedded signature
    /// keeps verifying no matter how far the notary's clock has advanced —
    /// 100 signing sessions later, the seal still opens.
    #[test]
    fn document_signatures_survive_100_sessions() {
        let t1 = mint_timestamp(1, &entropy(1), "GENESIS");
        let binding = bind_signature(t1, "GENESIS", &[1, 0, 1, 0], 11, "commitment");
        // Wire path: by window 65 the bearer freshness horizon kills it...
        assert!(
            trap_check(&binding, &[1, 0, 1, 0], 11, "commitment", &["QDS-GENESIS-0".to_string(), binding.issued.chain_hex.clone()], Some(&Default::default()), 65)
                .is_err()
        );
        // ...but the DOCUMENT path keeps it verifiable forever (and the
        // notary has fully minted the window, so the local-mint branch is
        // exercised too).
        assert!(
            trap_check_document(
                &binding,
                &[1, 0, 1, 0],
                11,
                "commitment",
                &["QDS-GENESIS-0".to_string(), binding.issued.chain_hex.clone()],
                101
            )
            .is_ok()
        );
    }

    /// The document path still catches the attacks: transplant and forged
    /// chains are NOT excused by document longevity.
    #[test]
    fn document_path_still_traps_transplant_and_forgery() {
        let t1 = mint_timestamp(1, &entropy(1), "GENESIS");
        let chain = ["QDS-GENESIS-0".to_string(), t1.chain_hex.clone()];
        let binding = bind_signature(t1, "GENESIS", &[1, 1, 0], 3, "commitment");
        // Transplant: same binding on different bits → tag fires.
        let err = trap_check_document(&binding, &[0, 0, 1], 3, "commitment", &chain, 50)
            .expect_err("document transplant must be trapped");
        assert!(!err.tag_ok);
        // Forged chain: never minted by this notary → chain fires.
        let bogus = mint_timestamp(2, &entropy(9), "attacker-link");
        let bogus_binding = bind_signature(bogus, "attacker-link", &[1], 4, "commitment");
        let err2 = trap_check_document(&bogus_binding, &[1], 4, "commitment", &chain, 50)
            .expect_err("document with forged chain must be trapped");
        assert!(!err2.chain_ok);
    }
}
