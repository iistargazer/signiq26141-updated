//! SIH26141 main binary — a seeded, reproducible walk through every engine
//! of the pipeline. Everything here is a **classical software simulation** of
//! the quantum protocols (no quantum hardware, no physical channel).
//!
//! Scenarios:
//!   A. Secure six-state run → key distillation → HMAC binding
//!   B. Intercept-resend attack → QBER alarm → distillation aborted
//!      (an abort rejects this channel run; it is not key revocation)
//!   C. Chernoff–Hoeffding finite-sample bounds over real measurement batches
//!   D. Document sealing → tamper attempts → verification + audit-chain proof
//!   E. Full attack-class evaluation sweep (detection / false-accept rates)

use attacks::AttackSimulator;
use audit::AuditLog;
use crypto::{compute_message_hmac, verify_message_hmac};
use detection::bounds::{confidence_interval, threshold_curve, verdict_confidence};
use detection::ThreatDetector;
use qds::metrics::evaluate;
use quantum::{privacy_amplification, QuantumKeyGenerator};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sealing::{
    container_bytes, container_bytes_opt, parse_container, seal_document, unseal_envelope,
    verify_document, AuditRef, QuorumSpec,
};
use sha2::{Digest, Sha256};

const KEY_LENGTH: usize = 3000;
const BASE_THRESHOLD: f64 = 0.15;
const DELTA: f64 = 0.01; // two-sided confidence 1 − δ = 99%
const NOISE_FLOOR: f64 = 0.02;

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Fixed wall-clock stamps keep the whole run bit-reproducible for a given
/// seed; a server would use real timestamps instead.
const TS: &str = "2026-09-30T00:00:00.000Z";

fn main() {
    println!("=== SIH26141 Quantum-Secured Pipeline Simulation ===");
    println!("(classical software simulation of the quantum protocols; seeded for reproducibility)");

    let mut rng = StdRng::seed_from_u64(42);

    let qkg = QuantumKeyGenerator::new(KEY_LENGTH).unwrap();
    let alice_keys = qkg.generate_eigenstates(&mut rng);
    println!("\n[1] Alice generated {KEY_LENGTH} raw Pauli eigenstates.");

    let detector = ThreatDetector::new(BASE_THRESHOLD).unwrap();

    // --- SCENARIO A: Secure Channel (No Eavesdropping) -----------------------
    println!("\n--- Scenario A: Legitimate Secure Channel ---");
    let tx_secure = AttackSimulator::run_secure_simulation(&alice_keys, &mut rng);
    let eval_secure = detector
        .evaluate_signature(tx_secure.mismatch_rate, tx_secure.matching_bases_count)
        .unwrap();

    println!("  -> Matching Bases Count: {}", tx_secure.matching_bases_count);
    println!("  -> Measured QBER:        {:.4}", eval_secure.mismatch_rate);
    println!("  -> Dynamic Threshold:    {:.4}", eval_secure.dynamic_threshold);
    println!("  -> Threat Flagged:       {}", eval_secure.threat_flagged);

    // Sanity check: clean channel => keys agree
    debug_assert_eq!(tx_secure.sifted_key_bits, tx_secure.alice_sifted_bits);

    let mut shared_secret = String::new();
    if eval_secure.is_authentic {
        // NOTE: a real pipeline runs error correction here before PA.
        shared_secret = privacy_amplification(&tx_secure.sifted_key_bits);
        println!("  -> Derived Secret (SHA-256 PA): {}...", &shared_secret[..16]);

        let message = b"SIH26141 Sensitive Financial Transaction Data";
        let tag = compute_message_hmac(&shared_secret, message).unwrap();
        println!("  -> HMAC-SHA256 Tag: {tag}");
        println!(
            "  -> HMAC Verification: {}",
            verify_message_hmac(&shared_secret, message, &tag).unwrap()
        );
    }

    // --- SCENARIO B: Intercept-Resend Attack (expected QBER ~= 1/3) ----------
    println!("\n--- Scenario B: Intercept-Resend Eavesdropping Attack ---");
    let tx_attack = AttackSimulator::run_intercept_resend_simulation(&alice_keys, &mut rng);
    let eval_attack = detector
        .evaluate_signature(tx_attack.mismatch_rate, tx_attack.matching_bases_count)
        .unwrap();

    println!("  -> Matching Bases Count: {}", tx_attack.matching_bases_count);
    println!("  -> Measured QBER:        {:.4}", eval_attack.mismatch_rate);
    println!("  -> Dynamic Threshold:    {:.4}", eval_attack.dynamic_threshold);
    println!("  -> Threat Flagged:       {}", eval_attack.threat_flagged);

    if !eval_attack.is_authentic {
        println!("  -> SECURITY ALERT: Eavesdropping detected! Key distillation aborted.");
        println!("     (the abort rejects this channel run; it is not key revocation — no");
        println!("      revocation registry exists in this model)");
    }

    // --- SCENARIO C: Finite-sample statistical bounds ------------------------
    println!("\n--- Scenario C: Chernoff–Hoeffding Bounds on Real Measurement Batches ---");
    for (label, tx) in [("secure channel", &tx_secure), ("attacked channel", &tx_attack)] {
        let n = tx.matching_bases_count;
        let k = (tx.mismatch_rate * n as f64).round() as usize;
        let ci = confidence_interval(k, n, DELTA);
        let verdict = verdict_confidence(k, n, BASE_THRESHOLD);

        println!("  [{label}] n={n} mismatches={k} (p̂={:.4})", ci.p_hat);
        println!(
            "    Hoeffding 99% CI: [{:.4}, {:.4}] | Chernoff upper: {:.4} (gain ×{:.2})",
            ci.lo_hoeffding, ci.hi_hoeffding, ci.hi_chernoff, bounds_gain(&ci)
        );
        println!(
            "    verdict vs {BASE_THRESHOLD} line: band={:?} p_value={:.3e} rejection_conf={:.6}",
            verdict.band, verdict.p_value, verdict.rejection_confidence
        );
    }
    // The dynamic threshold narrows like a vice as the sample grows.
    let curve = threshold_curve(16, tx_secure.matching_bases_count.max(16), 2, NOISE_FLOOR, DELTA);
    println!(
        "    dynamic threshold: n=16 → {:.4} | n={} → {:.4} (noise floor {NOISE_FLOOR} + Hoeffding slack)",
        curve[0].threshold, curve[1].n, curve[1].threshold
    );

    // --- SCENARIO D: Sealing, tampering, verification + audit chain ----------
    println!("\n--- Scenario D: Document Sealing → Tamper → Verify + Audit Ledger ---");
    scenario_d(&shared_secret, &mut rng);

    // --- SCENARIO E: Full attack-class evaluation sweep ----------------------
    println!("\n--- Scenario E: Attack-Class Evaluation Sweep (detection / false-accept) ---");
    let report = evaluate(120, 42);
    let t = &report.teleport;
    println!(
        "  teleport QDS ({} trials, q={}, λ={}): accuracy {:.4} | detection {:.4} | false-accept {:.4}",
        t.trials, t.qubit_count, t.lambda,
        t.confusion.accuracy(), t.confusion.detection_rate(), t.confusion.false_negative_rate()
    );
    println!(
        "    forgery probability: empirical {:.6} vs theory 4^(−qλ) = {:.6}",
        t.empirical_forgery_probability, t.theoretical_forgery_probability
    );
    let s = &report.six_state;
    println!(
        "  six-state QDS ({} trials, {} pulses): accuracy {:.4} | detection {:.4} | false-accept {:.4}",
        s.trials, s.n_pulses,
        s.confusion.accuracy(), s.confusion.detection_rate(), s.confusion.false_negative_rate()
    );
    for (class, d) in &s.detection_by_class {
        println!("    {:<28} detection {:.1}%", class, d.rate() * 100.0);
    }
    println!("  (false-accept rate = missed-attack rate, i.e. the false-negative measure;");
    println!("   every decision above is an explicit threshold rule — no AI/ML anywhere)");
    for note in &report.notes {
        println!("  note: {note}");
    }

    println!("\n=== Simulation Completed Successfully ===");
}

/// Chernoff-vs-Hoeffding sharpness gain for the printed dossier.
fn bounds_gain(ci: &detection::bounds::ConfidenceInterval) -> f64 {
    if ci.hi_chernoff > 1e-12 {
        ci.hi_hoeffding / ci.hi_chernoff
    } else {
        1.0
    }
}

/// Scenario D body: seal a document under the distilled key, round-trip it
/// through the v3 envelope, attempt two tamper modes, and record the whole
/// lifecycle in a hash-chained audit log with a Merkle inclusion proof.
fn scenario_d(shared_secret: &str, rng: &mut StdRng) {
    if shared_secret.is_empty() {
        println!("  (skipped: no distilled key from Scenario A)");
        return;
    }

    let payload = b"SIH26141 quarterly ledger - sealed by the main binary";
    let mut log = AuditLog::new();
    let e_seal = log.append(
        "seal",
        "main_app",
        true,
        "main binary sealed ledger.txt under a simulated-QKD key",
        &sha256_hex(payload),
        TS,
    );
    let audit_ref = AuditRef {
        first_seq: Some(e_seal.seq),
        last_seq: Some(e_seal.seq),
        root: log.root(),
    };

    let doc = seal_document(
        "ledger.txt",
        "text/plain",
        payload,
        shared_secret,
        TS,
        audit_ref,
        QuorumSpec::default(),
        rng,
    )
    .unwrap_or_else(|e| panic!("sealing failed: {e}"));

    // Round trip: v3 envelope bytes → parse → unseal → verify.
    let sealed = container_bytes(&doc);
    let parsed = parse_container(&sealed).unwrap_or_else(|e| panic!("container parse failed: {e}"));
    let opened =
        unseal_envelope(&parsed, shared_secret).unwrap_or_else(|e| panic!("unseal failed: {e}"));
    let outcome = verify_document(&opened, shared_secret).unwrap_or_else(|e| panic!("verify failed: {e}"));
    println!(
        "  -> sealed {} bytes → {} container bytes → verify passed={} (authentic={}, integrity={}, key_match={}, via {})",
        payload.len(),
        sealed.len(),
        outcome.passed(),
        outcome.authentic,
        outcome.integrity,
        outcome.key_match,
        outcome.unlocked_via
    );
    let _ = log.append(
        "verify",
        "main_app",
        outcome.passed(),
        "legitimate container verified",
        &doc.meta.sha256,
        TS,
    );

    // Tamper mode 1: flip one byte of the v3 envelope (GCM seal over the
    // whole container) — the envelope must refuse to open.
    let mut env_tampered = container_bytes(&doc);
    let idx = env_tampered.len() - 10;
    env_tampered[idx] ^= 0x01;
    match parse_container(&env_tampered).and_then(|sealed| unseal_envelope(&sealed, shared_secret)) {
        Ok(_) => println!("  -> envelope tamper: ACCEPTED (unexpected!)"),
        Err(e) => {
            println!("  -> envelope tamper: rejected ({e})");
            let _ = log.append(
                "verify",
                "main_app",
                false,
                "tampered envelope rejected",
                &doc.meta.sha256,
                TS,
            );
        }
    }

    // Tamper mode 2: corrupt one base64 char of the payload inside a legacy
    // (clear-JSON) container — parsing still succeeds, verification must fail
    // on integrity (GCM tag / HMAC no longer match).
    let mut legacy_tampered = container_bytes_opt(&doc, false);
    if let Some(start) = legacy_tampered
        .windows(14)
        .position(|w| w == b"\"ciphertext\":\"")
        .map(|p| p + 14)
    {
        if start < legacy_tampered.len() {
            legacy_tampered[start] = if legacy_tampered[start] == b'A' { b'B' } else { b'A' };
        }
    }
    match parse_container(&legacy_tampered) {
        Ok(tampered_doc) => {
            let out = verify_document(&tampered_doc, shared_secret).unwrap_or_else(|e| panic!("verify failed: {e}"));
            println!(
                "  -> inner-payload tamper: passed={} (integrity={})",
                out.passed(),
                out.integrity
            );
            let _ = log.append(
                "verify",
                "main_app",
                out.passed(),
                "tampered payload rejected",
                &doc.meta.sha256,
                TS,
            );
        }
        Err(e) => println!("  -> inner-payload tamper: rejected at parse ({e})"),
    }

    // Forensic ledger: hash chain + Merkle root + inclusion proof.
    let chain = log.verify_chain();
    let root = log.root().unwrap_or_default();
    let proof = log.inclusion_proof(e_seal.seq).expect("inclusion proof");
    println!(
        "  -> audit ledger: {} events, root {}…, chain_ok={} ({})",
        log.len(),
        &root[..16],
        chain.ok,
        chain.detail
    );
    println!(
        "  -> inclusion proof for event #{}: verified={}",
        e_seal.seq,
        AuditLog::verify_inclusion(&proof)
    );
}
