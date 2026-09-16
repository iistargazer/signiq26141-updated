use attacks::AttackSimulator;
use crypto::{compute_message_hmac, verify_message_hmac};
use detection::ThreatDetector;
use quantum::{privacy_amplification, QuantumKeyGenerator};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn main() {
    println!("=== SIH26141 Quantum-Secured Pipeline Simulation ===");

    // Seeded RNG for reproducibility (use OsRng for real key generation)
    let mut rng = StdRng::seed_from_u64(42);

    let key_length = 3000;
    let base_threshold = 0.15;

    let qkg = QuantumKeyGenerator::new(key_length).unwrap();
    let alice_keys = qkg.generate_eigenstates(&mut rng);
    println!("[1] Alice generated {key_length} raw Pauli eigenstates.");

    let detector = ThreatDetector::new(base_threshold).unwrap();

    // --- SCENARIO A: Secure Channel (No Eavesdropping) ---
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

    if eval_secure.is_authentic {
        // NOTE: a real pipeline runs error correction here before PA
        let shared_secret = privacy_amplification(&tx_secure.sifted_key_bits);
        println!("  -> Derived Secret (SHA-256 PA): {}...", &shared_secret[..16]);

        let message = b"SIH26141 Sensitive Financial Transaction Data";
        let tag = compute_message_hmac(&shared_secret, message).unwrap();
        println!("  -> HMAC-SHA256 Tag: {tag}");
        println!(
            "  -> HMAC Verification: {}",
            verify_message_hmac(&shared_secret, message, &tag).unwrap()
        );
    }

    // --- SCENARIO B: Intercept-Resend Attack (expected QBER ~= 1/3) ---
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
    }

    println!("\n=== Simulation Completed Successfully ===");
}
