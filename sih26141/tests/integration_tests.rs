use attacks::AttackSimulator;
use crypto::{compute_message_hmac, verify_message_hmac};
use detection::ThreatDetector;
use quantum::{privacy_amplification, QuantumKeyGenerator};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_secure_pipeline_end_to_end() {
    let mut rng = StdRng::seed_from_u64(1337);
    let qkg = QuantumKeyGenerator::new(2000).unwrap();
    let keys = qkg.generate_eigenstates(&mut rng);

    let transmission = AttackSimulator::run_secure_simulation(&keys, &mut rng);
    // No eavesdropping => Alice's and Bob's sifted keys must agree exactly
    assert_eq!(transmission.sifted_key_bits, transmission.alice_sifted_bits);

    let detector = ThreatDetector::new(0.15).unwrap();
    let evaluation = detector
        .evaluate_signature(transmission.mismatch_rate, transmission.matching_bases_count)
        .unwrap();

    assert!(evaluation.is_authentic);
    assert!(!evaluation.threat_flagged);

    let secret = privacy_amplification(&transmission.sifted_key_bits);
    let message = b"Test payload";
    let tag = compute_message_hmac(&secret, message).unwrap();
    assert!(verify_message_hmac(&secret, message, &tag).unwrap());
    assert!(!verify_message_hmac(&secret, b"Tampered payload", &tag).unwrap());
}

#[test]
fn test_attack_detection_pipeline() {
    let mut rng = StdRng::seed_from_u64(1337);
    let qkg = QuantumKeyGenerator::new(2000).unwrap();
    let keys = qkg.generate_eigenstates(&mut rng);

    let transmission = AttackSimulator::run_intercept_resend_simulation(&keys, &mut rng);
    // Eavesdropping disturbs the channel => keys must disagree
    assert_ne!(transmission.sifted_key_bits, transmission.alice_sifted_bits);

    let detector = ThreatDetector::new(0.15).unwrap();
    let evaluation = detector
        .evaluate_signature(transmission.mismatch_rate, transmission.matching_bases_count)
        .unwrap();

    assert!(!evaluation.is_authentic);
    assert!(evaluation.threat_flagged);
}

#[test]
fn test_input_validation_guards() {
    assert!(QuantumKeyGenerator::new(0).is_err());
    assert!(ThreatDetector::new(-0.1).is_err());
    assert!(ThreatDetector::new(1.5).is_err());
    assert!(ThreatDetector::new(0.15)
        .unwrap()
        .with_confidence_delta(0.0)
        .is_err());
}
