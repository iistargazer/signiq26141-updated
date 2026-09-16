use qds::attacks::{
    attempt_channel_tampering, attempt_forgery, attempt_impersonation, attempt_replay,
    attempt_unauthorized_verification,
};
use qds::{
    estimate_forgery_probability, metrics, sign, theory_forgery_probability, verify,
    verify_transferability, Verdict, Trent,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const QUBITS: usize = 16;
const LAMBDA: usize = 4;
const MESSAGE: &[u8] = b"SIH26141 ledger entry #4711: transfer 5.000 QCO to acct 88";

#[test]
fn legitimate_signature_is_deterministically_accepted() {
    let mut rng = StdRng::seed_from_u64(1001);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let report = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert!(report.accepted, "legit signature must accept: {:?}", report.reason);
    assert_eq!(report.match_ratio, 1.0);
    assert_eq!(report.mismatches, 0);
}

#[test]
fn tampered_message_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1002);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let tampered = b"SIH26141 ledger entry #4711: transfer 9.999 QCO to acct 13";
    let report = verify(tampered, &sig, &mut trent, 0.0);
    assert!(!report.accepted, "modified message must be rejected");
    assert!(report.mismatches > 0);
}

#[test]
fn forgery_attack_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1003);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let attempt = attempt_forgery(MESSAGE, &mut trent, &mut rng);
    let report = verify(MESSAGE, &attempt.signature, &mut trent, 0.0);
    assert!(!report.accepted, "random-bit forgery must be rejected");
}

#[test]
fn impersonation_attack_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1004);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let real = b"invoice paid: 120 QCO";
    let (genuine, _) = sign(real, &mut trent, &mut rng);
    let attempt = attempt_impersonation(&genuine, real, MESSAGE);
    let report = verify(MESSAGE, &attempt.signature, &mut trent, 0.0);
    assert!(!report.accepted, "signature transplant must be rejected");
}

#[test]
fn replay_attack_is_rejected() {
    let mut rng = StdRng::seed_from_u64(1005);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (genuine, _) = sign(MESSAGE, &mut trent, &mut rng);
    let first = verify(MESSAGE, &genuine, &mut trent, 0.0);
    assert!(first.accepted, "first presentation must accept");

    let replay = attempt_replay(&genuine, MESSAGE);
    let second = verify(MESSAGE, &replay.signature, &mut trent, 0.0);
    assert!(!second.accepted, "replay of consumed nonce must be rejected");
    assert!(second.reason.contains("replay"));
}

#[test]
fn channel_tampering_is_detected_proportionally() {
    let mut rng = StdRng::seed_from_u64(1006);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _teleports) = sign(MESSAGE, &mut trent, &mut rng);

    let attempt =
        attempt_channel_tampering(&sig, 0.5, MESSAGE, &trent, &mut rng);
    let mut sig = attempt.signature.clone();
    sig.nonce = trent.issue_nonce(); // tamper flow uses its own fresh nonce
    let report = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert!(!report.accepted, "50% channel tampering must be rejected");
    assert!(report.mismatches > 0, "tampering must produce mismatches");
}

#[test]
fn forgery_probability_matches_theory() {
    let mut rng = StdRng::seed_from_u64(1007);
    // All-position guess forgery: (1/4)^(qubits*lambda) = (1/4)^64 ≈ 5e-39
    let theory = theory_forgery_probability(QUBITS, LAMBDA);
    assert!(theory < 1e-30, "theory bound should be astronomically small");

    // Small-parameter Monte Carlo: 1 qubit, 1 lambda => per-signature 1/4.
    let p = estimate_forgery_probability((1, 1), 4000, &mut rng);
    assert!(
        (p - 0.25).abs() < 0.05,
        "MC forgery probability {p} should approximate 1/4"
    );
}

#[test]
fn failed_verification_keeps_nonce_usable() {
    let mut rng = StdRng::seed_from_u64(1008);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    // Wrong message first (verification fails)...
    let bad = verify(b"wrong", &sig, &mut trent, 0.0);
    assert!(!bad.accepted);
    // ...the genuine message must still verify (nonce not consumed on failure).
    let good = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert!(good.accepted, "failed attempt must not burn the nonce");
}

#[test]
fn genuine_signature_yields_1acc_verdict() {
    let mut rng = StdRng::seed_from_u64(1009);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let report = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert_eq!(report.verdict, Verdict::Acc1, "clean channel => transferable");
    assert!(report.transferable());
}

#[test]
fn forged_signature_in_gray_zone_yields_0acc_not_rej_boundary() {
    // A signature with a few flipped bits lands in the gray zone (0-ACC) when
    // the mismatch fraction is in (c1, c2]. We craft one at ~6% mismatch with
    // c2 = 0.10: valid-ish locally, NOT transferable.
    let mut rng = StdRng::seed_from_u64(1010);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (mut sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    // Flip exactly 4 of 128 signature bits => 2 of 64 positions mismatch (~3%).
    for b in sig.correction_bits.iter_mut().take(4) {
        *b ^= 1;
    }
    let report = verify(MESSAGE, &sig, &mut trent, 0.10);
    assert_eq!(report.verdict, Verdict::Acc0, "few mismatches => 0-ACC gray zone");
    assert!(report.accepted, "0-ACC is still locally accepted");
    assert!(!report.transferable(), "0-ACC must not be forwarded as trusted");
}

#[test]
fn unauthorized_verification_attempt_is_flagged() {
    let mut rng = StdRng::seed_from_u64(1012);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (genuine, _) = sign(MESSAGE, &mut trent, &mut rng);

    // An unauthorized party replays a captured signature through a verbatim
    // attempt — the attempt is its own threat class and is surfaced as such.
    let attempt = attempt_unauthorized_verification(&genuine, MESSAGE, b"attacker payload");
    assert_eq!(attempt.kind, qds::AttackKind::UnauthorizedVerification);
    // The captured bits are unchanged, so statistics would fail on a fresh
    // nonce for a different message (impersonation-equivalent):
    let mut sig = attempt.signature.clone();
    sig.nonce = trent.issue_nonce();
    let report = verify(b"attacker payload", &sig, &mut trent, 0.0);
    assert!(!report.accepted, "unauthorized re-presentation must be rejected");
}

#[test]
fn channel_tampering_scales_with_fraction() {
    let mut rng = StdRng::seed_from_u64(1013);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);
    let (genuine_sig, _teleports) = sign(MESSAGE, &mut trent, &mut rng);

    // A mild 10% disturbance should produce a small but nonzero mismatch
    // count; a 90% disturbance should mismatch most positions.
    let mut count_mismatches = |fraction: f64| -> usize {
        let attempt =
            attempt_channel_tampering(&genuine_sig, fraction, MESSAGE, &trent, &mut rng);
        let mut sig = attempt.signature;
        sig.nonce = trent.issue_nonce();
        verify(MESSAGE, &sig, &mut trent, 0.10).mismatches
    };
    let mild = count_mismatches(0.1);
    let heavy = count_mismatches(0.9);
    assert!(heavy > mild * 2, "mismatches must scale with tamper fraction ({mild} vs {heavy})");
}

#[test]
fn noisy_channel_thresholds_are_statistically_sized() {
    use qds::noisy::{assess_mismatch, hoeffding_slack};

    // Clean-channel statistics always yield 1-ACC:
    let a = assess_mismatch(0, 64, 0.0, 0.05, 0.05);
    assert_eq!(a.verdict, Verdict::Acc1);

    // Slack shrinks with sample size (Hoeffding):
    assert!(hoeffding_slack(10_000, 0.05) < hoeffding_slack(50, 0.05));

    // A 75% mismatch (guessed forgery) is always flagged:
    let b = assess_mismatch(48, 64, 0.05, 0.05, 0.05);
    assert_eq!(b.verdict, Verdict::Rej);
    assert!(b.channel_flagged);
}

#[test]
fn six_state_scheme_rejects_all_attacks() {
    use qds::six_state as ss;
    let mut rng = StdRng::seed_from_u64(1014);
    let params = ss::SessionParams { n_pulses: 800, test_fraction: 0.25, basis_misalignment: 0.0 };
    let thresholds = qds::Thresholds { c1: 0.10, c2: 0.25 };

    let session = ss::build_session(params.clone(), 1, 1, 0.0, &mut rng);
    let material = ss::VerifierMaterial::from_session(&session);

    // Honest:
    let sig = ss::sign_six_state(&session, 0);
    let v_ok = ss::verify_six_state(&sig, &material, &session.session_commitment, thresholds);
    assert_eq!(v_ok.verdict, Verdict::Acc1, "honest six-state signature must accept");

    // Forgery:
    let forged = ss::attempt_six_state_forgery(&session, 0, &mut rng);
    let v_f = ss::verify_six_state(&forged, &material, &session.session_commitment, thresholds);
    assert_eq!(v_f.verdict, Verdict::Rej);

    // Impersonation (message transplant):
    let transplant = ss::attempt_six_state_impersonation(&sig);
    let v_i = ss::verify_six_state(&transplant, &material, &session.session_commitment, thresholds);
    assert_eq!(v_i.verdict, Verdict::Rej);

    // Channel tampering (30% disturbed):
    let (t_session, t_sig) = ss::attempt_six_state_tampering(&params, 1, 2, 0.3, 0, &mut rng);
    let t_material = ss::VerifierMaterial::from_session(&t_session);
    let v_t = ss::verify_six_state(&t_sig, &t_material, &t_session.session_commitment, thresholds);
    assert_eq!(v_t.verdict, Verdict::Rej);

    // Unauthorized verifier:
    let v_u = ss::verify_six_state(&sig, &ss::VerifierMaterial::default(), &session.session_commitment, thresholds);
    assert_eq!(v_u.verdict, Verdict::Rej);
    assert!(v_u.reason.contains("unauthorized"));
}

#[test]
fn performance_evaluation_meets_lap2_targets() {
    let report = metrics::evaluate(80, 90210);

    // Verification accuracy (both schemes):
    assert!(report.teleport.confusion.accuracy() > 0.99);
    assert!(report.six_state.confusion.accuracy() > 0.99);

    // False-alarm rate on legitimate signatures is zero:
    assert_eq!(report.teleport.confusion.false_positive_rate(), 0.0);
    assert_eq!(report.six_state.confusion.false_positive_rate(), 0.0);

    // Detection rate over attacks is 1.0 in the noiseless simulation:
    assert!(report.teleport.confusion.detection_rate() > 0.99);
    assert!(report.six_state.confusion.detection_rate() > 0.99);

    // Empirical forgery probability ~0 vs theory 4^-8:
    assert!(report.teleport.empirical_forgery_probability < 0.02);
    assert!((report.teleport.theoretical_forgery_probability - 4.0_f64.powi(-8)).abs() < 1e-12);

    // Every attack class detected by the six-state layer:
    for (class, d) in &report.six_state.detection_by_class {
        assert!(d.rate() > 0.95, "class {class} detection rate too low");
    }
}

#[test]
fn transferability_consensus_genuine_and_forged() {
    let mut rng = StdRng::seed_from_u64(1011);
    let mut trent = Trent::setup(QUBITS, LAMBDA, &mut rng);

    // Genuine: Bob accepts 1-ACC; Charlie (transferability) must also be non-REJ.
    let (sig, _) = sign(MESSAGE, &mut trent, &mut rng);
    let bob = verify(MESSAGE, &sig, &mut trent, 0.0);
    assert_eq!(bob.verdict, Verdict::Acc1);
    let charlie = verify_transferability(MESSAGE, &sig, &mut trent, 0.10);
    assert!(charlie.accepted, "second verifier must agree on genuine signature");

    // Forged: Charlie must reject, and the attempt must not consume the nonce.
    let attempt = attempt_forgery(b"attacker payload", &mut trent, &mut rng);
    let charlie2 = verify_transferability(b"attacker payload", &attempt.signature, &mut trent, 0.10);
    assert_eq!(charlie2.verdict, Verdict::Rej);
}
