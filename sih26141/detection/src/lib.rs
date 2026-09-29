//! Channel classification for the QKD layer.
//!
//! Distinguishes three channel states from the measured mismatch statistics:
//!
//! * `Secure`       — QBER within the configured noise-floor band.
//! * `Degraded`     — QBER above that band but within the shared decision
//!                    line; the measurement does not identify the cause.
//! * `UnderAttack`  — measured QBER exceeds the configured statistical
//!                    decision line; the observation alone cannot identify
//!                    whether noise, an attacker, or another cause produced it.
pub mod bounds;
pub struct ThreatDetector {
    base_threshold: f64,
    confidence_delta: f64,
}

/// Expected environmental bit-flip probability used to establish the noise
/// floor. Set to the configured channel noise (e.g. 0.03 for 3% fiber noise).
pub const DEFAULT_NOISE_FLOOR: f64 = 0.03;

/// One QKD-channel classification outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectionResult {
    pub is_authentic: bool,
    pub mismatch_rate: f64,
    pub dynamic_threshold: f64,
    pub threat_flagged: bool,
    pub note: &'static str,
    /// Three-way classification (secure / degraded / under attack).
    pub channel_class: ChannelClass,
    /// Noise floor used for the degraded band (echoed for UI display).
    pub noise_floor: f64,
    /// Environmental noise rate the channel was configured with (0 if none).
    pub measured_noise_rate: f64,
    /// Fraction of sifted positions whose value Eve could know — for six-
    /// state intercept-resend she picks the right basis with probability
    /// 1/3, so this is QBER·(3/2) under the standard model: each observed
    /// error implicates a 1/2-basis-known position. Feeds the PA budget.
    pub eve_information_fraction: f64,
    /// True when the sifted sample is large enough that the Hoeffding
    /// margin is smaller than the distance from the decision boundary —
    /// i.e. the classification is statistically settled, not noise.
    pub finite_key_ok: bool,
}

/// Three-way model-relative channel classification. The class describes
/// measured QBER relative to configured thresholds, not its physical cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelClass {
    /// QBER within the configured noise-floor band and the decision line.
    Secure,
    /// QBER above the noise-floor band but within the decision line.
    Degraded,
    /// QBER exceeds the configured decision line; no cause is inferred.
    UnderAttack,
}

impl ChannelClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelClass::Secure => "secure",
            ChannelClass::Degraded => "degraded",
            ChannelClass::UnderAttack => "under_attack",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ChannelClass::Secure => "Channel secure",
            ChannelClass::Degraded => "Above expected noise floor",
            ChannelClass::UnderAttack => "QBER decision threshold exceeded",
        }
    }
}

impl ThreatDetector {
    pub fn new(base_threshold: f64) -> Result<Self, &'static str> {
        if !(0.0..=1.0).contains(&base_threshold) {
            return Err("Threshold must be between 0.0 and 1.0.");
        }
        Ok(Self {
            base_threshold,
            confidence_delta: 0.05,
        })
    }

    /// Optional: override the failure probability δ of the statistical bound.
    pub fn with_confidence_delta(mut self, delta: f64) -> Result<Self, &'static str> {
        if !(0.0 < delta && delta < 1.0) {
            return Err("Confidence delta must be strictly between 0 and 1.");
        }
        self.confidence_delta = delta;
        Ok(self)
    }

    /// Two-sided Hoeffding bound: P(|p̂ − p| ≥ ε) ≤ 2·exp(−2nε²)
    /// ⇒ ε = √(ln(2/δ) / 2n). Scales with √(1/n), no variance guess.
    pub fn evaluate_signature(
        &self,
        mismatch_rate: f64,
        matching_bases_count: usize,
    ) -> Result<DetectionResult, &'static str> {
        self.evaluate_channel(mismatch_rate, matching_bases_count, self.base_threshold, 0.0)
    }

    /// Full three-way evaluation using measured QBER, sample size, an
    /// expected noise floor, and a configured decision line. Labels are
    /// model-relative and do not identify the cause of a high QBER.
    pub fn evaluate_channel(
        &self,
        mismatch_rate: f64,
        matching_bases_count: usize,
        noise_floor: f64,
        measured_noise_rate: f64,
    ) -> Result<DetectionResult, &'static str> {
        if !(0.0..=1.0).contains(&mismatch_rate) {
            return Err("Mismatch rate must be between 0.0 and 1.0.");
        }
        if matching_bases_count == 0 {
            return Ok(DetectionResult {
                is_authentic: false,
                mismatch_rate,
                dynamic_threshold: 1.0,
                threat_flagged: true,
                note: "Zero matching bases: complete signal loss or empty transmission.",
                channel_class: ChannelClass::UnderAttack,
                noise_floor,
                measured_noise_rate,
                eve_information_fraction: 1.0,
                finite_key_ok: false,
            });
        }

        let slack = ((2.0 / self.confidence_delta).ln() / (2.0 * matching_bases_count as f64)).sqrt();
        // dynamic_threshold keeps the legacy meaning: the largest QBER the
        // detector tolerates before flagging a breach.
        let dynamic_threshold = (self.base_threshold + slack).min(1.0);
        // The configured noise expectation creates a lower-confidence band,
        // but can never make the rejection line more permissive.
        let secure_line = (noise_floor.clamp(0.0, 1.0) + slack).min(dynamic_threshold);
        let (channel_class, note) = if mismatch_rate <= secure_line {
            (ChannelClass::Secure, "QBER is within the configured noise floor + Hoeffding margin.")
        } else if mismatch_rate <= dynamic_threshold {
            (
                ChannelClass::Degraded,
                "QBER is above the configured noise floor but within the decision line; this measurement does not identify the cause.",
            )
        } else {
            (
                ChannelClass::UnderAttack,
                "QBER exceeds the configured decision line; no key is distilled and this measurement does not identify the cause.",
            )
        };
        let is_authentic = channel_class != ChannelClass::UnderAttack;
        let threat_flagged = !is_authentic;

        // The Hoeffding interval must sit wholly on one side of the decision
        // line before the finite-sample outcome is marked settled.
        let lower = (mismatch_rate - slack).max(0.0);
        let upper = (mismatch_rate + slack).min(1.0);
        let finite_key_ok = upper <= dynamic_threshold || lower > dynamic_threshold;

        // Eve's information fraction: under six-state intercept-resend an
        // observed error implicates positions where Eve picked the right
        // basis (1/3 chance) — she knows the bit there. Conservative
        // accounting: charge 1/2 bit per error position × (3/2) scaling.
        let eve_information_fraction = (mismatch_rate * 1.5).min(1.0);

        Ok(DetectionResult {
            is_authentic,
            mismatch_rate,
            dynamic_threshold,
            threat_flagged,
            note,
            channel_class,
            noise_floor,
            measured_noise_rate,
            eve_information_fraction,
            finite_key_ok,
        })
    }
}

#[cfg(test)]
mod finite_key_tests {
    use super::*;

    #[test]
    fn small_samples_are_not_finite_key_ok() {
        // 30 sifted bits, QBER near the line: slack ≈ 0.26 >> margin
        let d = ThreatDetector::new(0.15).unwrap().evaluate_channel(0.17, 30, 0.0, 0.0).unwrap();
        assert!(!d.finite_key_ok);
        assert!(d.eve_information_fraction > 0.0);
    }

    #[test]
    fn large_samples_settle_the_decision() {
        // 20k sifted bits at clean QBER: slack ≈ 0.0098 << margin
        let d = ThreatDetector::new(0.15).unwrap().evaluate_channel(0.0, 20_000, 0.0, 0.0).unwrap();
        assert!(d.finite_key_ok, "large clean sample must settle");
    }

    #[test]
    fn eve_information_tracks_qber() {
        let clean = ThreatDetector::new(0.15).unwrap().evaluate_channel(0.0, 5000, 0.0, 0.0).unwrap();
        let dirty = ThreatDetector::new(0.15).unwrap().evaluate_channel(0.20, 5000, 0.0, 0.0).unwrap();
        assert_eq!(clean.eve_information_fraction, 0.0);
        assert!(dirty.eve_information_fraction > clean.eve_information_fraction);
    }

    #[test]
    fn classification_and_key_acceptance_share_one_finite_sample_line() {
        let detector = ThreatDetector::new(0.15).unwrap();
        let accepted = detector.evaluate_channel(0.19, 1000, 0.0, 0.0).unwrap();
        assert!(accepted.is_authentic);
        assert!(!accepted.threat_flagged);
        assert_eq!(accepted.channel_class, ChannelClass::Degraded);
        assert!(accepted.mismatch_rate <= accepted.dynamic_threshold);

        let rejected = detector.evaluate_channel(0.20, 1000, 0.0, 0.0).unwrap();
        assert!(!rejected.is_authentic);
        assert!(rejected.threat_flagged);
        assert_eq!(rejected.channel_class, ChannelClass::UnderAttack);
        assert!(rejected.mismatch_rate > rejected.dynamic_threshold);
        assert!(rejected.note.contains("does not identify the cause"));
    }

    #[test]
    fn expected_noise_floor_cannot_exceed_the_rejection_line() {
        let detector = ThreatDetector::new(0.10).unwrap();
        let accepted = detector.evaluate_channel(0.11, 20_000, 0.50, 0.50).unwrap();
        assert!(!accepted.is_authentic);
        assert_eq!(accepted.channel_class, ChannelClass::UnderAttack);
    }
}
