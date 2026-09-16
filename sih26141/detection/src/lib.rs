//! Channel classification for the QKD layer.
//!
//! Distinguishes three channel states from the measured mismatch statistics:
//!
//! * `Secure`       — QBER within the noise floor + Hoeffding slack.
//! * `Degraded`     — QBER above the noise floor but below the attack line.
//!                    Usually environmental (fiber attenuation, turbulence):
//!                    warn, retry, or add redundancy — but do not panic.
//! * `UnderAttack`  — QBER above the attack line. On a six-state channel the
//!                    canonical intercept-resend signature is QBER ≈ 1/3, and
//!                    any sustained QBER above `degraded_max` is treated as
//!                    adversarial because it exceeds plausible nature.
pub struct ThreatDetector {
    base_threshold: f64,
    confidence_delta: f64,
}

/// Expected environmental bit-flip probability used to establish the noise
/// floor. Set to the configured channel noise (e.g. 0.03 for 3% fiber noise).
pub const DEFAULT_NOISE_FLOOR: f64 = 0.03;

/// QBER above which environmental noise is no longer a plausible
/// explanation — treated as adversarial (intercept-resend ≈ 33%).
pub const ATTACK_QBER_LINE: f64 = 0.15;

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
}

/// Three-way channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelClass {
    /// QBER within noise floor + slack: keys are safe to distill.
    Secure,
    /// QBER above noise floor but below the attack line: environmental
    /// degradation warning — key distillation proceeds with caution.
    Degraded,
    /// QBER above the attack line: adversarial disturbance assumed.
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
            ChannelClass::Degraded => "Channel Degradation Warning",
            ChannelClass::UnderAttack => "Security Breach — eavesdropping suspected",
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

    /// Full three-way evaluation:
    ///
    /// * `mismatch_rate`      — measured QBER.
    /// * `matching_bases_count` — sifted sample size n (drives the bound).
    /// * `noise_floor`        — configured environmental noise (e.g. 0.03).
    /// * `measured_noise_rate` — the noise actually applied in simulation
    ///   (echoed to the UI; does not influence the verdict).
    ///
    /// Classification:
    ///   QBER ≤ noise_floor + ε(n)              → Secure
    ///   noise_floor + ε(n) < QBER ≤ attack_line → Degraded (warning)
    ///   QBER > attack_line                     → UnderAttack
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
            });
        }

        let slack = ((2.0 / self.confidence_delta).ln() / (2.0 * matching_bases_count as f64)).sqrt();
        // dynamic_threshold keeps the legacy meaning: the largest QBER the
        // detector tolerates before flagging a breach.
        let dynamic_threshold = (self.base_threshold + slack).min(1.0);
        // The degraded band rides on the configured noise floor, not on the
        // legacy base threshold, so a clean run at 3% noise stays Secure.
        let secure_line = (noise_floor + slack).min(1.0);
        let is_authentic = mismatch_rate <= dynamic_threshold;

        let (channel_class, threat_flagged, note) = if mismatch_rate <= secure_line {
            (ChannelClass::Secure, false, "QBER within noise floor + Hoeffding margin.")
        } else if mismatch_rate <= ATTACK_QBER_LINE {
            (
                ChannelClass::Degraded,
                false,
                "QBER above noise floor but below attack line: environmental degradation, not eavesdropping.",
            )
        } else {
            (
                ChannelClass::UnderAttack,
                true,
                "QBER exceeds attack line: intercept-resend signature — abort key distillation.",
            )
        };

        Ok(DetectionResult {
            is_authentic,
            mismatch_rate,
            dynamic_threshold,
            threat_flagged,
            note,
            channel_class,
            noise_floor,
            measured_noise_rate,
        })
    }
}
