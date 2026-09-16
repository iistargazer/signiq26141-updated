//! Noisy-channel QDS verification: statistical thresholds for the
//! teleportation-QDS mismatch statistics.
//!
//! In the noiseless simulation `verify(..., tolerance = 0)` is exact. Real
//! channels add noise, so the mismatch ratio μ/N must be judged against a
//! statistically safe band instead of a hard zero — this is the same
//! finite-key reasoning as the QKD layer (`detection` crate) applied to
//! signature verification, and it is exactly the tolerance band
//! Gottesman–Chuang's dual thresholds c1/c2 exist for:
//!
//! * μ/N ≤ c1 → 1-ACC (transferable)
//! * c1 < μ/N ≤ c2 → 0-ACC (valid locally, transfer not guaranteed)
//! * μ/N > c2 → REJ
//!
//! Thresholds:
//! * c1 = noise_floor + ε(n) — tolerates channel noise up to the estimated
//!   floor plus the two-sided Hoeffding margin √(ln(2/δ)/2n).
//! * c2 = c1 + gap — the GC01 gap that bounds Alice's repudiation
//!   probability; here sized to sit far above the noise floor yet far below
//!   the ≈75% mismatch a guessed forgery produces.

use crate::Thresholds;

/// Two-sided Hoeffding margin: ε(n) = √(ln(2/δ) / 2n).
pub fn hoeffding_slack(n: usize, delta: f64) -> f64 {
    if n == 0 {
        return 1.0;
    }
    ((2.0_f64 / delta).ln() / (2.0 * n as f64)).sqrt()
}

/// Derive the dual thresholds for a noisy channel.
///
/// * `noise_floor` — expected mismatch ratio from honest channel noise
///   (0.0 for the noiseless simulation).
/// * `n` — number of measured positions q·λ.
/// * `delta` — tolerated failure probability of the bound.
/// * `gray_zone_width` — c2 − c1 (the GC01 anti-repudiation gap).
pub fn noisy_thresholds(noise_floor: f64, n: usize, delta: f64, gray_zone_width: f64) -> Thresholds {
    let slack = hoeffding_slack(n, delta);
    let c1 = (noise_floor + slack).clamp(0.0, 0.5);
    let c2 = (c1 + gray_zone_width).clamp(c1, 1.0);
    Thresholds { c1, c2 }
}

/// Verdict of the noisy-channel check (mirrors `Verdict` but carries the
/// measured evidence for the dashboard).
#[derive(Debug, Clone, serde::Serialize)]
pub struct NoisyChannelAssessment {
    pub mismatch_ratio: f64,
    pub c1: f64,
    pub c2: f64,
    pub hoeffding_slack: f64,
    pub noise_floor: f64,
    /// True when μ/N ≤ c2 (channel not flagged); the verdict band then
    /// decides transferability.
    pub channel_flagged: bool,
    pub verdict: crate::Verdict,
    pub note: String,
}

/// Assess a measured mismatch ratio against the noisy-channel thresholds.
pub fn assess_mismatch(
    mismatches: usize,
    total_positions: usize,
    noise_floor: f64,
    delta: f64,
    gray_zone_width: f64,
) -> NoisyChannelAssessment {
    let ratio = if total_positions == 0 {
        0.0
    } else {
        mismatches as f64 / total_positions as f64
    };
    let th = noisy_thresholds(noise_floor, total_positions, delta, gray_zone_width);
    let channel_flagged = ratio > th.c2;
    let verdict = if ratio <= th.c1 {
        crate::Verdict::Acc1
    } else if ratio <= th.c2 {
        crate::Verdict::Acc0
    } else {
        crate::Verdict::Rej
    };
    NoisyChannelAssessment {
        mismatch_ratio: ratio,
        c1: th.c1,
        c2: th.c2,
        hoeffding_slack: th.c1 - noise_floor.min(th.c1),
        noise_floor,
        channel_flagged,
        verdict,
        note: if channel_flagged {
            format!(
                "channel flagged: mismatch {ratio:.3} exceeds rejection threshold {:.3}",
                th.c2
            )
        } else if ratio <= th.c1 {
            format!(
                "channel clean: mismatch {ratio:.3} within noise band ({noise_floor:.3} + {:.3})",
                th.c1 - noise_floor.min(th.c1)
            )
        } else {
            format!(
                "gray zone: mismatch {ratio:.3} in ({:.3}, {:.3}] — valid here, transfer not guaranteed",
                th.c1, th.c2
            )
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noiseless_channel_is_always_transferable() {
        // Zero mismatches ⇒ 1-ACC regardless of n.
        let a = assess_mismatch(0, 64, 0.0, 0.05, 0.05);
        assert_eq!(a.verdict, crate::Verdict::Acc1);
        assert!(!a.channel_flagged);
    }

    #[test]
    fn noise_within_floor_is_tolerated() {
        // 5% mismatch on 1000 positions: slack ≈ 3.7%, floor 5% ⇒ c1 ≈ 8.7%
        // ⇒ 5% is comfortably 1-ACC.
        let a = assess_mismatch(50, 1000, 0.05, 0.05, 0.05);
        assert_eq!(a.verdict, crate::Verdict::Acc1, "{}", a.note);
        assert!(!a.channel_flagged);
    }

    #[test]
    fn attack_level_mismatch_is_flagged() {
        // 75% mismatch (guessed forgery) on any n ⇒ REJ + channel flagged.
        let a = assess_mismatch(750, 1000, 0.05, 0.05, 0.05);
        assert_eq!(a.verdict, crate::Verdict::Rej);
        assert!(a.channel_flagged);
    }

    #[test]
    fn gray_zone_is_neither_clean_nor_flagged() {
        // c1 ≈ 8.7%, c2 ≈ 13.7%: a 10% mismatch sits in the gray zone.
        let a = assess_mismatch(100, 1000, 0.05, 0.05, 0.05);
        assert_eq!(a.verdict, crate::Verdict::Acc0, "{}", a.note);
        assert!(!a.channel_flagged);
    }

    #[test]
    fn small_samples_get_lenient_thresholds() {
        let tight = noisy_thresholds(0.0, 10_000, 0.05, 0.05);
        let loose = noisy_thresholds(0.0, 50, 0.05, 0.05);
        assert!(loose.c1 > tight.c1, "Hoeffding slack must shrink with n");
    }
}
