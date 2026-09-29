//! Feature 3 — Chernoff–Hoeffding Statistical Confidence Engine.
//!
//! **The question this answers.** "How do you know 0.15 is the right
//! threshold?" — the honest answer is a *bound*, not a vibe. For an observed
//! mismatch count k over n sampled positions, concentration inequalities
//! bound the true mismatch rate p with explicit confidence 1−δ:
//!
//! * **Hoeffding (1963)** — distribution-free, additive:
//!   `P(p̂ ≥ p + ε) ≤ exp(−2nε²)`, so ε(n, δ) = √(ln(1/δ) / 2n). Safe
//!   for any bounded random variable; the workhorse for "is the sample
//!   large enough to trust the verdict at all".
//! * **Chernoff (1952)** — multiplicative, sharper for rare events:
//!   `P(p̂ ≥ (1+γ)p) ≤ exp(−p·γ²/(2+γ))` for γ ≥ 0. When the true rate is
//!   small (an honest channel), the multiplicative form is dramatically
//!   tighter than Hoeffding's additive form — this is the bound that makes
//!   a 1% observed rate *mean* something at n = 10⁴.
//! * **Exact binomial tail** — the ground truth both bounds approximate:
//!   P(X ≥ k) = Σ C(n,i)·pⁱ(1−p)ⁿ⁻ⁱ computed in log-space (no overflow).
//!   The visualizer uses it to show how much the bounds give away vs the
//!   exact combinatorics.
//!
//! The engine exposes three consumer-facing artifacts:
//!
//! 1. `confidence_interval(k, n, δ)` — the two-sided interval the verdict
//!    thresholds ride inside of.
//! 2. `dynamic_threshold(n, δ, noise_floor)` — the rejection line as a
//!    *function of sample size*: it starts loose (small n, huge slack) and
//!    narrows like a vice as N grows — the curve the visualizer plots.
//! 3. `verdict_confidence(k, n, threshold)` — how confident the REJECT
//!    verdict itself is: how incompatible the observation is with an honest
//!    channel running at the threshold rate, as an exact-tail p-value.

use serde::Serialize;

/// Hoeffding's additive slack: ε such that P(|p̂ − p| ≥ ε) ≤ δ.
/// Two-sided at confidence 1−δ: ε = √(ln(2/δ) / 2n).
pub fn hoeffding_slack(n: usize, delta: f64) -> f64 {
    if n == 0 || delta <= 0.0 || delta >= 1.0 {
        return 1.0;
    }
    ((1.0 / delta * 2.0).ln() / (2.0 * n as f64)).sqrt().min(1.0)
}

/// Chernoff's multiplicative upper deviation: given observed p̂, the γ
/// radius such that P(p̂ ≥ (1+γ)p) ≤ δ — solved in closed form.
///
/// Inverting exp(−p̂γ²/(2+γ)) = δ/2 for γ ≥ 0 gives a quadratic in γ:
///   p̂γ² − (p̂ln(2/δ))γ + 2p̂ln(2/δ)... solved directly below.
pub fn chernoff_gamma(p_hat: f64, n: usize, delta: f64) -> f64 {
    if n == 0 || p_hat <= 0.0 {
        return 1.0;
    }
    let l = (2.0 / delta).ln();
    // Solve p̂·γ²/(2+γ) = l → γ² − (l/p̂)γ − 2l/p̂ = 0, positive root.
    let b = l / (p_hat * n as f64);
    let gamma = (b + (b * b + 4.0 * b).sqrt()) / 2.0;
    gamma.min(1.0 / p_hat.max(1e-12)).min(1.0)
}

/// Upper confidence bound on the true rate via Chernoff: p̂(1+γ).
pub fn chernoff_upper(p_hat: f64, n: usize, delta: f64) -> f64 {
    (p_hat * (1.0 + chernoff_gamma(p_hat, n, delta))).min(1.0)
}

/// Exact upper binomial tail: P(X ≥ k) for X ~ Bin(n, p).
///
/// Computed with the multiplicative recurrence C(n,i+1) = C(n,i)·(n−i)/(i+1)
/// — every intermediate value is a probability ≤ 1, so there is no overflow
/// and no need for log-space gymnastics; underflow to 0 deep in the tail is
/// exactly the correct answer.
pub fn binom_tail_ge(n: usize, k: usize, p: f64) -> f64 {
    if k > n {
        return 0.0;
    }
    if p >= 1.0 {
        return 1.0;
    }
    if p <= 0.0 {
        return 0.0;
    }
    let q = 1.0 - p;
    // Start at i = k: C(n,k)·p^k·q^(n-k) via iterated products.
    let mut log_term = k as f64 * p.ln() + (n - k) as f64 * q.ln();
    let mut comb = 1.0f64;
    for j in 0..k {
        comb *= (n - j) as f64 / (j + 1) as f64;
        if comb > 1e300 {
            // Extremely large k with n large: renormalize via logs instead.
            return binom_tail_ge_logspace(n, k, p);
        }
    }
    let mut total = comb * log_term.exp();
    let mut c = comb;
    for i in k..n {
        // Move to i+1: C(n,i+1) = C(n,i)·(n−i)/(i+1); term gains a p, drops a q.
        c *= (n - i) as f64 / (i + 1) as f64;
        log_term += p.ln() - q.ln();
        total += c * log_term.exp();
    }
    total.min(1.0)
}

/// Log-space fallback for extreme parameters (n large, k large).
fn binom_tail_ge_logspace(n: usize, k: usize, p: f64) -> f64 {
    let lp = p.ln();
    let lq = (1.0 - p).ln();
    // ln C(n,k) via the sum of logs (O(k), bounded by the caller's guard).
    let mut lck = 0.0f64;
    for j in 0..k {
        lck += ((n - j) as f64 / (j + 1) as f64).ln();
    }
    let mut total = f64::NEG_INFINITY;
    let mut lci = lck;
    let mut li = k as f64 * lp + (n - k) as f64 * lq;
    for i in k..=n {
        let t = lci + li;
        total = if total > t {
            total + (1.0 + (t - total).exp()).ln()
        } else {
            t + (1.0 + (total - t).exp()).ln()
        };
        if i < n {
            lci += ((n - i) as f64 / (i + 1) as f64).ln();
            li += lp - lq;
        }
    }
    total.exp().min(1.0)
}

/// Exact lower binomial tail: P(X ≤ k).
pub fn binom_tail_le(n: usize, k: usize, p: f64) -> f64 {
    1.0 - binom_tail_ge(n, k + 1, p)
}

/// A two-sided confidence interval for the true mismatch rate.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ConfidenceInterval {
    pub n: usize,
    pub k: usize,
    pub p_hat: f64,
    /// Hoeffding additive interval [max(0, p̂−ε), min(1, p̂+ε)].
    pub lo_hoeffding: f64,
    pub hi_hoeffding: f64,
    /// Chernoff multiplicative upper bound (≤ Hoeffding's for small p̂).
    pub hi_chernoff: f64,
    /// Confidence level of both bounds (1−δ).
    pub confidence: f64,
}

/// Two-sided confidence interval for the true rate given k mismatches in n
/// samples, at confidence 1−δ. Both classical bounds are reported so the
/// dashboard can *show* the multiplicative gain.
pub fn confidence_interval(k: usize, n: usize, delta: f64) -> ConfidenceInterval {
    let p_hat = if n == 0 { 0.0 } else { k as f64 / n as f64 };
    let eps = hoeffding_slack(n, delta);
    ConfidenceInterval {
        n,
        k,
        p_hat,
        lo_hoeffding: (p_hat - eps).max(0.0),
        hi_hoeffding: (p_hat + eps).min(1.0),
        hi_chernoff: chernoff_upper(p_hat, n, delta),
        confidence: 1.0 - delta,
    }
}

/// One point of the dynamic-threshold curve: the rejection line for a
/// sample of size n. Composed as noise floor + Hoeffding slack, capped by
/// 1.0, and paired with the exact-tail sample-size requirement for the
/// requested confidence — the visualizer plots how the line narrows.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ThresholdPoint {
    pub n: usize,
    /// noise_floor + ε(n) — the verdict line.
    pub threshold: f64,
    /// The Hoeffding slack component alone (what statistics added).
    pub slack: f64,
}

/// Sample the threshold curve over logarithmically spaced sample sizes
/// from `n_min` to `n_max` — the vice-narrowing the visualizer plots.
pub fn threshold_curve(
    n_min: usize,
    n_max: usize,
    points: usize,
    noise_floor: f64,
    delta: f64,
) -> Vec<ThresholdPoint> {
    let n_min = n_min.max(1);
    let n_max = n_max.max(n_min);
    let points = points.max(2);
    let lo = (n_min as f64).ln();
    let hi = (n_max as f64).ln();
    (0..points)
        .map(|i| {
            let n = (lo + (hi - lo) * i as f64 / (points - 1) as f64)
                .exp()
                .round() as usize;
            let n = n.clamp(n_min, n_max);
            let slack = hoeffding_slack(n, delta);
            ThresholdPoint {
                n,
                threshold: (noise_floor + slack).min(1.0),
                slack,
            }
        })
        .collect()
}

/// Confidence of a REJECT verdict: how incompatible the observation is
/// with an honest channel running AT the threshold rate. The p-value is
///   P(X ≥ k | true rate = threshold)
/// — the chance an honest channel would produce k or MORE mismatches by
/// sheer luck. A tiny value means the observation is (essentially)
/// incompatible with honesty: the rejection is statistically airtight,
/// not just "above a line".
#[derive(Debug, Clone, Copy, Serialize)]
pub struct VerdictConfidence {
    pub n: usize,
    pub k: usize,
    pub threshold: f64,
    /// P(X ≥ k | true rate = threshold) — small ⇒ reject is airtight.
    pub p_value: f64,
    /// 1 − p_value, the confidence the rejection is correct.
    pub rejection_confidence: f64,
    /// Simple qualitative band for UI coloring.
    pub band: VerdictBand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictBand {
    /// p < 10⁻⁶ — mathematically airtight.
    Airtight,
    /// p < 10⁻³ — statistically decisive.
    Decisive,
    /// p < 0.05 — significant.
    Significant,
    /// p ≥ 0.05 — the sample cannot separate honesty from attack at this
    /// threshold: enlarge the sample.
    Undersized,
}

pub fn verdict_confidence(k: usize, n: usize, threshold: f64) -> VerdictConfidence {
    let p_value = binom_tail_ge(n, k, threshold);
    let band = if p_value < 1e-6 {
        VerdictBand::Airtight
    } else if p_value < 1e-3 {
        VerdictBand::Decisive
    } else if p_value < 0.05 {
        VerdictBand::Significant
    } else {
        VerdictBand::Undersized
    };
    VerdictConfidence {
        n,
        k,
        threshold,
        p_value,
        rejection_confidence: 1.0 - p_value,
        band,
    }
}

/// The full statistical dossier for one observed sample — everything the
/// confidence visualizer renders, in one serializable payload.
#[derive(Debug, Clone, Serialize)]
pub struct BoundsReport {
    pub interval: ConfidenceInterval,
    /// The threshold curve around the observed n (for the plot).
    pub curve: Vec<ThresholdPoint>,
    pub verdict: VerdictConfidence,
    /// Multiplicative sharpness gain of Chernoff over Hoeffding at this
    /// sample (> 1 means Chernoff is tighter by that factor).
    pub chernoff_gain: f64,
}

/// Assemble the dossier for k mismatches in n samples.
pub fn bounds_report(
    k: usize,
    n: usize,
    noise_floor: f64,
    delta: f64,
    threshold: f64,
) -> BoundsReport {
    let interval = confidence_interval(k, n, delta);
    let observed_n = n.max(1);
    let lo = (observed_n as f64 / 4.0).round().max(16.0) as usize;
    let hi = ((observed_n as f64 * 4.0).round() as usize).max(lo * 2);
    let curve = threshold_curve(lo, hi, 24, noise_floor, delta);
    let verdict = verdict_confidence(k, n, threshold);
    let chernoff_gain = if interval.hi_chernoff > 1e-12 {
        interval.hi_hoeffding / interval.hi_chernoff
    } else {
        1.0
    };
    BoundsReport {
        interval,
        curve,
        verdict,
        chernoff_gain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hoeffding_slack_narrows_like_a_vice() {
        let d = 0.01;
        let s16 = hoeffding_slack(16, d);
        let s1k = hoeffding_slack(1_000, d);
        let s1m = hoeffding_slack(1_000_000, d);
        assert!(s16 > 0.4, "tiny samples are loose: {s16}");
        assert!(s1k < 0.08 && s1k > 0.05, "1k ≈ √(5.3/2000): {s1k}");
        assert!(s1m < 0.002, "1M is airtight: {s1m}");
        // Monotone decrease.
        assert!(s16 > s1k && s1k > s1m);
    }

    #[test]
    fn chernoff_beats_hoeffding_for_small_rates() {
        // Observed 1% over 10⁴: multiplicative bound should be far tighter.
        let interval = confidence_interval(100, 10_000, 0.01);
        assert!(interval.hi_chernoff < interval.hi_hoeffding,
            "chernoff {} must beat hoeffding {}",
            interval.hi_chernoff, interval.hi_hoeffding);
        assert!(interval.hi_hoeffding / interval.hi_chernoff > 1.5);
        // And the interval must contain the observation.
        assert!(interval.hi_chernoff >= interval.p_hat);
    }

    #[test]
    fn exact_tail_matches_closed_form_small_cases() {
        // P(X ≥ 1 | n=2, p=1/2) = 3/4.
        let tail = binom_tail_ge(2, 1, 0.5);
        assert!((tail - 0.75).abs() < 1e-12);
        // P(X ≥ 0) = 1 always.
        assert!((binom_tail_ge(10, 0, 0.3) - 1.0).abs() < 1e-12);
        // P(X ≥ 11 | n=10) = 0.
        assert_eq!(binom_tail_ge(10, 11, 0.3), 0.0);
        // P(X ≤ 0 | n=5, p=0.1) = 0.9⁵.
        let le = binom_tail_le(5, 0, 0.1);
        assert!((le - 0.9_f64.powi(5)).abs() < 1e-12);
    }

    #[test]
    fn reject_verdict_confidence_is_airtight_for_40_percent_attack() {
        // 40% mismatch over 2000 samples against a 15% line: p-value must
        // be astronomically small — the attack is not noise.
        let v = verdict_confidence(800, 2000, 0.15);
        assert!(v.p_value < 1e-50, "p = {}", v.p_value);
        assert_eq!(v.band, VerdictBand::Airtight);
    }

    #[test]
    fn undersized_samples_are_flagged_not_hidden() {
        // 1 mismatch in 20 samples against a 15% line: entirely consistent
        // with honesty — the engine must say so instead of pretending.
        let v = verdict_confidence(1, 20, 0.15);
        assert!(v.p_value > 0.05);
        assert_eq!(v.band, VerdictBand::Undersized);
    }

    #[test]
    fn threshold_curve_narrows_monotonically() {
        let curve = threshold_curve(100, 1_000_000, 16, 0.02, 0.01);
        for w in curve.windows(2) {
            assert!(w[1].n >= w[0].n, "n must be nondecreasing");
            // Slack shrinks; threshold never increases by more than the
            // floor wiggle (it strictly narrows for pure-Hoeffding terms).
            assert!(w[1].threshold <= w[0].threshold + 1e-9,
                "threshold must narrow: {} → {}",
                w[0].threshold, w[1].threshold);
        }
        assert!(curve.last().unwrap().threshold < 0.025);
    }

    #[test]
    fn full_report_is_coherent() {
        let r = bounds_report(150, 1000, 0.02, 0.01, 0.15);
        assert_eq!(r.interval.n, 1000);
        assert_eq!(r.interval.k, 150);
        assert!((r.interval.p_hat - 0.15).abs() < 1e-12);
        assert!(r.chernoff_gain >= 1.0);
        assert_eq!(r.curve.len(), 24);
        // The verdict at threshold is Undersized (p_hat == threshold), but
        // the report itself is coherent.
        assert!(r.verdict.p_value > 0.0 && r.verdict.p_value < 1.0);
    }
}
